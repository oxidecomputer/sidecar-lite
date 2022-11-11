// Copyright 2022 Oxide Computer Company

use p4rs::TableEntry;
use p9ds::proto::{P9Version, Rclunk, Rwrite, Tclunk, Twrite, Version};
use p9kp::Client;
use slog::{Drain, Logger};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use devinfo::{get_devices, DiPropValue};
use indicatif::{ProgressBar, ProgressStyle};
use softnpu::mgmt::{
    ManagementRequest, ManagementResponse, TableAdd, TableRemove,
};
use tokio::net::UnixDatagram;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    Propolis,
    Standalone,
}

#[derive(Parser, Debug)]
#[clap(version, about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[arg(value_enum)]
    mode: Mode,

    #[arg(short, long, default_value = "/opt/softnpu/stuff/client")]
    client: String,

    #[arg(short, long, default_value = "/opt/softnpu/stuff/server")]
    server: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Add an IPv4 route to the routing table.
    AddRoute4 {
        /// Destination address for the route.
        destination: Ipv4Addr,

        /// Subnet mask for the destination.
        mask: u8,

        /// Outbound port for the route.
        port: u16,

        /// Next Hop
        nexthop: Ipv4Addr,
    },

    /// Remove a route from the routing table.
    RemoveRoute4 {
        /// Destination address for the route.
        destination: Ipv4Addr,

        /// Subnet mask for the destination.
        mask: u8,
    },

    /// Add an IPv6 route to the routing table.
    AddRoute6 {
        /// Destination address for the route.
        destination: Ipv6Addr,

        /// Subnet mask for the destination.
        mask: u8,

        /// Outbound port for the route.
        port: u16,

        /// Next Hop
        nexthop: Ipv6Addr,
    },

    /// Remove a route from the routing table.
    RemoveRoute6 {
        /// Destination address for the route.
        destination: Ipv6Addr,

        /// Subnet mask for the destination.
        mask: u8,
    },

    /// Add an IPv6 address to the router.
    AddAddress6 {
        /// Address to add.
        address: Ipv6Addr,
    },

    /// Remove an IPv6 address from the router.
    RemoveAddress6 {
        /// Address to add.
        address: Ipv6Addr,
    },

    /// Add an IPv4 address to the router.
    AddAddress4 {
        /// Address to add.
        address: Ipv4Addr,
    },

    /// Remove an IPv4 address from the router.
    RemoveAddress4 {
        /// Address to add.
        address: Ipv4Addr,
    },

    /// Specify MAC address for a port.
    SetMac {
        /// Port to set MAC for.
        port: u16,
        /// The MAC address.
        mac: MacAddr,
    },

    /// Clear a port's MAC address.
    ClearMac { port: u16 },

    /// Show port count
    PortCount,

    /// Add a static NDP entry
    AddNdpEntry { l3: Ipv6Addr, l2: MacAddr },

    /// Remove a static NDP entry
    RemoveNdpEntry { l3: Ipv6Addr },

    /// Add a static ARP entry
    AddArpEntry { l3: Ipv4Addr, l2: MacAddr },

    /// Remove a static ARP entry
    RemoveArpEntry { l3: Ipv4Addr },

    /// Dump all tables
    DumpState,

    /// Add an IPv6 NAT entry
    AddNat6 {
        /// Destination address for ingress NAT packets.
        dst: Ipv6Addr,
        /// Beginning of L4 port range for this entry.
        begin: u16,
        /// End of L4 port range for this entry.
        end: u16,
        /// Underlay IPv6 address to send encapsulated packets to.
        target: Ipv6Addr,
        /// VNI to encapsulate packets onto.
        vni: u32,
        /// Mac address to use for inner-packet L2 destination.
        mac: MacAddr,
    },

    /// Remove an IPv6 NAT entry
    RemoveNat6 { dst: Ipv6Addr, begin: u16, end: u16 },

    /// Add an IPv4 NAT entry
    AddNat4 {
        /// Destination address for ingress NAT packets.
        dst: Ipv4Addr,
        /// Beginning of L4 port range for this entry.
        begin: u16,
        /// End of L4 port range for this entry.
        end: u16,
        /// Underlay IPv6 address to send encapsulated packets to.
        target: Ipv6Addr,
        /// VNI to encapsulate packets onto.
        vni: u32,
        /// Mac address to use for inner-packet L2 destination.
        mac: MacAddr,
    },

    /// Remove an IPv4 NAT entry
    RemoveNat4 { dst: Ipv4Addr, begin: u16, end: u16 },

    /// Add a proxy ARP entry.
    AddProxyArp {
        begin: Ipv4Addr,
        end: Ipv4Addr,
        mac: MacAddr,
    },

    /// Remove a proxy ARP entry.
    RemoveProxyArp { begin: Ipv4Addr, end: Ipv4Addr },

    /// Load a program onto the SoftNPU ASIC emulator
    LoadProgram { path: String },
}

#[derive(Debug, Clone)]
struct MacAddr(pub [u8; 6]);

impl std::str::FromStr for MacAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err("Expected mac in the form aa:bb:cc:dd:ee:ff".into());
        }
        let mut result = MacAddr([0u8; 6]);
        for (i, p) in parts.iter().enumerate() {
            result.0[i] = match u8::from_str_radix(p, 16) {
                Ok(n) => n,
                Err(_) => {
                    return Err(
                        "Expected mac in the form aa:bb:cc:dd:ee:ff".into()
                    );
                }
            }
        }
        Ok(result)
    }
}

const ROUTER_V4: &str = "router.router_v4";
const ROUTER_V6: &str = "router.router_v6";
const LOCAL_V6: &str = "local.local_v6";
const LOCAL_V4: &str = "local.local_v4";
const NAT_V4: &str = "nat.nat_v4";
const NAT_V6: &str = "nat.nat_v6";
const NAT_ICMP_V6: &str = "nat.nat_icmp_v6";
const NAT_ICMP_V4: &str = "nat.nat_icmp_v4";
const RESOLVER_V4: &str = "resolver.resolver_v4";
const RESOLVER_V6: &str = "resolver.resolver_v6";
const MAC_REWRITE: &str = "mac.mac_rewrite";
const PROXY_ARP: &str = "pxarp.proxy_arp";

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::AddRoute4 {
            destination,
            mask,
            port,
            nexthop,
        } => {
            let mut keyset_data: Vec<u8> = destination.octets().into();
            keyset_data.push(mask);

            let mut parameter_data = port.to_be_bytes().to_vec();
            let nexthop_data: Vec<u8> = nexthop.octets().into();
            parameter_data.extend_from_slice(&nexthop_data);

            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: ROUTER_V4.into(),
                    action: "forward_v4".into(),
                    keyset_data,
                    parameter_data,
                }),
                &cli,
            )
            .await;
        }
        Commands::RemoveRoute4 { destination, mask } => {
            let mut keyset_data: Vec<u8> = destination.octets().into();
            keyset_data.push(mask);

            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: ROUTER_V4.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::AddRoute6 {
            destination,
            mask,
            port,
            nexthop,
        } => {
            let mut keyset_data: Vec<u8> = destination.octets().into();
            keyset_data.push(mask);

            let mut parameter_data = port.to_be_bytes().to_vec();
            let nexthop_data: Vec<u8> = nexthop.octets().into();
            parameter_data.extend_from_slice(&nexthop_data);

            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: ROUTER_V6.into(),
                    action: "forward_v6".into(),
                    keyset_data,
                    parameter_data,
                }),
                &cli,
            )
            .await;
        }
        Commands::RemoveRoute6 { destination, mask } => {
            let mut keyset_data: Vec<u8> = destination.octets().into();
            keyset_data.push(mask);

            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: ROUTER_V6.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::AddNat4 {
            dst,
            begin,
            end,
            target,
            vni,
            ref mac,
        } => {
            if vni >= 1 << 24 {
                println!("vni too big, only 24 bits");
                std::process::exit(1);
            }

            let mut keyset_data: Vec<u8> = dst.octets().into();
            keyset_data.extend_from_slice(&begin.to_be_bytes());
            keyset_data.extend_from_slice(&end.to_be_bytes());

            let mut parameter_data: Vec<u8> = target.octets().into();
            let vni_bits = vni.to_be_bytes();
            parameter_data.extend_from_slice(&vni_bits[1..4]);
            parameter_data.extend_from_slice(&mac.0);

            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: NAT_V4.into(),
                    action: "forward_to_sled".into(),
                    keyset_data,
                    parameter_data,
                }),
                &cli,
            )
            .await;
        }
        Commands::RemoveNat4 { dst, begin, end } => {
            let mut keyset_data: Vec<u8> = dst.octets().into();
            keyset_data.extend_from_slice(&begin.to_be_bytes());
            keyset_data.extend_from_slice(&end.to_be_bytes());

            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: NAT_V4.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::AddNat6 {
            dst,
            begin,
            end,
            target,
            vni,
            ref mac,
        } => {
            if vni >= 1 << 24 {
                println!("vni too big, only 24 bits");
                std::process::exit(1);
            }

            let mut keyset_data: Vec<u8> = dst.octets().into();
            keyset_data.extend_from_slice(&begin.to_be_bytes());
            keyset_data.extend_from_slice(&end.to_be_bytes());

            let mut parameter_data: Vec<u8> = target.octets().into();
            let vni_bits = vni.to_be_bytes();
            parameter_data.extend_from_slice(&vni_bits[1..4]);
            parameter_data.extend_from_slice(&mac.0);

            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: NAT_V6.into(),
                    action: "forward_to_sled".into(),
                    keyset_data,
                    parameter_data,
                }),
                &cli,
            )
            .await;
        }
        Commands::RemoveNat6 { dst, begin, end } => {
            let mut keyset_data: Vec<u8> = dst.octets().into();
            keyset_data.extend_from_slice(&begin.to_be_bytes());
            keyset_data.extend_from_slice(&end.to_be_bytes());

            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: NAT_V6.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::AddAddress4 { address } => {
            let keyset_data: Vec<u8> = address.octets().into();
            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: LOCAL_V4.into(),
                    action: "local".into(),
                    keyset_data,
                    ..Default::default()
                }),
                &cli,
            )
            .await;
        }
        Commands::RemoveAddress4 { address } => {
            let keyset_data: Vec<u8> = address.octets().into();
            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: LOCAL_V4.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::AddAddress6 { address } => {
            let keyset_data: Vec<u8> = address.octets().into();
            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: LOCAL_V6.into(),
                    action: "local".into(),
                    keyset_data,
                    ..Default::default()
                }),
                &cli,
            )
            .await;
        }
        Commands::RemoveAddress6 { address } => {
            let keyset_data: Vec<u8> = address.octets().into();
            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: LOCAL_V6.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::SetMac { port, ref mac } => {
            let keyset_data: Vec<u8> = port.to_be_bytes().to_vec();
            let parameter_data: Vec<u8> = mac.0.into();
            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: MAC_REWRITE.into(),
                    action: "rewrite".into(),
                    keyset_data,
                    parameter_data,
                }),
                &cli,
            )
            .await;
        }
        Commands::ClearMac { port } => {
            let keyset_data: Vec<u8> = port.to_be_bytes().to_vec();
            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: MAC_REWRITE.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::PortCount => match cli.mode {
            Mode::Standalone => {
                let uds = bind_uds(&cli);
                let j = tokio::spawn(async move {
                    if let ManagementResponse::RadixResponse(n) =
                        recv_uds(uds).await
                    {
                        println!("{}", n)
                    }
                });
                send(ManagementRequest::RadixRequest, &cli).await;
                j.await.unwrap();
            }
            Mode::Propolis => {
                let mut f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/tty03")
                    .unwrap();

                let msg = ManagementRequest::RadixRequest;
                let mut buf = Vec::new();
                buf.push(0b11100101);
                let mut js = serde_json::to_vec(&msg).unwrap();
                js.retain(|x| *x != b'\n');
                buf.extend_from_slice(&js);
                buf.push(b'\n');

                f.write_all(&buf).unwrap();
                f.sync_all().unwrap();

                let mut buf = [0u8; 1024];
                let n = f.read(&mut buf).unwrap();
                let radix: u16 = std::str::from_utf8(&buf[..n - 1])
                    .unwrap()
                    .parse()
                    .unwrap();
                println!("{:?}", radix);
            }
        },

        Commands::AddNdpEntry { l3, ref l2 } => {
            let keyset_data: Vec<u8> = l3.octets().into();
            let parameter_data: Vec<u8> = l2.0.into();
            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: RESOLVER_V6.into(),
                    action: "rewrite_dst".into(),
                    keyset_data,
                    parameter_data,
                }),
                &cli,
            )
            .await;
        }
        Commands::RemoveNdpEntry { l3 } => {
            let keyset_data: Vec<u8> = l3.octets().into();
            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: RESOLVER_V6.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::AddArpEntry { l3, ref l2 } => {
            let keyset_data: Vec<u8> = l3.octets().into();
            let parameter_data: Vec<u8> = l2.0.into();
            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: RESOLVER_V4.into(),
                    action: "rewrite_dst".into(),
                    keyset_data,
                    parameter_data,
                }),
                &cli,
            )
            .await;
        }
        Commands::RemoveArpEntry { l3 } => {
            let keyset_data: Vec<u8> = l3.octets().into();
            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: RESOLVER_V4.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::DumpState => {
            match cli.mode {
                Mode::Standalone => {
                    let uds = bind_uds(&cli);
                    let j = tokio::spawn(async move {
                        if let ManagementResponse::DumpResponse(ref tables) =
                            recv_uds(uds).await
                        {
                            dump_tables(tables);
                        }
                    });
                    send(ManagementRequest::DumpRequest, &cli).await;
                    j.await.unwrap();
                }
                Mode::Propolis => {
                    let mut f = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open("/dev/tty03")
                        .unwrap();

                    let fd = f.as_raw_fd();
                    unsafe {
                        let mut term: libc::termios = std::mem::zeroed();
                        if libc::tcgetattr(fd, &mut term) != 0 {
                            println!("tcgetattr failed, dump may hang");
                        }
                        term.c_lflag &= !(libc::ICANON
                            | libc::ECHO
                            | libc::ECHOE
                            | libc::ISIG);
                        if libc::tcsetattr(fd, libc::TCSANOW, &term) != 0 {
                            println!("tcsetattr failed, dump may hang");
                        }
                    }

                    let msg = ManagementRequest::DumpRequest;
                    let mut buf = Vec::new();
                    buf.push(0b11100101);
                    buf.extend_from_slice(&serde_json::to_vec(&msg).unwrap());
                    buf.push(b'\n');

                    f.write_all(&buf).unwrap();
                    f.sync_all().unwrap();

                    let mut buf = [0u8; 10240];
                    let mut i = 0;
                    loop {
                        let n = f.read(&mut buf[i..]).unwrap();
                        i += n;
                        //XXX
                        let s =
                            String::from_utf8_lossy(&buf[..i - 1]).to_string();
                        println!("PATIAL ({}): {}", s.len(), s);
                        if buf[i - 1] == b'\n' {
                            break;
                        }
                    }
                    let s = String::from_utf8_lossy(&buf[..i - 1]).to_string();

                    //let mut d = TableDump::default();

                    let d = serde_json::from_str(&s).unwrap();
                    dump_tables(&d);
                }
            }
        }

        Commands::AddProxyArp {
            begin,
            end,
            ref mac,
        } => {
            let mut keyset_data: Vec<u8> = begin.octets().into();
            keyset_data.extend_from_slice(&end.octets());

            let parameter_data: Vec<u8> = mac.0.into();

            send(
                ManagementRequest::TableAdd(TableAdd {
                    table: PROXY_ARP.into(),
                    action: "proxy_arp_reply".into(),
                    keyset_data,
                    parameter_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::RemoveProxyArp { begin, end } => {
            let mut keyset_data: Vec<u8> = begin.octets().into();
            keyset_data.extend_from_slice(&end.octets());

            send(
                ManagementRequest::TableRemove(TableRemove {
                    table: PROXY_ARP.into(),
                    keyset_data,
                }),
                &cli,
            )
            .await;
        }

        Commands::LoadProgram { path } => {
            if cli.mode == Mode::Standalone {
                panic!("load program not supported in standalone mode");
            }
            let mut file = File::open(path).unwrap();
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).unwrap();

            let pb = ProgressBar::new(buf.len() as u64);
            let sty = ProgressStyle::with_template(
                "[{elapsed_precise}] \
                {bar:40.cyan/blue} \
                {bytes}/{total_bytes} \
                {msg}",
            )
            .unwrap()
            .progress_chars("##-");

            pb.set_style(sty);

            let mut client = get_p9_client().await.unwrap();

            let mut i = 0;
            let stride = 0x10000 - 23;
            let end = buf.len();
            loop {
                let j = std::cmp::min(i + stride, end);
                let req = Twrite::new(buf[i..j].to_owned(), 0, i as u64);
                let resp: Rwrite = client.send(&req).await.unwrap();
                pb.inc(resp.count as u64);
                i += stride;
                if i >= end {
                    break;
                }
            }
            pb.finish_with_message("done");
            println!();

            let req = Tclunk::new(0);
            let _resp: Rclunk = client.send(&req).await.unwrap();
        }
    }
}

fn logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    Logger::root(drain, slog::o!())
}

async fn get_p9_client() -> Option<p9kp::ChardevClient> {
    let devices = get_devices(false).unwrap();

    // look for libvirt/vritfs device
    let vendor_id = 0x1af4;
    let device_id = 0x1009;

    for (device_key, dev_info) in devices {
        let vendor_match = match dev_info.props.get("vendor-id") {
            Some(value) => value.matches_int(vendor_id),
            _ => false,
        };
        let dev_match = match dev_info.props.get("device-id") {
            Some(value) => value.matches_int(device_id),
            _ => false,
        };
        let unit_address = match dev_info.props.get("unit-address") {
            Some(DiPropValue::Strings(vs)) => {
                if vs.is_empty() {
                    continue;
                }
                vs[0].clone()
            }
            _ => continue,
        };
        if vendor_match && dev_match {
            let dev_path = format!(
                "/devices/pci@0,0/{}@{}:9p",
                device_key.node_name, unit_address,
            );
            let pb = PathBuf::from(dev_path);
            let mut client = p9kp::ChardevClient::new(pb, 0x10000, logger());

            let mut ver = Version::new(P9Version::V2000P4);
            ver.msize = 0x10000;
            let server_version =
                client.send::<Version, Version>(&ver).await.unwrap();
            if Some(P9Version::V2000P4)
                == P9Version::from_str(&server_version.version)
            {
                return Some(client);
            }
        }
    }
    None
}

fn dump_tables(table: &BTreeMap<String, Vec<TableEntry>>) {
    println!("local v6:");
    for e in table.get(LOCAL_V6).unwrap() {
        if let Some(a) = get_addr(&e.keyset_data, true) {
            println!("{}", a)
        }
    }
    println!("local v4:");
    for e in table.get(LOCAL_V4).unwrap() {
        if let Some(a) = get_addr(&e.keyset_data, true) {
            println!("{}", a)
        }
    }

    println!("router v6:");
    for e in table.get(ROUTER_V6).unwrap() {
        let tgt = match get_addr_subnet(&e.keyset_data) {
            Some((a, m)) => format!("{}/{}", a, m),
            None => "?".into(),
        };
        let gw = match get_port_addr(&e.parameter_data) {
            Some((a, p)) => format!("{} ({})", a, p),
            None => "?".into(),
        };
        println!("{} -> {}", tgt, gw);
    }
    println!("router v4:");
    for e in table.get(ROUTER_V4).unwrap() {
        let tgt = match get_addr_subnet(&e.keyset_data) {
            Some((a, m)) => format!("{}/{}", a, m),
            None => "?".into(),
        };
        let gw = match get_port_addr(&e.parameter_data) {
            Some((a, p)) => format!("{} ({})", a, p),
            None => "?".into(),
        };
        println!("{} -> {}", tgt, gw);
    }

    println!("resolver v4:");
    for e in table.get(RESOLVER_V4).unwrap() {
        let l3 = match get_addr(&e.keyset_data, true) {
            Some(a) => a.to_string(),
            None => "?".into(),
        };
        let l2 = match get_mac(&e.parameter_data) {
            Some(m) => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5],
            ),
            None => "?".into(),
        };
        println!("{} -> {}", l3, l2);
    }

    println!("resolver v6:");
    for e in table.get(RESOLVER_V6).unwrap() {
        let l3 = match get_addr(&e.keyset_data, true) {
            Some(a) => a.to_string(),
            None => "?".into(),
        };
        let l2 = match get_mac(&e.parameter_data) {
            Some(m) => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5],
            ),
            None => "?".into(),
        };
        println!("{} -> {}", l3, l2);
    }

    println!("nat_v4:");
    for e in table.get(NAT_V4).unwrap() {
        let dst_nat_id = match get_addr_nat_id(&e.keyset_data) {
            Some((dst, nat_start, nat_end)) => {
                format!("{} {}/{}", dst, nat_start, nat_end,)
            }
            None => "?".into(),
        };
        let target = match get_addr_vni_mac(&e.parameter_data) {
            Some((addr, vni, m)) => format!(
                "{} {}/{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                addr, vni, m[0], m[1], m[2], m[3], m[4], m[5],
            ),
            None => "?".into(),
        };
        println!("{} -> {}", dst_nat_id, target);
    }
    println!("nat_v6:");
    for e in table.get(NAT_V6).unwrap() {
        let dst_nat_id = match get_addr_nat_id(&e.keyset_data) {
            Some((dst, nat_start, nat_end)) => {
                format!("{} {}/{}", dst, nat_start, nat_end,)
            }
            None => "?".into(),
        };
        let target = match get_addr_vni_mac(&e.parameter_data) {
            Some((addr, vni, m)) => format!(
                "{} {}/{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                addr, vni, m[0], m[1], m[2], m[3], m[4], m[5],
            ),
            None => "?".into(),
        };
        println!("{} -> {}", dst_nat_id, target);
    }

    println!("port_mac:");
    for e in table.get(MAC_REWRITE).unwrap() {
        let port = u16::from_le_bytes([e.keyset_data[0], e.keyset_data[1]]);

        let m = &e.parameter_data;
        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5],
        );
        println!("{}: {}", port, mac);
    }

    println!("icmp_v6:");
    for e in table.get(NAT_ICMP_V6).unwrap() {
        dump_table_entry(e);
    }
    println!("icmp_v4:");
    for e in table.get(NAT_ICMP_V4).unwrap() {
        dump_table_entry(e);
    }

    println!("proxy_arp:");
    for e in table.get(PROXY_ARP).unwrap() {
        let begin = Ipv4Addr::new(
            e.keyset_data[0],
            e.keyset_data[1],
            e.keyset_data[2],
            e.keyset_data[3],
        );
        let end = Ipv4Addr::new(
            e.keyset_data[4],
            e.keyset_data[5],
            e.keyset_data[6],
            e.keyset_data[7],
        );

        let m = &e.parameter_data;

        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5],
        );
        println!("{}/{}: {}", begin, end, mac);
    }
}

fn dump_table_entry(e: &p4rs::TableEntry) {
    println!(
        "{} {:#x?} {:#x?}",
        e.action_id, e.keyset_data, e.parameter_data
    );
}

fn get_addr(data: &[u8], rev: bool) -> Option<IpAddr> {
    match data.len() {
        4 => {
            let mut buf: [u8; 4] = data.try_into().unwrap();
            if rev {
                buf.reverse();
            }
            Some(Ipv4Addr::from(buf).into())
        }
        16 => {
            let mut buf: [u8; 16] = data.try_into().unwrap();
            if rev {
                buf.reverse();
            }
            Some(Ipv6Addr::from(buf).into())
        }
        _ => {
            println!("expected address, found: {:x?}", data);
            None
        }
    }
}

fn get_mac(data: &[u8]) -> Option<[u8; 6]> {
    match data.len() {
        6 => Some(data.try_into().unwrap()),
        _ => {
            println!("expected mac address, found: {:x?}", data);
            None
        }
    }
}

fn get_addr_subnet(data: &[u8]) -> Option<(IpAddr, u8)> {
    match data.len() {
        5 => Some((get_addr(&data[..4], true)?, data[4])),
        17 => Some((get_addr(&data[..16], true)?, data[16])),
        _ => {
            println!("expected [address, subnet], found: {:x?}", data);
            None
        }
    }
}

fn get_addr_vni_mac(data: &[u8]) -> Option<(IpAddr, u32, [u8; 6])> {
    match data.len() {
        13 => Some((
            get_addr(&data[..4], false)?,
            u32::from_be_bytes([0, data[4], data[5], data[6]]),
            data[7..13].try_into().ok()?,
        )),
        25 => Some((
            get_addr(&data[..16], false)?,
            u32::from_be_bytes([0, data[16], data[17], data[18]]),
            data[19..25].try_into().ok()?,
        )),
        _ => {
            println!("expected [address, vni, mac], found: {:x?}", data);
            None
        }
    }
}

fn get_addr_nat_id(data: &[u8]) -> Option<(IpAddr, u16, u16)> {
    match data.len() {
        8 => Some((
            get_addr(&data[..4], false)?,
            u16::from_be_bytes([data[4], data[5]]),
            u16::from_be_bytes([data[6], data[7]]),
        )),
        20 => Some((
            get_addr(&data[..16], false)?,
            u16::from_be_bytes([data[16], data[17]]),
            u16::from_be_bytes([data[18], data[19]]),
        )),
        _ => {
            println!("expected [address, nat_id], found: {:x?}", data);
            None
        }
    }
}

fn get_port_addr(data: &[u8]) -> Option<(IpAddr, u16)> {
    match data.len() {
        6 => Some((
            get_addr(&data[2..], false)?,
            u16::from_be_bytes([data[0], data[1]]),
        )),
        18 => Some((
            get_addr(&data[2..], false)?,
            u16::from_be_bytes([data[0], data[1]]),
        )),
        _ => {
            println!("expected [port, address], found: {:x?}", data);
            None
        }
    }
}

async fn send(msg: ManagementRequest, cli: &Cli) {
    match cli.mode {
        Mode::Propolis => send_uart(msg),
        Mode::Standalone => send_uds(msg, cli).await,
    }
}

fn send_uart(msg: ManagementRequest) {
    let mut buf = Vec::new();
    buf.push(0b11100101);
    let mut js = serde_json::to_vec(&msg).unwrap();
    js.retain(|x| *x != b'\n');
    buf.extend_from_slice(&js);
    buf.push(b'\n');

    let mut f = OpenOptions::new().write(true).open("/dev/tty03").unwrap();

    f.write_all(&buf).unwrap();
    f.sync_all().unwrap();
}

async fn send_uds(msg: ManagementRequest, cli: &Cli) {
    let uds = UnixDatagram::unbound().unwrap();

    let buf = serde_json::to_vec(&msg).unwrap();
    uds.send_to(&buf, &cli.server).await.unwrap();
}

fn bind_uds(cli: &Cli) -> UnixDatagram {
    let _ = std::fs::remove_file(&cli.client);
    UnixDatagram::bind(&cli.client).unwrap()
}

async fn recv_uds(uds: UnixDatagram) -> ManagementResponse {
    let mut buf = vec![0u8; 10240];
    let n = uds.recv(&mut buf).await.unwrap();
    serde_json::from_slice(&buf[..n]).unwrap()
}
