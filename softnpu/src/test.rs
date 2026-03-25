use crate::main_pipeline;
use p4_test::softnpu::{SoftNpu, TxFrame};
use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet_macros::Packet as PktDerive;
use pnet_macros_support::types::{u1, u16be, u2, u24be, u3, u5, u6, u7};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::println;

// Protocol constants.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_SIDECAR: u16 = 0x0901;
const GENEVE_UDP_PORT: u16 = 6081;
const GENEVE_PROTO_ETH: u16 = 0x6558;
const OXG_OPTION_CLASS: u16 = 0x0129;

// Multicast tag values matching Dendrite's MULTICAST_TAG_* constants.
const MCAST_TAG_EXTERNAL: u8 = 0;
const MCAST_TAG_UNDERLAY: u8 = 1;
const MCAST_TAG_UNDERLAY_EXTERNAL: u8 = 2;

// Reserved underlay multicast destination. Packets to this prefix
// with tag=UNDERLAY_EXTERNAL are candidates for per-port decap,
// matching Dendrite's ff04::/64 subnet gate.
const UNDERLAY_MCAST_DST: &str = "ff04::1";

// Header sizes in bytes. Standard protocol values; used to compute
// field offsets into constructed packet buffers.
const IPV6_HDR_LEN: usize = 40;
const UDP_HDR_LEN: usize = 8;
const GENEVE_HDR_LEN: usize = 8;
const GENEVE_OPT_HDR_LEN: usize = 4;
const ETH_HDR_LEN: usize = 14;
const IPV4_TTL_FIELD_OFFSET: usize = 8;

// Byte offset of the inner IPv4 TTL field within the geneve-over-IPv6
// packet buffer (starting from outer IPv6, not including ethernet).
const INNER_IPV4_TTL_OFFSET: usize = IPV6_HDR_LEN
    + UDP_HDR_LEN
    + GENEVE_HDR_LEN
    + GENEVE_OPT_HDR_LEN
    + ETH_HDR_LEN
    + IPV4_TTL_FIELD_OFFSET;

/// Poll a condition with bounded retries, panicking with `msg` on timeout.
/// Default: 50 retries at 10ms intervals (500ms total).
fn wait_for<F: Fn() -> bool>(f: F, msg: &str) {
    wait_for_retries(f, msg, 50);
}

fn wait_for_retries<F: Fn() -> bool>(f: F, msg: &str, retries: usize) {
    for _ in 0..retries {
        if f() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("timed out waiting for: {msg}");
}

/// Build a sentinel IPv4 packet that routes to port 1 via the default
/// 0.0.0.0/0 entry in `pipeline_init`. Send after the packet under test,
/// then `wait_for` its arrival to confirm the pipeline has drained.
fn sentinel_v4() -> Vec<u8> {
    let mut buf = vec![0u8; 28];
    let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(28);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination("8.8.8.8".parse().unwrap());
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_ttl(64);
    buf
}

/// Build a sentinel IPv6 packet that routes to port 0 via the fd00:1::/64
/// entry in `pipeline_init`.
fn sentinel_v6() -> Vec<u8> {
    let mut buf = vec![0u8; 48];
    let mut ip = MutableIpv6Packet::new(&mut buf).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:1::99".parse().unwrap());
    ip.set_destination("fd00:1::1".parse().unwrap());
    ip.set_payload_length(8);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(64);
    buf
}

// Geneve types used to verify encap and ingress NAT behaviour.
#[allow(dead_code)]
#[derive(PktDerive)]
pub struct Geneve {
    version: u2,
    options_len: u6,
    control_packet: u1,
    has_critical_option: u1,
    _reserved: u6,
    protocol_type: u16be,
    vni: u24be,
    _reserved2: u8,

    #[payload]
    payload: Vec<u8>,
}

#[allow(dead_code)]
#[derive(PktDerive)]
pub struct GeneveOpt {
    option_class: u16be,
    critical_option: u1,
    option_type: u7,
    _reserved2: u3,
    option_len: u5,

    #[payload]
    payload: Vec<u8>,
}

/// Oxide geneve multicast option data (oxg_opt_multicast_h).
/// Follows the GeneveOpt tag when option_type == 0x01.
#[allow(dead_code)]
#[derive(PktDerive)]
pub struct OxgMcastOpt {
    mcast_tag: u2,
    _reserved: u6,
    _reserved2: u24be,

    #[payload]
    payload: Vec<u8>,
}

fn pipeline_init(pipeline: &mut main_pipeline) {
    // router entry upstream
    // Add a single path for 0.0.0.0/0 pointing at data in slot 2.
    let (key_buf, param_buf) = router_idx_entry("0.0.0.0", 0, 2, 1);
    pipeline
        .add_ingress_router_v4_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    // At slot 2, add a forwarding entry gw=1.2.3.1, port=1
    let (key_buf, param_buf) = router_forward_entry(2, "1.2.3.1", 1, 0);
    pipeline.add_ingress_router_v4_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // router entry downstream
    // Add a single path for fd00::1 pointing at data in slot 2.
    let (key_buf, param_buf) = router_idx_entry("fd00:1::", 64, 2, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    // At slot 2, add a forwarding entry gw=fe80::1 port=0
    let (key_buf, param_buf) = router_forward_entry(2, "fe80::1", 0, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // nat entry
    let (key_buf, param_buf) = nat4_entry(
        "1.2.3.4",
        1000,
        2000,
        "fd00:1::1",
        7777,
        [11, 22, 33, 44, 55, 66],
    );
    pipeline.add_ingress_nat_nat_v4_entry(
        "forward_to_sled",
        &key_buf,
        &param_buf,
        0,
    );

    // boundary services loopback ip entry
    let (key_buf, param_buf) = local6_entry("fd00:99::1");
    pipeline.add_ingress_local_local_v6_entry("local", &key_buf, &param_buf, 0);

    // resolver entry for upstream gateway
    let (key_buf, param_buf) =
        resolver4_entry("1.2.3.1", [8, 9, 10, 11, 12, 13]);
    pipeline.add_ingress_resolver_resolver_v4_entry(
        "rewrite_dst",
        &key_buf,
        &param_buf,
        0,
    );

    // resolver entry for sled
    let (key_buf, param_buf) =
        resolver6_entry("fe80::1", [20, 21, 22, 23, 24, 25]);
    pipeline.add_ingress_resolver_resolver_v6_entry(
        "rewrite_dst",
        &key_buf,
        &param_buf,
        0,
    );

    // mac rewrite tables
    let (key_buf, param_buf) = mac_rewrite_entry(0, [1, 2, 3, 4, 5, 6]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = mac_rewrite_entry(1, [6, 5, 4, 3, 2, 1]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
}

#[test]
fn vlan_routing_egress() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    /*
     * Create a header stack
     * eth
     * ipv6
     * udp
     * geneve
     * inner_eth
     * inner_ipv4
     * inner_udp
     */

    // start from bottom up
    let mut n = 8;
    let mut icmp_data: Vec<u8> = vec![0; n];
    let mut icmp = MutableIcmpPacket::new(&mut icmp_data).unwrap();
    icmp.set_payload([0x04, 0x17, 0x00, 0x00].as_slice());

    /*
    let payload = b"muffins";
    let mut n = 8 + payload.len();
    let mut inner_udp_data: Vec<u8> = vec![0; n];


    let mut inner_udp = MutableUdpPacket::new(&mut inner_udp_data).unwrap();
    inner_udp.set_source(1047);
    inner_udp.set_destination(1074);
    inner_udp.set_payload(payload);
    inner_udp.set_checksum(99);
    */

    n += 20;
    let mut inner_ip_data: Vec<u8> = vec![0; n];

    let inner_src: Ipv4Addr = "1.2.3.4".parse().unwrap();
    let inner_dst: Ipv4Addr = "8.8.8.8".parse().unwrap();
    let src: Ipv6Addr = "fd00:1::1".parse().unwrap();
    let dst: Ipv6Addr = "fd00:99::1".parse().unwrap();

    let mut inner_ip = MutableIpv4Packet::new(&mut inner_ip_data).unwrap();
    inner_ip.set_version(4);
    inner_ip.set_source(inner_src);
    inner_ip.set_header_length(5);
    inner_ip.set_destination(inner_dst);
    inner_ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    inner_ip.set_total_length(20 + icmp_data.len() as u16);
    inner_ip.set_payload(&icmp_data);

    n += 14;
    let mut eth_data: Vec<u8> = vec![0; n];
    let mut eth = MutableEthernetPacket::new(&mut eth_data).unwrap();
    eth.set_destination(MacAddr::new(0x11, 0x11, 0x11, 0x22, 0x22, 0x22));
    eth.set_source(MacAddr::new(0x33, 0x33, 0x33, 0x44, 0x44, 0x44));
    eth.set_ethertype(EtherType(ETHERTYPE_IPV4));
    eth.set_payload(&inner_ip_data);

    n += 8;
    let proto = GENEVE_PROTO_ETH.to_be_bytes();
    let mut geneve_data: Vec<u8> =
        vec![0x00, 0x00, proto[0], proto[1], 0x11, 0x11, 0x11, 0x00];
    geneve_data.extend_from_slice(&eth_data);

    n += 8;
    let mut udp_data: Vec<u8> = vec![0; n];
    let mut udp = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp.set_source(100);
    udp.set_destination(GENEVE_UDP_PORT);
    udp.set_checksum(0x1701);
    udp.set_payload(&geneve_data);

    n += 40;
    let mut ip_data: Vec<u8> = vec![0; n];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source(src);
    ip.set_destination(dst);
    ip.set_payload_length(udp_data.len() as u16);
    ip.set_payload(&udp_data);
    ip.set_next_header(IpNextHeaderProtocol::new(17));

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    let fs = phy1.recv();
    let f = &fs[0];
    let decapped_ip = Ipv4Packet::new(&f.payload).unwrap();
    let decapped_udp = UdpPacket::new(decapped_ip.payload()).unwrap();

    println!("Decapped IP: {:#?}", decapped_ip);
    println!("Decapped UDP: {:#?}", decapped_udp);

    assert_eq!(
        Ipv4Packet::new(&inner_ip_data.clone()).unwrap(),
        decapped_ip
    );
    assert_eq!(UdpPacket::new(&icmp_data.clone()).unwrap(), decapped_udp);

    Ok(())
}

#[test]
fn vlan_routing_ingress() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let mut n = 8;
    let mut icmp_data: Vec<u8> = vec![0; n];
    let mut icmp = MutableIcmpPacket::new(&mut icmp_data).unwrap();
    icmp.set_payload([0x04, 0x17, 0x00, 0x00].as_slice());

    // start from bottom up
    /*
    let payload = b"muffins";
    let mut n = 8 + payload.len();
    let mut udp_data: Vec<u8> = vec![0; n];
    let mut udp = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp.set_source(1074);
    udp.set_destination(1047);
    udp.set_checksum(0x1701);
    udp.set_payload(payload.as_slice());
    */

    n += 20;
    let mut ip_data: Vec<u8> = vec![0; n];

    let src: Ipv4Addr = "8.8.8.8".parse().unwrap();
    let dst: Ipv4Addr = "1.2.3.4".parse().unwrap();

    let send_ip_len = 20 + icmp_data.len() as u16;

    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_source(src);
    ip.set_header_length(5);
    ip.set_destination(dst);
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(1));
    ip.set_total_length(send_ip_len);
    ip.set_payload(&icmp_data);

    // ---- CASE 1 ----
    // This frame should get through
    // ----------------
    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV4, &ip_data)])?;
    wait_for(|| phy0.recv_buffer_len() > 0, "NAT packet to arrive");
    assert_eq!(phy0.recv_buffer_len(), 1);

    let fs = phy0.recv();
    let f = &fs[0];

    // Assert: correct length, Geneve header behaves reasonably, option defined.
    let ip = Ipv6Packet::new(&f.payload).unwrap();
    let udp = UdpPacket::new(ip.payload()).unwrap();
    let geneve = GenevePacket::new(udp.payload()).unwrap();
    let geneve_opt = GeneveOptPacket::new(geneve.payload()).unwrap();

    let recv_body_len = send_ip_len as usize
        + UdpPacket::minimum_packet_size()
        + GenevePacket::minimum_packet_size()
        + GeneveOptPacket::minimum_packet_size()
        + EthernetPacket::minimum_packet_size();

    assert_eq!(ip.get_payload_length(), recv_body_len as u16);
    assert_eq!(udp.get_length(), recv_body_len as u16);

    assert_eq!(udp.get_source(), GENEVE_UDP_PORT);
    assert_eq!(udp.get_destination(), GENEVE_UDP_PORT);

    assert_eq!(geneve.get_version(), 0);
    assert_eq!(geneve.get_options_len(), 1);
    assert_eq!(geneve.get_control_packet(), 0);
    assert_eq!(geneve.get_has_critical_option(), 0);
    assert_eq!(geneve.get_protocol_type(), GENEVE_PROTO_ETH);
    assert_eq!(geneve.get_vni(), 7777);

    assert_eq!(geneve_opt.get_option_class(), OXG_OPTION_CLASS);
    assert_eq!(geneve_opt.get_critical_option(), 0);
    assert_eq!(geneve_opt.get_option_type(), 0);
    assert_eq!(geneve_opt.get_option_len(), 0);

    Ok(())
}

#[test]
fn geneve_options_preserved_on_underlay() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    // router entry downstream
    // Add a single path for fd00:2:: pointing at data in slot 4.
    let (key_buf, param_buf) = router_idx_entry("fd00:2::", 64, 4, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    // At slot 4, add a forwarding entry gw=fe80::2 port=2
    let (key_buf, param_buf) = router_forward_entry(4, "fe80::2", 2, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // resolver entry for sled
    let (key_buf, param_buf) =
        resolver6_entry("fe80::2", [20, 21, 22, 23, 24, 26]);
    pipeline.add_ingress_resolver_resolver_v6_entry(
        "rewrite_dst",
        &key_buf,
        &param_buf,
        0,
    );

    // mac rewrite tables
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy2 = npu.phy(2);

    npu.run();

    // Goal: MSS option should be forwarded intact from port 0 to port 2.
    let mut n = 8;
    let mut icmp_data: Vec<u8> = vec![0; n];
    let mut icmp = MutableIcmpPacket::new(&mut icmp_data).unwrap();
    icmp.set_payload([0x04, 0x17, 0x00, 0x00].as_slice());

    n += 20;
    let mut inner_ip_data: Vec<u8> = vec![0; n];

    let inner_src: Ipv4Addr = "1.2.3.4".parse().unwrap();
    let inner_dst: Ipv4Addr = "8.8.8.8".parse().unwrap();
    let src: Ipv6Addr = "fd00:1::1".parse().unwrap();
    let dst: Ipv6Addr = "fd00:2::1".parse().unwrap();

    let mut inner_ip = MutableIpv4Packet::new(&mut inner_ip_data).unwrap();
    inner_ip.set_version(4);
    inner_ip.set_source(inner_src);
    inner_ip.set_header_length(5);
    inner_ip.set_destination(inner_dst);
    inner_ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    inner_ip.set_total_length(20 + icmp_data.len() as u16);
    inner_ip.set_payload(&icmp_data);

    n += 14;
    let mut eth_data: Vec<u8> = vec![0; n];
    let mut eth = MutableEthernetPacket::new(&mut eth_data).unwrap();
    eth.set_destination(MacAddr::new(0x11, 0x11, 0x11, 0x22, 0x22, 0x22));
    eth.set_source(MacAddr::new(0x33, 0x33, 0x33, 0x44, 0x44, 0x44));
    eth.set_ethertype(EtherType(ETHERTYPE_IPV4));
    eth.set_payload(&inner_ip_data);

    n += 16;
    let mut geneve_data: Vec<u8> = vec![0; 16];
    let mut gen = MutableGenevePacket::new(&mut geneve_data).unwrap();
    gen.set_version(0);
    gen.set_options_len(2);
    gen.set_protocol_type(GENEVE_PROTO_ETH);
    gen.set_vni(7777);
    let mut genopt = MutableGeneveOptPacket::new(gen.payload_mut()).unwrap();
    genopt.set_option_class(OXG_OPTION_CLASS);
    genopt.set_option_type(0x02);
    genopt.set_option_len(1);
    genopt.payload_mut().copy_from_slice(&1448u32.to_be_bytes());
    geneve_data.extend_from_slice(&eth_data);

    n += 8;
    let mut udp_data: Vec<u8> = vec![0; n];
    let mut udp = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp.set_source(100);
    udp.set_destination(GENEVE_UDP_PORT);
    udp.set_checksum(0x1701);
    udp.set_payload(&geneve_data);

    n += 40;
    let mut ip_data: Vec<u8> = vec![0; n];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source(src);
    ip.set_destination(dst);
    ip.set_payload_length(udp_data.len() as u16);
    ip.set_payload(&udp_data);
    ip.set_next_header(IpNextHeaderProtocol::new(17));

    phy0.send(&[TxFrame::new(phy2.mac, ETHERTYPE_IPV6, &ip_data)])?;

    let fs = phy2.recv();
    let f = &fs[0];

    // Assert: Geneve header has been carried over correctly.
    let ip = Ipv6Packet::new(&f.payload).unwrap();
    let udp = UdpPacket::new(ip.payload()).unwrap();
    let geneve = GenevePacket::new(udp.payload()).unwrap();
    let geneve_opt = GeneveOptPacket::new(geneve.payload()).unwrap();

    assert_eq!(geneve.get_version(), 0);
    assert_eq!(geneve.get_options_len(), 2);
    assert_eq!(geneve.get_control_packet(), 0);
    assert_eq!(geneve.get_has_critical_option(), 0);
    assert_eq!(geneve.get_protocol_type(), GENEVE_PROTO_ETH);
    assert_eq!(geneve.get_vni(), 7777);

    assert_eq!(geneve_opt.get_option_class(), OXG_OPTION_CLASS);
    assert_eq!(geneve_opt.get_critical_option(), 0);
    assert_eq!(geneve_opt.get_option_type(), 2);
    assert_eq!(geneve_opt.get_option_len(), 1);

    assert_eq!(
        &geneve_opt.payload()[..size_of::<u32>()],
        &1448u32.to_be_bytes()
    );

    // Goal 2: What about *two* options?
    let mut n = 8;
    let mut icmp_data: Vec<u8> = vec![0; n];
    let mut icmp = MutableIcmpPacket::new(&mut icmp_data).unwrap();
    icmp.set_payload([0x04, 0x17, 0x00, 0x00].as_slice());

    n += 20;
    let mut inner_ip_data: Vec<u8> = vec![0; n];

    let inner_src: Ipv4Addr = "1.2.3.4".parse().unwrap();
    let inner_dst: Ipv4Addr = "8.8.8.8".parse().unwrap();
    let src: Ipv6Addr = "fd00:1::1".parse().unwrap();
    let dst: Ipv6Addr = "fd00:2::1".parse().unwrap();

    let mut inner_ip = MutableIpv4Packet::new(&mut inner_ip_data).unwrap();
    inner_ip.set_version(4);
    inner_ip.set_source(inner_src);
    inner_ip.set_header_length(5);
    inner_ip.set_destination(inner_dst);
    inner_ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    inner_ip.set_total_length(20 + icmp_data.len() as u16);
    inner_ip.set_payload(&icmp_data);

    n += 14;
    let mut eth_data: Vec<u8> = vec![0; n];
    let mut eth = MutableEthernetPacket::new(&mut eth_data).unwrap();
    eth.set_destination(MacAddr::new(0x11, 0x11, 0x11, 0x22, 0x22, 0x22));
    eth.set_source(MacAddr::new(0x33, 0x33, 0x33, 0x44, 0x44, 0x44));
    eth.set_ethertype(EtherType(ETHERTYPE_IPV4));
    eth.set_payload(&inner_ip_data);

    n += 24;
    let mut geneve_data: Vec<u8> = vec![0; 24];
    let mut gen = MutableGenevePacket::new(&mut geneve_data).unwrap();
    gen.set_version(0);
    gen.set_options_len(4);
    gen.set_protocol_type(GENEVE_PROTO_ETH);
    gen.set_vni(7777);

    let opt_space = gen.payload_mut();
    let mut mcastopt =
        MutableGeneveOptPacket::new(&mut opt_space[8..]).unwrap();
    mcastopt.set_option_class(OXG_OPTION_CLASS);
    mcastopt.set_option_type(0x01);
    mcastopt.set_option_len(1);
    mcastopt
        .payload_mut()
        .copy_from_slice(&0x8000_0000u32.to_be_bytes());
    let mut mssopt = MutableGeneveOptPacket::new(&mut opt_space[..8]).unwrap();
    mssopt.set_option_class(OXG_OPTION_CLASS);
    mssopt.set_option_type(0x02);
    mssopt.set_option_len(1);
    mssopt.payload_mut().copy_from_slice(&1448u32.to_be_bytes());
    geneve_data.extend_from_slice(&eth_data);

    n += 8;
    let mut udp_data: Vec<u8> = vec![0; n];
    let mut udp = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp.set_source(100);
    udp.set_destination(GENEVE_UDP_PORT);
    udp.set_checksum(0x1701);
    udp.set_payload(&geneve_data);

    n += 40;
    let mut ip_data: Vec<u8> = vec![0; n];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source(src);
    ip.set_destination(dst);
    ip.set_payload_length(udp_data.len() as u16);
    ip.set_payload(&udp_data);
    ip.set_next_header(IpNextHeaderProtocol::new(17));

    phy0.send(&[TxFrame::new(phy2.mac, ETHERTYPE_IPV6, &ip_data)])?;

    let fs = phy2.recv();
    let f = &fs[0];

    // Assert: Geneve header has been carried over correctly.
    let ip = Ipv6Packet::new(&f.payload).unwrap();
    let udp = UdpPacket::new(ip.payload()).unwrap();
    let geneve = GenevePacket::new(udp.payload()).unwrap();
    let geneve_opt_0 = GeneveOptPacket::new(geneve.payload()).unwrap();
    let geneve_opt_0_payl = geneve_opt_0.payload();
    let geneve_opt_1 = GeneveOptPacket::new(&geneve_opt_0_payl[4..]).unwrap();
    let geneve_opt_1_payl = geneve_opt_1.payload();

    assert_eq!(geneve.get_version(), 0);
    assert_eq!(geneve.get_options_len(), 4);
    assert_eq!(geneve.get_control_packet(), 0);
    assert_eq!(geneve.get_has_critical_option(), 0);
    assert_eq!(geneve.get_protocol_type(), GENEVE_PROTO_ETH);
    assert_eq!(geneve.get_vni(), 7777);

    // NOTE: these are **not** in the same order as we put them in.
    // Since we are not making use of header stacks (and need to
    // extract semantics from e.g. multicast info), the switch places
    // each header in a dedcated slot. When deparsing, these are
    // returned in that internal order.
    assert_eq!(geneve_opt_0.get_option_class(), OXG_OPTION_CLASS);
    assert_eq!(geneve_opt_0.get_critical_option(), 0);
    assert_eq!(geneve_opt_0.get_option_type(), 1);
    assert_eq!(geneve_opt_0.get_option_len(), 1);

    assert_eq!(
        &geneve_opt_0_payl[..size_of::<u32>()],
        &0x8000_0000u32.to_be_bytes()
    );

    assert_eq!(geneve_opt_1.get_option_class(), OXG_OPTION_CLASS);
    assert_eq!(geneve_opt_1.get_critical_option(), 0);
    assert_eq!(geneve_opt_1.get_option_type(), 2);
    assert_eq!(geneve_opt_1.get_option_len(), 1);

    assert_eq!(
        &geneve_opt_1_payl[..size_of::<u32>()],
        &1448u32.to_be_bytes()
    );

    Ok(())
}

#[test]
fn ipv4_ttl1_dropped() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    // Add ttl_exceeded entry for path_idx=2, route_ttl_is_1=1.
    // The forward entry for (2, 0) is already in pipeline_init.
    let (key_buf, param_buf) = router_ttl_exceeded_entry(2);
    pipeline.add_ingress_router_v4_route_rtr_entry(
        "ttl_exceeded",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // A plain IPv4 packet with TTL=1, dst=8.8.8.8 (matches 0.0.0.0/0
    // default route). Sent from phy0 so egress port=1 avoids reflection.
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 20 + payload.len()];

    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination("8.8.8.8".parse().unwrap());
    ip.set_total_length(20 + payload.len() as u16);
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_ttl(1);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &ip_data)])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    wait_for(|| phy1.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy1.recv_buffer_len(),
        1,
        "TTL=1 packet should be dropped, only sentinel arrives"
    );

    Ok(())
}

#[test]
fn ipv4_ttl2_forwarded() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    // Add ttl_exceeded entry so both key variants exist.
    let (key_buf, param_buf) = router_ttl_exceeded_entry(2);
    pipeline.add_ingress_router_v4_route_rtr_entry(
        "ttl_exceeded",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // Same packet as above but TTL=2. Should be forwarded.
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 20 + payload.len()];

    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination("8.8.8.8".parse().unwrap());
    ip.set_total_length(20 + payload.len() as u16);
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_ttl(2);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &ip_data)])?;

    let fs = phy1.recv();
    assert!(!fs.is_empty(), "TTL=2 packet should be forwarded");

    Ok(())
}

#[test]
fn ipv6_ttl1_dropped() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    // Add ttl_exceeded entry for v6 route table, path_idx=2.
    let (key_buf, param_buf) = router_ttl_exceeded_entry(2);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "ttl_exceeded",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // An IPv6 packet with hop_limit=1, non-multicast dst that matches
    // the fd00:1::/64 route (path_idx=2, port=0). Send from phy1 so we
    // avoid reflection (egress port=0, ingress port=1).
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 40 + payload.len()];

    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:2::1".parse().unwrap());
    ip.set_destination("fd00:1::99".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(1);
    ip.set_payload(&payload);

    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV6, &ip_data)])?;
    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV6, &sentinel_v6())])?;
    wait_for(|| phy0.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy0.recv_buffer_len(),
        1,
        "hop_limit=1 packet should be dropped, only sentinel arrives"
    );

    Ok(())
}

#[test]
fn ipv4_mcast_ttl1_rejected() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // IPv4 multicast dst (224.1.1.1) with TTL=1.
    // Parser rejects before any table processing (RFC 1112).
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 20 + payload.len()];

    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination("224.1.1.1".parse().unwrap());
    ip.set_total_length(20 + payload.len() as u16);
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_ttl(1);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &ip_data)])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    wait_for(|| phy1.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy1.recv_buffer_len(),
        1,
        "IPv4 mcast TTL=1 should be rejected by parser"
    );
    assert_eq!(
        phy0.recv_buffer_len(),
        0,
        "IPv4 mcast TTL=1 should not reflect"
    );

    Ok(())
}

#[test]
fn ipv6_mcast_hop_limit1_rejected() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // IPv6 multicast dst (ff0e::1, admin-scoped) with hop_limit=1.
    // Parser rejects for non-link-local multicast with hop_limit <= 1.
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 40 + payload.len()];

    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:1::1".parse().unwrap());
    ip.set_destination("ff0e::1".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(1);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    wait_for(|| phy1.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy1.recv_buffer_len(),
        1,
        "IPv6 mcast hop_limit=1 should be rejected"
    );
    assert_eq!(
        phy0.recv_buffer_len(),
        0,
        "IPv6 mcast hop_limit=1 should not reflect"
    );

    Ok(())
}

#[test]
fn ipv6_mcast_ff01_rejected() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // IPv6 interface-local multicast (ff01::1) is always rejected
    // regardless of hop_limit.
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 40 + payload.len()];

    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:1::1".parse().unwrap());
    ip.set_destination("ff01::1".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(64);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    wait_for(|| phy1.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy1.recv_buffer_len(),
        1,
        "ff01:: should be rejected regardless of hop_limit"
    );
    assert_eq!(phy0.recv_buffer_len(), 0, "ff01:: should not reflect");

    Ok(())
}

#[test]
fn ipv4_mcast_ttl0_rejected() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 20 + payload.len()];
    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination("238.1.1.1".parse().unwrap());
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_total_length(20 + payload.len() as u16);
    ip.set_ttl(0);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &ip_data)])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    wait_for(|| phy1.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy1.recv_buffer_len(),
        1,
        "IPv4 mcast TTL=0 should be rejected"
    );

    Ok(())
}

#[test]
fn ipv6_mcast_hop_limit0_rejected() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 40 + payload.len()];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:1::1".parse().unwrap());
    ip.set_destination("ff0e::1".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(0);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    wait_for(|| phy1.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy1.recv_buffer_len(),
        1,
        "IPv6 mcast hop_limit=0 should be rejected"
    );

    Ok(())
}

// ff02:: (link-local multicast) bypasses hop limit check and routes to
// scrimlet via fwd_to_scrimlet(). The sidecar header (ethertype 0x0901)
// wraps the original packet and sends to port 0.
#[test]
fn ipv6_mcast_ff02_to_scrimlet() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // ff02::1 with hop_limit=1: would be rejected for non-link-local
    // multicast, but ff02:: bypasses the check.
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 40 + payload.len()];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:1::1".parse().unwrap());
    ip.set_destination("ff02::1".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(1);
    ip.set_payload(&payload);

    // Send from port 1 so scrimlet (port 0) can receive it.
    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(
        || phy0.recv_buffer_len() > 0,
        "scrimlet should receive ff02:: packet",
    );
    let fs = phy0.recv();
    let f = &fs[0];

    // fwd_to_scrimlet sets ethernet.ether_type = 0x0901 (sidecar header).
    assert_eq!(
        f.ethertype, ETHERTYPE_SIDECAR,
        "ff02:: packet should arrive with sidecar header ethertype"
    );

    Ok(())
}

// Basic multicast replication via IPv4 multicast dst, no geneve.
// Non-encapsulated traffic bypasses source filtering.
#[test]
fn mcast_replication_basic() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    // Route for IPv4 multicast 224.0.0.0/4 → idx=6, slot=1.
    let (key_buf, param_buf) = router_idx_entry("224.0.0.0", 4, 6, 1);
    pipeline
        .add_ingress_router_v4_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "1.2.3.1", 1, 0);
    pipeline.add_ingress_router_v4_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // Replication bitmap for 224.1.1.1.
    let (key_buf, param_buf) =
        mcast_replication_v4_entry("224.1.1.1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v4_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Plain IPv4 multicast packet, no geneve. Source filtering is
    // bypassed for non-encapsulated traffic (allow_source_mcast = true).
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 20 + payload.len()];

    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination("224.1.1.1".parse().unwrap());
    ip.set_total_length(20 + payload.len() as u16);
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_ttl(64);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &ip_data)])?;

    wait_for(
        || phy1.recv_buffer_len() > 0,
        "port 1 mcast copy (external)",
    );
    wait_for(
        || phy2.recv_buffer_len() > 0,
        "port 2 mcast copy (underlay)",
    );

    Ok(())
}

// Multicast source filter allows matching (S,G) pairs to proceed
// to replication group lookup.
#[test]
fn mcast_source_filter_allows() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    // Route for outer multicast prefix ff0e::/16 → idx=6, slot=1.
    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    // Forward entry for idx=6 → port=1, gw=fe80::1.
    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let inner_mcast_dst = "238.1.1.1";

    // Source filter: allow inner src 10.0.0.0/8 -> inner dst.
    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, inner_mcast_dst);
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    // Replication bitmap for outer dst ff0e::1.
    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // MAC rewrite for port 2.
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let ip_data = geneve_mcast_v4_pkt(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        inner_mcast_dst,
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    // Source filter matches (10.0.0.1 in 10.0.0.0/8), replication proceeds.
    wait_for(
        || phy1.recv_buffer_len() > 0,
        "port 1 mcast copy (external)",
    );
    wait_for(
        || phy2.recv_buffer_len() > 0,
        "port 2 mcast copy (underlay)",
    );

    Ok(())
}

// Source filter denies traffic from outside the allowed prefix.
#[test]
fn mcast_source_filter_denies() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    // Route for outer multicast prefix.
    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let inner_mcast_dst = "238.1.1.1";

    // Source filter only allows 10.0.0.0/8 -> inner_mcast_dst.
    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, inner_mcast_dst);
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    // Replication bitmap for ff0e::1.
    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Inner src 192.168.0.1 is outside the allowed 10.0.0.0/8 prefix.
    // Source filter should deny, no replication.
    let ip_data = geneve_mcast_v4_pkt(
        "fd00:1::1",
        "ff0e::1",
        "192.168.0.1",
        inner_mcast_dst,
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    wait_for(|| phy1.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy2.recv_buffer_len(),
        0,
        "port 2 should not receive mcast copy when source filter denies"
    );

    Ok(())
}

// When hdr.oxg_mcast.mcast_tag == 0 (External), the underlay bitmap is
// suppressed. Only external bitmap ports receive copies.
#[test]
fn mcast_replication_suppresses_underlay() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let inner_mcast_dst = "238.1.1.1";

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, inner_mcast_dst);
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // hdr.oxg_mcast.mcast_tag == 0 (External) -> suppress underlay bitmap.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        inner_mcast_dst,
        Some(MCAST_TAG_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    // External ports (port 1) should get a copy; underlay (port 2) suppressed.
    wait_for(
        || phy1.recv_buffer_len() > 0,
        "port 1 mcast copy (external)",
    );
    assert_eq!(
        phy2.recv_buffer_len(),
        0,
        "port 2 should not receive copy when underlay suppressed"
    );

    Ok(())
}

// When hdr.oxg_mcast.mcast_tag == 1 (Underlay), the external bitmap is
// suppressed. Only underlay bitmap ports receive copies.
#[test]
fn mcast_replication_suppresses_external() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let inner_mcast_dst = "238.1.1.1";

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, inner_mcast_dst);
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // hdr.oxg_mcast.mcast_tag == 1 (Underlay) -> suppress external bitmap.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        inner_mcast_dst,
        Some(MCAST_TAG_UNDERLAY),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    // Underlay ports (port 2) should get a copy; external (port 1) suppressed.
    wait_for(
        || phy2.recv_buffer_len() > 0,
        "port 2 mcast copy (underlay)",
    );
    assert_eq!(
        phy1.recv_buffer_len(),
        0,
        "port 1 should not receive copy when external suppressed"
    );

    Ok(())
}

// IPv6 inner multicast source filtering: allow path.
// Uses inner IPv6 dst ff0e::99 (full-byte slice [127:120] == 0xff, no
// x4c workaround needed).
#[test]
fn mcast_source_filter_v6_inner_allows() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // Source filter: allow inner src fd00::/16, inner dst ff0e::99.
    let (key_buf, param_buf) =
        mcast_source_filter_v6_entry("fd00::", 16, "ff0e::99");
    pipeline.add_ingress_mcast_mcast_source_filter_v6_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let ip_data = geneve_mcast_v6_inner_pkt(
        "fd00:1::1",
        "ff0e::1",
        "fd00::1",
        "ff0e::99",
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(
        || phy1.recv_buffer_len() > 0,
        "port 1 mcast copy (external)",
    );
    wait_for(
        || phy2.recv_buffer_len() > 0,
        "port 2 mcast copy (underlay)",
    );

    Ok(())
}

// IPv6 inner source filter deny path.
#[test]
fn mcast_source_filter_v6_inner_denies() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v6_entry("fd00::", 16, "ff0e::99");
    pipeline.add_ingress_mcast_mcast_source_filter_v6_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let _phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Inner src fe80::1 is outside the allowed fd00::/16.
    let ip_data = geneve_mcast_v6_inner_pkt(
        "fd00:1::1",
        "ff0e::1",
        "fe80::1",
        "ff0e::99",
    );
    phy0.send(&[TxFrame::new(_phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;
    phy0.send(&[TxFrame::new(_phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    wait_for(|| _phy1.recv_buffer_len() > 0, "sentinel");

    assert_eq!(
        phy2.recv_buffer_len(),
        0,
        "port 2 should not receive copy when v6 source filter denies"
    );

    Ok(())
}

// IPv4 outer multicast replication (non-encapsulated).
//
// This exercises the mcast_replication_v4 table.
#[test]
fn mcast_replication_v4_outer() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    // IPv4 route for 238.0.0.0/4 -> idx=6.
    let (key_buf, param_buf) = router_idx_entry("224.0.0.0", 4, 6, 1);
    pipeline
        .add_ingress_router_v4_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "1.2.3.1", 1, 0);
    pipeline.add_ingress_router_v4_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // Replication bitmap for 238.1.1.1.
    let (key_buf, param_buf) =
        mcast_replication_v4_entry("238.1.1.1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v4_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 20 + payload.len()];
    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination("238.1.1.1".parse().unwrap());
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_total_length(20 + payload.len() as u16);
    ip.set_ttl(64);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &ip_data)])?;

    wait_for(
        || phy1.recv_buffer_len() > 0,
        "port 1 mcast copy (external)",
    );
    wait_for(
        || phy2.recv_buffer_len() > 0,
        "port 2 mcast copy (underlay)",
    );

    Ok(())
}

// Non-multicast inner destination in geneve bypasses source filtering.
#[test]
fn mcast_non_mcast_inner_bypasses_source_filter() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // No source filter entries. Non-mcast inner should bypass.
    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Inner dst 10.0.0.2 is unicast, not multicast. Source filter bypassed.
    let ip_data =
        geneve_mcast_v4_pkt("fd00:1::1", "ff0e::1", "10.0.0.1", "10.0.0.2");
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(
        || phy1.recv_buffer_len() > 0,
        "port 1 mcast copy (external)",
    );
    wait_for(
        || phy2.recv_buffer_len() > 0,
        "port 2 mcast copy (underlay)",
    );

    Ok(())
}

// Untagged geneve multicast packet (no oxg_mcast option) passes through
// with geneve options unchanged and skips decap even when a decap table
// entry exists for the egress port. The decap gate requires
// oxg_mcast.isValid() and mcast_tag == 2.
#[test]
fn mcast_egress_untagged_passthrough() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mcast_replication_v6_entry("ff0e::1", &[1], &[]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Decap entry for port 1, but the packet has no mcast tag.
    let (key_buf, param_buf) = mcast_egress_decap_entry(1);
    pipeline
        .add_egress_mcast_egress_decap_entry("decap", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let ip_data =
        geneve_mcast_v4_pkt("fd00:1::1", "ff0e::1", "10.0.0.1", "238.1.1.1");
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 copy");
    let fs = phy1.recv();
    let f = &fs[0];

    // Encap preserved despite decap table entry -> no tag means no decap.
    assert_eq!(f.ethertype, ETHERTYPE_IPV6, "outer IPv6 intact");
    let ip = Ipv6Packet::new(&f.payload).unwrap();
    let udp = UdpPacket::new(ip.payload()).unwrap();
    assert_eq!(udp.get_destination(), GENEVE_UDP_PORT, "geneve intact");

    let geneve = GenevePacket::new(udp.payload()).unwrap();
    assert_eq!(
        geneve.get_options_len(),
        1,
        "geneve opt_len unchanged (no egress stamping)"
    );

    // Dst MAC derived from outer IPv6 dst (ff0e::1).
    // RFC 2464: 33:33 + lower 32 bits = 33:33:00:00:00:01.
    assert_eq!(
        f.dst,
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
        "encapsulated copy dst MAC from outer IPv6 (ff0e::1)"
    );

    Ok(())
}

// Egress preserves an existing mcast option. The option count and tag
// value pass through unchanged (read-only egress model).
#[test]
fn mcast_egress_preserves_existing_mcast_tag() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mcast_replication_v6_entry("ff0e::1", &[1], &[]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // Existing mcast option with mcast_tag=0 (External, suppresses underlay).
    // Tag preserved through pipeline (read-only egress model).
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 preserved tag copy");
    let fs = phy1.recv();
    let f = &fs[0];

    let ip = Ipv6Packet::new(&f.payload).unwrap();
    let udp = UdpPacket::new(ip.payload()).unwrap();
    let geneve = GenevePacket::new(udp.payload()).unwrap();

    // opt_len should remain 3 (external + mcast tag + mcast data).
    assert_eq!(
        geneve.get_options_len(),
        3,
        "opt_len unchanged when mcast option already present"
    );

    // Deparse external_tag first, then mcast_tag, then oxg_mcast data.
    let opt0 = GeneveOptPacket::new(geneve.payload()).unwrap();
    assert_eq!(opt0.get_option_type(), 0, "external tag");

    let opt1 = GeneveOptPacket::new(opt0.payload()).unwrap();
    assert_eq!(opt1.get_option_type(), 1, "mcast tag");
    assert_eq!(opt1.get_option_len(), 1);

    let mcast = OxgMcastOptPacket::new(opt1.payload()).unwrap();
    assert_eq!(mcast.get_mcast_tag(), 0, "tag preserved through pipeline");

    // Lengths unchanged (no new option added).
    let sent_ip = Ipv6Packet::new(&ip_data).unwrap();
    let sent_udp = UdpPacket::new(sent_ip.payload()).unwrap();
    assert_eq!(udp.get_length(), sent_udp.get_length());
    assert_eq!(ip.get_payload_length(), sent_ip.get_payload_length());

    Ok(())
}

// Egress decapsulates packets tagged Both(2) on ports with a decap entry.
// The decapsulated replica exits geneve encapsulation and is forwarded to
// a customer-facing port. Ports not in the decap table keep geneve intact.
#[test]
fn mcast_egress_decap() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff04::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Decap entry for port 2.
    let (key_buf, param_buf) = mcast_egress_decap_entry(2);
    pipeline
        .add_egress_mcast_egress_decap_entry("decap", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Send with mcast_tag=2 (Both) so egress decap gate is satisfied.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 encapped copy");
    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 decapped copy");

    // Port 1: geneve encap intact, mcast option from sender preserved.
    let fs1 = phy1.recv();
    let f1 = &fs1[0];
    assert_eq!(f1.ethertype, ETHERTYPE_IPV6, "port 1 keeps IPv6 encap");
    // Encapsulated copy: dst MAC from outer IPv6 dst (ff04::1).
    // RFC 2464: 33:33 + lower 32 bits of ff04::1 = 33:33:00:00:00:01.
    assert_eq!(
        f1.dst,
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
        "port 1 encapped dst MAC from outer IPv6"
    );
    let ip1 = Ipv6Packet::new(&f1.payload).unwrap();
    let udp1 = UdpPacket::new(ip1.payload()).unwrap();
    let geneve1 = GenevePacket::new(udp1.payload()).unwrap();
    assert_eq!(
        geneve1.get_options_len(),
        3,
        "port 1 keeps mcast option from sender"
    );

    // Port 2: decapped to inner IPv4.
    let fs2 = phy2.recv();
    let f2 = &fs2[0];
    assert_eq!(
        f2.ethertype, ETHERTYPE_IPV4,
        "port 2 decapped to inner IPv4"
    );

    // Decap must restore inner ethernet MACs, not keep underlay MACs.
    //
    // Inner dst: 01:00:5e:01:01:01 (derived from 238.1.1.1).
    // Inner src: aa:bb:cc:dd:ee:ff (set by geneve_mcast_v4_pkt).
    assert_eq!(
        f2.dst,
        [0x01, 0x00, 0x5e, 0x01, 0x01, 0x01],
        "decap restores inner eth dst (multicast MAC)"
    );
    assert_eq!(
        f2.src,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        "decap restores inner eth src"
    );

    let inner_ip = Ipv4Packet::new(&f2.payload).unwrap();
    assert_eq!(
        inner_ip.get_ttl(),
        63,
        "inner TTL decremented from 64 to 63 by decap"
    );

    // IPv4 header checksum must be valid after TTL decrement.
    let csum = pnet::packet::ipv4::checksum(&inner_ip);
    assert_eq!(
        inner_ip.get_checksum(),
        csum,
        "IPv4 header checksum recomputed after TTL decrement"
    );
    assert_eq!(
        inner_ip.get_destination(),
        "238.1.1.1".parse::<std::net::Ipv4Addr>().unwrap(),
        "inner dst preserved after decap",
    );

    Ok(())
}

// Egress decap must drop inner packets with TTL <= 1 instead of wrapping.
//
// An inner TTL of 1 decremented to 0 should be dropped, not forwarded.
// An inner TTL of 0 must never wrap to 255.
#[test]
fn mcast_egress_decap_drops_inner_ttl1() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff04::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Port 1 in external only (keeps encap, no decap entry).
    // Port 2 in both external and underlay (decap entry below).
    let (key_buf, param_buf) = mcast_egress_decap_entry(2);
    pipeline
        .add_egress_mcast_egress_decap_entry("decap", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Geneve mcast packet with mcast_tag=2 (Both) and inner TTL=1.
    // The mcast option adds 8 bytes, shifting the inner TTL offset.
    let mut ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    ip_data[INNER_IPV4_TTL_OFFSET + 8] = 1;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    // Port 1 (encapped) should still receive since inner TTL check only
    // applies at decap. Use it as our drain marker.
    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 encapped copy");

    // Port 2 should not receive: inner TTL=1 decremented to 0 means drop.
    assert_eq!(
        phy2.recv_buffer_len(),
        0,
        "decap must drop inner packet with TTL=1 (would become 0)"
    );

    Ok(())
}

// Same as above but for inner TTL=0 (should never be forwarded).
#[test]
fn mcast_egress_decap_drops_inner_ttl0() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff04::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mcast_egress_decap_entry(2);
    pipeline
        .add_egress_mcast_egress_decap_entry("decap", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Inner TTL=0 with mcast_tag=2 (Both) and must not wrap to 255.
    //
    // The mcast option adds 8 bytes, shifting the inner TTL offset.
    let mut ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    ip_data[INNER_IPV4_TTL_OFFSET + 8] = 0;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 encapped copy");
    assert_eq!(
        phy2.recv_buffer_len(),
        0,
        "decap must drop inner packet with TTL=0 (would wrap to 255)"
    );

    Ok(())
}

// Egress decapsulates inner IPv6 payloads, decrementing hop_limit and
// setting ethertype to 0x86dd.
#[test]
fn mcast_egress_decap_v6_inner() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff04::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v6_entry("fd00::", 16, "ff0e::99");
    pipeline.add_ingress_mcast_mcast_source_filter_v6_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Port 1 in external only.
    // Port 2 in both external and underlay, triggers decap.

    // Decap entry for port 2.
    let (key_buf, param_buf) = mcast_egress_decap_entry(2);
    pipeline
        .add_egress_mcast_egress_decap_entry("decap", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Send with mcast_tag=2 (Both) so egress decap gate is satisfied.
    let eth = inner_mcast_v6_frame("fd00::1", "ff0e::99");
    let ip_data = wrap_geneve(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        &eth,
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 encapped copy");
    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 decapped copy");

    // Port 1: geneve encap intact.
    let fs1 = phy1.recv();
    let f1 = &fs1[0];
    assert_eq!(f1.ethertype, ETHERTYPE_IPV6, "port 1 keeps IPv6 encap");

    // Port 2: decapped to inner IPv6.
    let fs2 = phy2.recv();
    let f2 = &fs2[0];
    assert_eq!(
        f2.ethertype, ETHERTYPE_IPV6,
        "port 2 decapped to inner IPv6"
    );

    let inner_ip = Ipv6Packet::new(&f2.payload).unwrap();
    assert_eq!(
        inner_ip.get_hop_limit(),
        63,
        "inner hop_limit decremented from 64 to 63 by decap"
    );
    assert_eq!(
        inner_ip.get_destination(),
        "ff0e::99".parse::<Ipv6Addr>().unwrap(),
        "inner dst preserved after decap",
    );
    assert_eq!(
        inner_ip.get_next_header().0,
        58,
        "inner next_header preserved (ICMPv6)"
    );

    Ok(())
}

// Both ports in the replication bitmap receive encapsulated copies
// with geneve options unchanged (opt_len=1, external tag only).
// No egress stamping occurs (read-only tag model).
#[test]
fn mcast_egress_multi_port_passthrough() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1, 2], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Port 1 in external only.
    // Port 2 in both external and underlay.

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let ip_data =
        geneve_mcast_v4_pkt("fd00:1::1", "ff0e::1", "10.0.0.1", "238.1.1.1");
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 copy");
    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 copy");

    // Both ports receive encapsulated copies with geneve options unchanged
    // (no egress stamping). opt_len stays 1 (external tag only).
    let fs1 = phy1.recv();
    let f1 = &fs1[0];
    let ip1 = Ipv6Packet::new(&f1.payload).unwrap();
    let udp1 = UdpPacket::new(ip1.payload()).unwrap();
    let geneve1 = GenevePacket::new(udp1.payload()).unwrap();
    assert_eq!(
        geneve1.get_options_len(),
        1,
        "port 1 geneve opt_len unchanged (no stamping)"
    );

    let fs2 = phy2.recv();
    let f2 = &fs2[0];
    let ip2 = Ipv6Packet::new(&f2.payload).unwrap();
    let udp2 = UdpPacket::new(ip2.payload()).unwrap();
    let geneve2 = GenevePacket::new(udp2.payload()).unwrap();
    assert_eq!(
        geneve2.get_options_len(),
        1,
        "port 2 geneve opt_len unchanged (no stamping)"
    );

    Ok(())
}

// Send with mcast_tag=1 (Underlay) as the port is in underlay only. Verify the
// tag passes through unchanged (read-only egress).
#[test]
fn mcast_egress_tagged_passthrough() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    // mcast_tag=1 (Underlay) suppresses external, so only underlay ports
    // get copies. Port 1 is underlay only.
    let (key_buf, param_buf) = mcast_replication_v6_entry("ff0e::1", &[], &[1]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // mcast_tag=1 (Underlay) suppresses the external bitmap (empty
    // here anyway). Only underlay port 1 gets a copy.
    // Tag=1 passes through (read-only egress).
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 passthrough tag copy");
    let fs = phy1.recv();
    let f = &fs[0];

    let ip = Ipv6Packet::new(&f.payload).unwrap();
    let udp = UdpPacket::new(ip.payload()).unwrap();
    let geneve = GenevePacket::new(udp.payload()).unwrap();

    // Sent with mcast option, meaning opt_len=3.
    assert_eq!(geneve.get_options_len(), 3, "mcast option preserved");

    let opt0 = GeneveOptPacket::new(geneve.payload()).unwrap();
    let opt1 = GeneveOptPacket::new(opt0.payload()).unwrap();
    let mcast = OxgMcastOptPacket::new(opt1.payload()).unwrap();
    assert_eq!(
        mcast.get_mcast_tag(),
        1,
        "mcast_tag=1 passes through (read-only egress)"
    );

    Ok(())
}

// Inner UDP port numbers and length are preserved after egress decap
// strips the outer encapsulation.
#[test]
fn mcast_egress_decap_preserves_inner_udp() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff04::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry(UNDERLAY_MCAST_DST, &[2], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Port 2 in both external and underlay, triggers decap.
    let (key_buf, param_buf) = mcast_egress_decap_entry(2);
    pipeline
        .add_egress_mcast_egress_decap_entry("decap", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy2 = npu.phy(2);

    npu.run();

    // Send with mcast_tag=2 (Both) so egress decap gate is satisfied.
    let eth = inner_mcast_v4_udp_frame("10.0.0.1", "238.1.1.1", 12345, 80);
    let ip_data = wrap_geneve(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        &eth,
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy2.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 decapped UDP copy");
    let fs = phy2.recv();
    let f = &fs[0];

    assert_eq!(f.ethertype, ETHERTYPE_IPV4, "decapped to inner IPv4");
    let inner_ip = Ipv4Packet::new(&f.payload).unwrap();
    assert_eq!(
        inner_ip.get_next_level_protocol().0,
        17,
        "inner proto is UDP"
    );

    let inner_udp = UdpPacket::new(inner_ip.payload()).unwrap();
    assert_eq!(
        inner_udp.get_source(),
        12345,
        "inner UDP src port preserved"
    );
    assert_eq!(
        inner_udp.get_destination(),
        80,
        "inner UDP dst port preserved"
    );
    assert_eq!(inner_udp.get_length(), 12, "inner UDP length preserved");

    Ok(())
}

// Decap with VLAN: the decap_vlan action strips geneve and inserts a VLAN
// tag with the configured VLAN ID (vid). The inner ethertype moves into the
// VLAN header and the outer ethertype becomes 0x8100.
#[test]
fn mcast_egress_decap_vlan() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff04::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Port 1 in external only.
    // Port 2 in both external and underlay.

    // VLAN decap entry for port 2 with vid=100.
    let (key_buf, param_buf) = mcast_egress_decap_vlan_entry(2, 100);
    pipeline.add_egress_mcast_egress_decap_entry(
        "decap_vlan",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Send with mcast_tag=2 (Both) so egress decap gate is satisfied.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 vlan decapped copy");
    let fs = phy2.recv();
    let f = &fs[0];

    // The frame receiver strips the VLAN tag into f.vid and sets
    // f.ethertype to the inner ethertype.
    assert_eq!(f.vid, Some(100), "VLAN tag present with vid=100");
    assert_eq!(f.ethertype, ETHERTYPE_IPV4, "inner ethertype is IPv4");

    let inner_ip = Ipv4Packet::new(&f.payload).unwrap();
    assert_eq!(inner_ip.get_ttl(), 63, "inner TTL decremented");

    // Multicast dst MAC derived from inner IPv4 (238.1.1.1).
    assert_eq!(
        f.dst,
        [0x01, 0x00, 0x5e, 0x01, 0x01, 0x01],
        "decap_vlan derives mcast dst MAC from inner IPv4"
    );

    Ok(())
}

// Port in both external and underlay bitmaps, sent with tag=Both(2) but has
// no mcast_egress_decap entry. Geneve encapsulation stays intact.
#[test]
fn mcast_both_tag_without_decap_keeps_encap() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff04::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_replication_v6_entry(UNDERLAY_MCAST_DST, &[2], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Port 2 in both external and underlay, no decap entry.

    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy2 = npu.phy(2);

    npu.run();

    // Send with mcast_tag=2 (Both) to exercise the no-decap path.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy2.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 copy with tag=Both");
    let fs = phy2.recv();
    let f = &fs[0];

    // Encap preserved: outer IPv6 with geneve.
    assert_eq!(f.ethertype, ETHERTYPE_IPV6, "outer IPv6 encap intact");
    let ip = Ipv6Packet::new(&f.payload).unwrap();
    let udp = UdpPacket::new(ip.payload()).unwrap();
    assert_eq!(
        udp.get_destination(),
        GENEVE_UDP_PORT,
        "geneve UDP port intact"
    );

    let geneve = GenevePacket::new(udp.payload()).unwrap();
    assert_eq!(
        geneve.get_options_len(),
        3,
        "mcast option preserved from sender"
    );

    // Verify tag = Both = 2 preserved through pipeline.
    let opt0 = GeneveOptPacket::new(geneve.payload()).unwrap();
    let opt1 = GeneveOptPacket::new(opt0.payload()).unwrap();
    let mcast = OxgMcastOptPacket::new(opt1.payload()).unwrap();
    assert_eq!(
        mcast.get_mcast_tag(),
        2,
        "tag = Both = 2, no decap entry: encap preserved"
    );

    Ok(())
}

// Non-encapsulated IPv6 multicast replication.
//
// No geneve header means allow_source_mcast = true, and
// mcast_replication_v6 matches on hdr.ipv6.dst directly.
#[test]
fn mcast_replication_v6_outer() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    // IPv6 route for ff0e::/16 -> idx=6.
    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // Replication bitmap for ff0e::1.
    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[1], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = mac_rewrite_entry(2, [1, 2, 3, 4, 5, 8]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Raw IPv6 multicast, no geneve.
    let payload = [0u8; 8];
    let mut ip_data = vec![0u8; 40 + payload.len()];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:1::1".parse().unwrap());
    ip.set_destination("ff0e::1".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(64);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    wait_for(
        || phy1.recv_buffer_len() > 0,
        "port 1 mcast copy (external)",
    );
    wait_for(
        || phy2.recv_buffer_len() > 0,
        "port 2 mcast copy (underlay)",
    );

    Ok(())
}

// PRE filters out the ingress port from multicast replication.
#[test]
fn mcast_ingress_port_suppressed() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    // External bitmap includes port 0 (ingress) and port 1.
    let (key_buf, param_buf) =
        mcast_replication_v6_entry("ff0e::1", &[0, 1], &[]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mac_rewrite_entry(1, [1, 2, 3, 4, 5, 7]);
    pipeline
        .add_ingress_mac_mac_rewrite_entry("rewrite", &key_buf, &param_buf, 0);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let ip_data =
        geneve_mcast_v4_pkt("fd00:1::1", "ff0e::1", "10.0.0.1", "238.1.1.1");

    // Send from port 0.
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    // Port 1 should receive, port 0 (ingress) should not. Once port 1
    // has its copy the pipeline has finished processing this packet.
    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 receives copy");
    assert_eq!(
        phy0.recv_buffer_len(),
        0,
        "ingress port 0 should not receive a copy"
    );

    Ok(())
}

// When the only active bitmap after suppression has no ports, no copies
// are produced.
#[test]
fn mcast_suppression_drops_when_only_group_zeroed() -> Result<(), anyhow::Error>
{
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("ff0e::", 16, 6, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    let (key_buf, param_buf) = router_forward_entry(6, "fe80::1", 1, 0);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    // External bitmap has no ports. Underlay bitmap has port 2.
    // mcast_tag=0 (External) suppresses underlay, leaving external empty.
    let (key_buf, param_buf) = mcast_replication_v6_entry("ff0e::1", &[], &[2]);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // mcast_tag=0 (External): suppresses underlay. External is empty. No copies.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;

    // Sentinel: send a plain unicast packet that routes to port 1 via the
    // default 0.0.0.0/0 entry in pipeline_init. Once it arrives we know
    // the pipeline has drained all earlier packets.
    let mut sentinel = vec![0u8; 28];
    let mut sip = MutableIpv4Packet::new(&mut sentinel).unwrap();
    sip.set_version(4);
    sip.set_header_length(5);
    sip.set_source("10.0.0.1".parse().unwrap());
    sip.set_destination("8.8.8.8".parse().unwrap());
    sip.set_total_length(28);
    sip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    sip.set_ttl(64);
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel)])?;

    // Wait for the sentinel to arrive at port 1, then check mcast ports.
    // Port 1 receives 2 frames: the mcast packet unicast-routed via the
    // router table (bitmap merged to 0, no replication) plus the sentinel.
    // The key assertion is that port 2 (underlay) receives nothing.
    wait_for(|| phy1.recv_buffer_len() > 0, "sentinel on port 1");
    assert_eq!(
        phy1.recv_buffer_len(),
        2,
        "unicast-routed mcast packet + sentinel on port 1"
    );
    assert_eq!(
        phy2.recv_buffer_len(),
        0,
        "port 2 should not receive (underlay suppressed)"
    );

    Ok(())
}

// Create an entry for the multipath cidr -> index table
fn router_idx_entry(
    dst: &str,
    prefix_len: u8,
    idx: u16,
    slots: u8,
) -> (Vec<u8>, Vec<u8>) {
    let mut key_buf = match dst.parse().unwrap() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    key_buf.push(prefix_len);

    let mut param_buf = idx.to_le_bytes().to_vec();
    let slots_buf = slots.to_le_bytes().to_vec();
    param_buf.extend_from_slice(&slots_buf);

    (key_buf, param_buf)
}

// Create an entry for the multipath index -> forwarding data table
fn router_forward_entry(
    idx: u16,
    gw: &str,
    port: u16,
    route_ttl_is_1: u8,
) -> (Vec<u8>, Vec<u8>) {
    let mut key_buf = idx.to_le_bytes().to_vec();
    key_buf.push(route_ttl_is_1);

    let mut param_buf = port.to_le_bytes().to_vec();

    let mut nexthop_buf = match gw.parse().unwrap() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    nexthop_buf.reverse();
    param_buf.extend_from_slice(&nexthop_buf);

    (key_buf, param_buf)
}

// Create a route entry that drops packets with TTL==1.
// The key matches on (path_idx, route_ttl_is_1=1) with the ttl_exceeded
// action which has no parameters.
fn router_ttl_exceeded_entry(idx: u16) -> (Vec<u8>, Vec<u8>) {
    let mut key_buf = idx.to_le_bytes().to_vec();
    key_buf.push(1);
    (key_buf, Vec::new())
}

fn nat4_entry(
    addr: &str,
    begin: u16,
    end: u16,
    target: &str,
    vni: u32,
    mac: [u8; 6],
) -> (Vec<u8>, Vec<u8>) {
    let addr: Ipv4Addr = addr.parse().unwrap();
    let target: Ipv6Addr = target.parse().unwrap();

    let mut key_buf = Vec::new();
    let mut buf = addr.octets().to_vec();
    buf.reverse();
    key_buf.extend_from_slice(&buf);
    key_buf.extend_from_slice(&begin.to_le_bytes());
    key_buf.extend_from_slice(&end.to_le_bytes());

    let mut param_buf = Vec::new();
    let mut buf = target.octets().to_vec();
    buf.reverse();
    param_buf.extend_from_slice(&buf);
    param_buf.extend_from_slice(&vni.to_le_bytes()[..3]);
    param_buf.extend_from_slice(&mac);

    (key_buf, param_buf)
}

fn local6_entry(addr: &str) -> (Vec<u8>, Vec<u8>) {
    let addr: Ipv6Addr = addr.parse().unwrap();
    let mut key_buf = addr.octets().to_vec();
    key_buf.reverse();

    (key_buf, Vec::new())
}

fn resolver4_entry(addr: &str, mac: [u8; 6]) -> (Vec<u8>, Vec<u8>) {
    let addr: Ipv4Addr = addr.parse().unwrap();
    let mut key_buf = addr.octets().to_vec();
    key_buf.reverse();

    (key_buf, mac.to_vec())
}

fn resolver6_entry(addr: &str, mac: [u8; 6]) -> (Vec<u8>, Vec<u8>) {
    let addr: Ipv6Addr = addr.parse().unwrap();
    let mut key_buf = addr.octets().to_vec();
    key_buf.reverse();

    (key_buf, mac.to_vec())
}

fn mac_rewrite_entry(port: u16, mac: [u8; 6]) -> (Vec<u8>, Vec<u8>) {
    let key_buf = port.to_le_bytes().to_vec();
    let param_buf = mac.to_vec();

    (key_buf, param_buf)
}

// Build a port bitmap for use as action parameter_data.
// With Msb0 ordering, bit index N in the BitVec corresponds to port N.
// The bitmap is 128 bits (16 bytes) to match the P4 `bit<128>` field.
fn port_bitmap(ports: &[u16]) -> Vec<u8> {
    let byte_len = 16;
    let mut bm = vec![0u8; byte_len];
    for &p in ports {
        let byte_idx = (p / 8) as usize;
        let bit_idx = 7 - (p % 8);
        assert!(byte_idx < byte_len, "port {p} exceeds bitmap width");
        bm[byte_idx] |= 1 << bit_idx;
    }
    bm
}

// Multicast replication bitmap lookup for IPv6 outer destination.
//
// Key matches hdr.ipv6.dst, stored in wire order (not reversed).
// Action has two parameters: external bitmap and underlay bitmap.
fn mcast_replication_v6_entry(
    dst: &str,
    external_ports: &[u16],
    underlay_ports: &[u16],
) -> (Vec<u8>, Vec<u8>) {
    let addr: Ipv6Addr = dst.parse().unwrap();
    let mut key_buf = addr.octets().to_vec();
    key_buf.reverse();

    let mut param_buf = port_bitmap(external_ports);
    param_buf.extend_from_slice(&port_bitmap(underlay_ports));

    (key_buf, param_buf)
}

// Multicast replication bitmap lookup for IPv4 outer destination.
fn mcast_replication_v4_entry(
    dst: &str,
    external_ports: &[u16],
    underlay_ports: &[u16],
) -> (Vec<u8>, Vec<u8>) {
    let addr: Ipv4Addr = dst.parse().unwrap();
    let mut key_buf = addr.octets().to_vec();
    key_buf.reverse();

    let mut param_buf = port_bitmap(external_ports);
    param_buf.extend_from_slice(&port_bitmap(underlay_ports));

    (key_buf, param_buf)
}

// Source filter entry for inner IPv4 multicast.
// Key: inner src (LPM, wire order) + inner dst (exact, wire order).
// Both are header fields, so bytes match packet wire order.
fn mcast_source_filter_v4_entry(
    src: &str,
    src_prefix_len: u8,
    dst: &str,
) -> (Vec<u8>, Vec<u8>) {
    let src_addr: Ipv4Addr = src.parse().unwrap();
    let dst_addr: Ipv4Addr = dst.parse().unwrap();

    // LPM key: network order (IpAddr::from expects BE)
    let mut key_buf = src_addr.octets().to_vec();
    key_buf.push(src_prefix_len);
    // Exact key: reversed to match confused-endian header storage
    let mut dst_bytes = dst_addr.octets().to_vec();
    dst_bytes.reverse();
    key_buf.extend_from_slice(&dst_bytes);

    (key_buf, Vec::new())
}

// Source filter entry for inner IPv6 multicast.
fn mcast_source_filter_v6_entry(
    src: &str,
    src_prefix_len: u8,
    dst: &str,
) -> (Vec<u8>, Vec<u8>) {
    let src_addr: Ipv6Addr = src.parse().unwrap();
    let dst_addr: Ipv6Addr = dst.parse().unwrap();

    // LPM key: network order (IpAddr::from expects BE)
    let mut key_buf = src_addr.octets().to_vec();
    key_buf.push(src_prefix_len);
    // Exact key: reversed to match confused-endian header storage
    let mut dst_bytes = dst_addr.octets().to_vec();
    dst_bytes.reverse();
    key_buf.extend_from_slice(&dst_bytes);

    (key_buf, Vec::new())
}

// Egress decap entry for multicast replicated copies.
fn mcast_egress_decap_entry(port: u16) -> (Vec<u8>, Vec<u8>) {
    let key_buf = port.to_le_bytes().to_vec();
    (key_buf, Vec::new())
}

fn mcast_egress_decap_vlan_entry(
    port: u16,
    vlan_id: u16,
) -> (Vec<u8>, Vec<u8>) {
    let key_buf = port.to_le_bytes().to_vec();
    let param_buf = vlan_id.to_le_bytes().to_vec();
    (key_buf, param_buf)
}

/// Wrap an inner ethernet frame in geneve-over-IPv6 with an Oxide
/// external tag. When `mcast_tag` is `Some(v)`, also includes the
/// oxg_mcast option (0 = External, 1 = Underlay, 2 = Both).
fn wrap_geneve(
    outer_src: &str,
    outer_dst: &str,
    inner_eth: &[u8],
    mcast_tag: Option<u8>,
) -> Vec<u8> {
    let opt_chunks: u8 = if mcast_tag.is_some() { 3 } else { 1 };
    // Geneve byte 0: version(2 bits) = 0, opt_len(6 bits) = opt_chunks.
    let geneve_byte0 = opt_chunks & 0x3f;
    let proto = GENEVE_PROTO_ETH.to_be_bytes();
    let oxg = OXG_OPTION_CLASS.to_be_bytes();

    let mut geneve_data: Vec<u8> = vec![
        geneve_byte0,
        0x00,
        proto[0],
        proto[1],
        0x00,
        0x00,
        0x01,
        0x00,
    ];
    geneve_data.extend_from_slice(&[oxg[0], oxg[1], 0x00, 0x00]);

    if let Some(tag) = mcast_tag {
        geneve_data.extend_from_slice(&[oxg[0], oxg[1], 0x01, 0x01]);
        let mcast_byte0 = tag << 6;
        geneve_data.extend_from_slice(&[mcast_byte0, 0x00, 0x00, 0x00]);
    }

    geneve_data.extend_from_slice(inner_eth);

    let mut udp_data = vec![0u8; 8 + geneve_data.len()];
    let mut udp = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp.set_source(100);
    udp.set_destination(GENEVE_UDP_PORT);
    udp.set_checksum(0);
    udp.set_payload(&geneve_data);

    let mut ip_data = vec![0u8; 40 + udp_data.len()];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source(outer_src.parse().unwrap());
    ip.set_destination(outer_dst.parse().unwrap());
    ip.set_payload_length(udp_data.len() as u16);
    ip.set_payload(&udp_data);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(64);

    ip_data
}

/// Inner IPv4/ICMP multicast ethernet frame.
fn inner_mcast_v4_frame(src: &str, dst: &str) -> Vec<u8> {
    let mut icmp_data = vec![0u8; 8];
    let mut icmp = MutableIcmpPacket::new(&mut icmp_data).unwrap();
    icmp.set_payload([0x04, 0x17, 0x00, 0x00].as_slice());

    let mut inner_ip_data = vec![0u8; 28];
    let mut inner_ip = MutableIpv4Packet::new(&mut inner_ip_data).unwrap();
    inner_ip.set_version(4);
    inner_ip.set_header_length(5);
    inner_ip.set_source(src.parse().unwrap());
    inner_ip.set_destination(dst.parse().unwrap());
    inner_ip.set_next_level_protocol(IpNextHeaderProtocol::new(1));
    inner_ip.set_total_length(28);
    inner_ip.set_ttl(64);
    inner_ip.set_payload(&icmp_data);
    let csum = pnet::packet::ipv4::checksum(&inner_ip.to_immutable());
    inner_ip.set_checksum(csum);

    let d: Ipv4Addr = dst.parse().unwrap();
    let o = d.octets();
    let mut eth_data = vec![0u8; 14 + inner_ip_data.len()];
    let mut eth = MutableEthernetPacket::new(&mut eth_data).unwrap();
    eth.set_destination(MacAddr::new(
        0x01,
        0x00,
        0x5e,
        o[1] & 0x7f,
        o[2],
        o[3],
    ));
    eth.set_source(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
    eth.set_ethertype(EtherType(ETHERTYPE_IPV4));
    eth.set_payload(&inner_ip_data);

    eth_data
}

/// Inner IPv6/ICMPv6 multicast ethernet frame.
fn inner_mcast_v6_frame(src: &str, dst: &str) -> Vec<u8> {
    let icmpv6_data = [0x80u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];

    let mut inner_ip_data = vec![0u8; 40 + icmpv6_data.len()];
    let mut inner_ip = MutableIpv6Packet::new(&mut inner_ip_data).unwrap();
    inner_ip.set_version(6);
    inner_ip.set_source(src.parse().unwrap());
    inner_ip.set_destination(dst.parse().unwrap());
    inner_ip.set_payload_length(icmpv6_data.len() as u16);
    inner_ip.set_next_header(IpNextHeaderProtocol::new(58));
    inner_ip.set_hop_limit(64);
    inner_ip.set_payload(&icmpv6_data);

    let d: Ipv6Addr = dst.parse().unwrap();
    let o = d.octets();
    let mut eth_data = vec![0u8; 14 + inner_ip_data.len()];
    let mut eth = MutableEthernetPacket::new(&mut eth_data).unwrap();
    eth.set_destination(MacAddr::new(0x33, 0x33, o[12], o[13], o[14], o[15]));
    eth.set_source(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
    eth.set_ethertype(EtherType(ETHERTYPE_IPV6));
    eth.set_payload(&inner_ip_data);

    eth_data
}

/// Inner IPv4/UDP multicast ethernet frame.
fn inner_mcast_v4_udp_frame(
    src: &str,
    dst: &str,
    udp_src: u16,
    udp_dst: u16,
) -> Vec<u8> {
    let mut inner_udp_data = vec![0u8; 12];
    let mut iudp = MutableUdpPacket::new(&mut inner_udp_data).unwrap();
    iudp.set_source(udp_src);
    iudp.set_destination(udp_dst);
    iudp.set_length(12);
    iudp.set_payload(&[0xde, 0xad, 0xbe, 0xef]);

    let inner_ip_len = 20 + inner_udp_data.len();
    let mut inner_ip_data = vec![0u8; inner_ip_len];
    let mut inner_ip = MutableIpv4Packet::new(&mut inner_ip_data).unwrap();
    inner_ip.set_version(4);
    inner_ip.set_header_length(5);
    inner_ip.set_source(src.parse().unwrap());
    inner_ip.set_destination(dst.parse().unwrap());
    inner_ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    inner_ip.set_total_length(inner_ip_len as u16);
    inner_ip.set_ttl(64);
    inner_ip.set_payload(&inner_udp_data);

    let d: Ipv4Addr = dst.parse().unwrap();
    let o = d.octets();
    let mut eth_data = vec![0u8; 14 + inner_ip_data.len()];
    let mut eth = MutableEthernetPacket::new(&mut eth_data).unwrap();
    eth.set_destination(MacAddr::new(
        0x01,
        0x00,
        0x5e,
        o[1] & 0x7f,
        o[2],
        o[3],
    ));
    eth.set_source(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
    eth.set_ethertype(EtherType(ETHERTYPE_IPV4));
    eth.set_payload(&inner_ip_data);

    eth_data
}

/// Geneve-over-IPv6 with inner IPv4/ICMP, no mcast tag.
fn geneve_mcast_v4_pkt(
    outer_src: &str,
    outer_dst: &str,
    inner_src: &str,
    inner_dst: &str,
) -> Vec<u8> {
    geneve_mcast_v4_pkt_repl(outer_src, outer_dst, inner_src, inner_dst, None)
}

/// Geneve-over-IPv6 with inner IPv4/ICMP and optional mcast tag.
fn geneve_mcast_v4_pkt_repl(
    outer_src: &str,
    outer_dst: &str,
    inner_src: &str,
    inner_dst: &str,
    mcast_tag: Option<u8>,
) -> Vec<u8> {
    let eth = inner_mcast_v4_frame(inner_src, inner_dst);
    wrap_geneve(outer_src, outer_dst, &eth, mcast_tag)
}

/// Geneve-over-IPv6 with inner IPv6/ICMPv6.
fn geneve_mcast_v6_inner_pkt(
    outer_src: &str,
    outer_dst: &str,
    inner_src: &str,
    inner_dst: &str,
) -> Vec<u8> {
    let eth = inner_mcast_v6_frame(inner_src, inner_dst);
    wrap_geneve(outer_src, outer_dst, &eth, None)
}
