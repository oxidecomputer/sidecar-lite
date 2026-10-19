use crate::main_pipeline;
use p4_test::softnpu::{
    OuterPhy, OwnedFrame, SoftNpu, TxFrame, EXPECT_FRAMES_TIMEOUT,
};
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
use std::time::Duration;

// Protocol constants.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
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
// matching Dendrite's ff04::/64 subnet check.
const UNDERLAY_MCAST_DST: &str = "ff04::1";

// Header sizes in bytes.
//
// These are standard protocol values and used to compute
// field offsets into our constructed packet buffers.

const IPV6_HDR_LEN: usize = 40;
const UDP_HDR_LEN: usize = 8;
const GENEVE_HDR_LEN: usize = 8;
const GENEVE_OPT_HDR_LEN: usize = 4;
const ETH_HDR_LEN: usize = 14;
const IPV4_TTL_FIELD_OFFSET: usize = 8;
const SIDECAR_HDR_LEN: usize = 24;

const SENTINEL_IPV4_ID: u16 = 0x5e57;
const SENTINEL_IPV6_FLOW_LABEL: u32 = 0x5e57;

const POLL_INTERVAL: Duration = Duration::from_millis(1);

// Byte offset of the inner IPv4 TTL field within the geneve-over-IPv6
// packet buffer (starting from outer IPv6, not including ethernet).
const INNER_IPV4_TTL_OFFSET: usize = IPV6_HDR_LEN
    + UDP_HDR_LEN
    + GENEVE_HDR_LEN
    + GENEVE_OPT_HDR_LEN
    + ETH_HDR_LEN
    + IPV4_TTL_FIELD_OFFSET;

// Same offset for packets carrying the multicast option after the external
// tag, which adds an option header and 4 bytes of option data.
const INNER_IPV4_TTL_OFFSET_MCAST: usize =
    INNER_IPV4_TTL_OFFSET + GENEVE_OPT_HDR_LEN + 4;

// The inner IPv4 protocol field directly follows TTL.
const INNER_IPV4_PROTO_OFFSET_MCAST: usize = INNER_IPV4_TTL_OFFSET_MCAST + 1;

// Poll a condition until it returns true, panicking with `msg` after
// `EXPECT_FRAMES_TIMEOUT`, which is the same bound the p4 harness uses for
// `expect_frames!`.
fn wait_for<F: Fn() -> bool>(f: F, msg: &str) {
    let deadline = std::time::Instant::now() + EXPECT_FRAMES_TIMEOUT;
    while !f() {
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for: {msg}");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

// Build a sentinel IPv4 packet that routes to port 1 via the default
// 0.0.0.0/0 entry in `pipeline_init`.
//
// We only send out the sentinel out after the packet that's actually under
// test, from the same ingress port, and then `recv_until_sentinel` to confirm
// the pipeline has drained properly.
fn sentinel_v4() -> Vec<u8> {
    sentinel_v4_to("8.8.8.8")
}

fn sentinel_v4_to(dst: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 28];
    let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(28);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination(dst.parse().unwrap());
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_ttl(64);
    ip.set_identification(SENTINEL_IPV4_ID);
    buf
}

// Similar to above, build a sentinel IPv6 packet that routes to port 0 via the
// fd00:1::/64 entry in `pipeline_init`.
fn sentinel_v6() -> Vec<u8> {
    sentinel_v6_to("fd00:1::1")
}

fn sentinel_v6_to(dst: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 48];
    let mut ip = MutableIpv6Packet::new(&mut buf).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:1::99".parse().unwrap());
    ip.set_destination(dst.parse().unwrap());
    ip.set_payload_length(8);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(64);
    mark_sentinel_v6(buf)
}

fn mark_sentinel_v6(mut ip_data: Vec<u8>) -> Vec<u8> {
    MutableIpv6Packet::new(&mut ip_data)
        .unwrap()
        .set_flow_label(SENTINEL_IPV6_FLOW_LABEL);
    ip_data
}

fn is_sentinel_v4(f: &OwnedFrame) -> bool {
    f.ethertype == ETHERTYPE_IPV4
        && Ipv4Packet::new(&f.payload)
            .is_some_and(|ip| ip.get_identification() == SENTINEL_IPV4_ID)
}

fn is_sentinel_v6(f: &OwnedFrame) -> bool {
    let l3 = match f.ethertype {
        ETHERTYPE_IPV6 => &f.payload[..],
        ETHERTYPE_SIDECAR
            if f.payload.len() > SIDECAR_HDR_LEN
                && u16::from_be_bytes([f.payload[6], f.payload[7]])
                    == ETHERTYPE_IPV6 =>
        {
            &f.payload[SIDECAR_HDR_LEN..]
        }
        _ => return false,
    };
    Ipv6Packet::new(l3)
        .is_some_and(|ip| ip.get_flow_label() == SENTINEL_IPV6_FLOW_LABEL)
}

fn is_sentinel(f: &OwnedFrame) -> bool {
    is_sentinel_v4(f) || is_sentinel_v6(f)
}

fn recv_until_sentinel<const R: usize, const N: usize, const F: usize>(
    phy: &OuterPhy<R, N, F>,
    msg: &str,
) -> Vec<OwnedFrame> {
    let deadline = std::time::Instant::now() + EXPECT_FRAMES_TIMEOUT;
    let mut before = Vec::new();
    loop {
        if phy.recv_buffer_len() > 0 {
            let mut frames = phy.recv().into_iter();
            for f in frames.by_ref() {
                if is_sentinel(&f) {
                    let after = frames.count();
                    assert_eq!(after, 0, "{msg}: frames after sentinel");
                    return before;
                }
                before.push(f);
            }
        }

        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for: {msg}");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

// Geneve types used to verify encap and ingress NAT behaviour.
//
// Note: these structs only describe a wire layout for pnet's derive, which
// generates the `*Packet` accessors used by our test suite. The accessors
// read the packet buffer itself, but never these individual fields.

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

// Oxide geneve multicast option data (oxg_opt_multicast_h).
//
// Follows the GeneveOpt tag when option_type == 0x01.
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
    let (key_buf, param_buf) = router_forward_entry(2, "1.2.3.1", 1);
    pipeline.add_ingress_router_v4_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // router entry downstream
    // Add a single path for fd00::1 pointing at data in slot 2.
    let (key_buf, param_buf) = router_idx_entry("fd00:1::", 64, 2, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    // At slot 2, add a forwarding entry gw=fe80::1 port=0
    let (key_buf, param_buf) = router_forward_entry(2, "fe80::1", 0);
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

fn sentinel_route_v4(pipeline: &mut main_pipeline, port: u16) -> String {
    let idx = 200 + port;
    let prefix = format!("9.9.{port}.0");
    let gw = format!("1.2.{port}.254");

    let (key_buf, param_buf) = router_idx_entry(&prefix, 24, idx, 1);
    pipeline
        .add_ingress_router_v4_idx_rtr_entry("index", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = router_forward_entry(idx, &gw, port);
    pipeline.add_ingress_router_v4_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );
    let (key_buf, param_buf) =
        resolver4_entry(&gw, [0x5e, 0x57, 0, 0, 0, port as u8]);
    pipeline.add_ingress_resolver_resolver_v4_entry(
        "rewrite_dst",
        &key_buf,
        &param_buf,
        0,
    );

    format!("9.9.{port}.9")
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
    inner_ip.set_ttl(64);
    inner_ip.set_payload(&icmp_data);
    let csum = pnet::packet::ipv4::checksum(&inner_ip.to_immutable());
    inner_ip.set_checksum(csum);

    let mut expected_ip_data = inner_ip_data.clone();
    let mut expected_ip =
        MutableIpv4Packet::new(&mut expected_ip_data).unwrap();
    expected_ip.set_ttl(63);
    let csum = pnet::packet::ipv4::checksum(&expected_ip.to_immutable());
    expected_ip.set_checksum(csum);

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
    ip.set_hop_limit(64);

    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "decapped frame");
    let fs = phy1.recv();
    let f = &fs[0];
    let decapped_ip = Ipv4Packet::new(&f.payload).unwrap();
    let decapped_udp = UdpPacket::new(decapped_ip.payload()).unwrap();

    println!("Decapped IP: {:#?}", decapped_ip);
    println!("Decapped UDP: {:#?}", decapped_udp);

    assert_eq!(Ipv4Packet::new(&expected_ip_data).unwrap(), decapped_ip);
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
    ip.set_ttl(64);
    ip.set_payload(&icmp_data);

    // ---- CASE 1 ----
    // This frame should get through
    // ----------------
    phy1.send(&[TxFrame::new(
        l2_dst(phy0.mac, ETHERTYPE_IPV4, &ip_data),
        ETHERTYPE_IPV4,
        &ip_data,
    )])?;
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
    let (key_buf, param_buf) = router_forward_entry(4, "fe80::2", 2);
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
    ip.set_hop_limit(64);

    phy0.send(&[TxFrame::new(
        l2_dst(phy2.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy2.recv_buffer_len() > 0, "underlay frame");
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
    ip.set_hop_limit(64);

    phy0.send(&[TxFrame::new(
        l2_dst(phy2.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy2.recv_buffer_len() > 0, "underlay frame");
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

    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV4, &ip_data),
        ETHERTYPE_IPV4,
        &ip_data,
    )])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    let leaked_pkts = recv_until_sentinel(&phy1, "sentinel");
    assert!(
        leaked_pkts.is_empty(),
        "TTL=1 packet should be dropped, only sentinel arrives"
    );

    Ok(())
}

#[test]
fn ipv4_ttl2_forwarded() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

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
    let csum = pnet::packet::ipv4::checksum(&ip.to_immutable());
    ip.set_checksum(csum);

    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV4, &ip_data),
        ETHERTYPE_IPV4,
        &ip_data,
    )])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "TTL=2 packet");
    let fs = phy1.recv();
    assert_eq!(fs.len(), 1, "TTL=2 packet should be forwarded");

    let fwd = Ipv4Packet::new(&fs[0].payload).unwrap();
    assert_eq!(fwd.get_ttl(), 1);
    assert_eq!(fwd.get_checksum(), pnet::packet::ipv4::checksum(&fwd));

    Ok(())
}

#[test]
fn ipv6_ttl1_dropped() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("fd00:3::", 64, 3, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = router_forward_entry(3, "fe80::3", 1);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );
    let (key_buf, param_buf) =
        resolver6_entry("fe80::3", [30, 31, 32, 33, 34, 35]);
    pipeline.add_ingress_resolver_resolver_v6_entry(
        "rewrite_dst",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // An IPv6 packet with hop_limit=1 sent toward fd00:3::/64, which routes out
    // of port 1. The router only enforces hop_limit on nonzero egress ports,
    // meaning that the drop needs a route away from port 0.
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 40 + payload.len()];

    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:2::1".parse().unwrap());
    ip.set_destination("fd00:3::99".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(1);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;
    phy0.send(&[TxFrame::new(
        phy1.mac,
        ETHERTYPE_IPV6,
        &sentinel_v6_to("fd00:3::1"),
    )])?;
    let leaked_pkts = recv_until_sentinel(&phy1, "sentinel");
    assert!(
        leaked_pkts.is_empty(),
        "hop_limit=1 packet should be dropped, only sentinel arrives"
    );

    Ok(())
}

#[test]
fn ipv6_ttl2_forwarded() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = router_idx_entry("fd00:3::", 64, 3, 1);
    pipeline
        .add_ingress_router_v6_idx_rtr_entry("index", &key_buf, &param_buf, 0);
    let (key_buf, param_buf) = router_forward_entry(3, "fe80::3", 1);
    pipeline.add_ingress_router_v6_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );
    let (key_buf, param_buf) =
        resolver6_entry("fe80::3", [30, 31, 32, 33, 34, 35]);
    pipeline.add_ingress_resolver_resolver_v6_entry(
        "rewrite_dst",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 40 + payload.len()];

    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source("fd00:2::1".parse().unwrap());
    ip.set_destination("fd00:3::99".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(2);
    ip.set_payload(&payload);

    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "hop_limit=2 packet");
    let fs = phy1.recv();
    assert_eq!(fs.len(), 1, "hop_limit=2 packet should be forwarded");

    let fwd = Ipv6Packet::new(&fs[0].payload).unwrap();
    assert_eq!(fwd.get_hop_limit(), 1);

    Ok(())
}

#[test]
fn ipv6_hop_limit0_routed_to_scrimlet_dropped() -> Result<(), anyhow::Error> {
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
    ip.set_source("fd00:2::1".parse().unwrap());
    ip.set_destination("fd00:1::99".parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(0);
    ip.set_payload(&payload);

    phy1.send(&[TxFrame::new(
        l2_dst(phy0.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;
    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV6, &sentinel_v6())])?;
    let leaked_pkts = recv_until_sentinel(&phy0, "sentinel");
    assert!(
        leaked_pkts.is_empty(),
        "hop_limit=0 packet routed to port 0 should be dropped"
    );

    Ok(())
}

#[test]
fn ipv6_hop_limit0_local_to_scrimlet() -> Result<(), anyhow::Error> {
    let probe = v6_probe("fd00:2::1", "fd00:99::1", 0);
    assert_v6_to_scrimlet(&probe, "local hop_limit=0 packet")
}

#[test]
fn nat_v4_ttl0_dropped() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let payload = [0u8; 8];
    let mut udp_data: Vec<u8> = vec![0; 8 + payload.len()];
    let mut udp = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp.set_source(100);
    udp.set_destination(1500);
    udp.set_length(8 + payload.len() as u16);
    udp.set_payload(&payload);

    let mut ip_data: Vec<u8> = vec![0; 20 + udp_data.len()];
    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source("8.8.8.8".parse().unwrap());
    ip.set_destination("1.2.3.4".parse().unwrap());
    ip.set_total_length(20 + udp_data.len() as u16);
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_ttl(0);
    ip.set_payload(&udp_data);

    phy1.send(&[TxFrame::new(
        l2_dst(phy0.mac, ETHERTYPE_IPV4, &ip_data),
        ETHERTYPE_IPV4,
        &ip_data,
    )])?;
    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV6, &sentinel_v6())])?;
    let leaked_pkts = recv_until_sentinel(&phy0, "sentinel");
    assert!(
        leaked_pkts.is_empty(),
        "TTL=0 packet should not be NAT-encapsulated toward the sled"
    );

    Ok(())
}

fn mcast_ttl_pipeline() -> main_pipeline {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mac = [0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a];

    let (key_buf, param_buf) =
        nat_mcast_v4_untagged_entry("238.1.1.1", UNDERLAY_MCAST_DST, 77, mac);
    pipeline.add_ingress_nat_nat_v4_mcast_untagged_entry(
        "forward_to_sled",
        &key_buf,
        &param_buf,
        0,
    );
    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    for group in ["ff0e::1", "ff01::1"] {
        let (key_buf, param_buf) =
            nat_mcast_v6_untagged_entry(group, UNDERLAY_MCAST_DST, 77, mac);
        pipeline.add_ingress_nat_nat_v6_mcast_untagged_entry(
            "forward_to_sled",
            &key_buf,
            &param_buf,
            0,
        );
        let (key_buf, param_buf) =
            mcast_source_filter_v6_entry("fd00::", 16, group);
        pipeline.add_ingress_mcast_mcast_source_filter_v6_entry(
            "allow_source",
            &key_buf,
            &param_buf,
            0,
        );
    }

    let (key_buf, param_buf) =
        mcast_repl_v6_entry(UNDERLAY_MCAST_DST, &[], &[1], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    pipeline
}

fn mcast_v4_probe(dst: &str, ttl: u8) -> Vec<u8> {
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 20 + payload.len()];
    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source("10.0.0.1".parse().unwrap());
    ip.set_destination(dst.parse().unwrap());
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_total_length(20 + payload.len() as u16);
    ip.set_ttl(ttl);
    ip.set_payload(&payload);
    ip_data
}

fn mcast_v6_probe(dst: &str, hop_limit: u8) -> Vec<u8> {
    v6_probe("fd00:1::1", dst, hop_limit)
}

fn v6_probe(src: &str, dst: &str, hop_limit: u8) -> Vec<u8> {
    let payload = [0u8; 8];
    let mut ip_data: Vec<u8> = vec![0; 40 + payload.len()];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source(src.parse().unwrap());
    ip.set_destination(dst.parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(hop_limit);
    ip.set_payload(&payload);
    ip_data
}

fn mcast_ttl_packet_copies(
    ethertype: u16,
    probe: &[u8],
) -> Result<usize, anyhow::Error> {
    let mut npu = SoftNpu::new(2, mcast_ttl_pipeline(), false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ethertype, probe),
        ethertype,
        probe,
    )])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    let copies = recv_until_sentinel(&phy1, "sentinel").len();
    assert_eq!(phy0.recv_buffer_len(), 0, "multicast should not reflect");

    Ok(copies)
}

#[test]
fn ipv4_mcast_ttl2_forwarded() -> Result<(), anyhow::Error> {
    let probe = mcast_v4_probe("238.1.1.1", 2);
    let copies = mcast_ttl_packet_copies(ETHERTYPE_IPV4, &probe)?;
    assert_eq!(copies, 1, "IPv4 mcast TTL=2 should replicate to port 1");
    Ok(())
}

#[test]
fn ipv4_mcast_ttl1_rejected() -> Result<(), anyhow::Error> {
    let probe = mcast_v4_probe("238.1.1.1", 1);
    let copies = mcast_ttl_packet_copies(ETHERTYPE_IPV4, &probe)?;
    assert_eq!(copies, 0, "IPv4 mcast TTL=1 should be rejected");
    Ok(())
}

#[test]
fn ipv4_mcast_ttl0_rejected() -> Result<(), anyhow::Error> {
    let probe = mcast_v4_probe("238.1.1.1", 0);
    let copies = mcast_ttl_packet_copies(ETHERTYPE_IPV4, &probe)?;
    assert_eq!(copies, 0, "IPv4 mcast TTL=0 should be rejected");
    Ok(())
}

#[test]
fn ipv6_mcast_hop_limit2_forwarded() -> Result<(), anyhow::Error> {
    let probe = mcast_v6_probe("ff0e::1", 2);
    let copies = mcast_ttl_packet_copies(ETHERTYPE_IPV6, &probe)?;
    assert_eq!(
        copies, 1,
        "IPv6 mcast hop_limit=2 should replicate to port 1"
    );
    Ok(())
}

#[test]
fn ipv6_mcast_hop_limit1_rejected() -> Result<(), anyhow::Error> {
    let probe = mcast_v6_probe("ff0e::1", 1);
    let copies = mcast_ttl_packet_copies(ETHERTYPE_IPV6, &probe)?;
    assert_eq!(copies, 0, "IPv6 mcast hop_limit=1 should be rejected");
    Ok(())
}

#[test]
fn ipv6_mcast_hop_limit0_rejected() -> Result<(), anyhow::Error> {
    let probe = mcast_v6_probe("ff0e::1", 0);
    let copies = mcast_ttl_packet_copies(ETHERTYPE_IPV6, &probe)?;
    assert_eq!(copies, 0, "IPv6 mcast hop_limit=0 should be rejected");
    Ok(())
}

#[test]
fn ipv6_mcast_ff01_rejected() -> Result<(), anyhow::Error> {
    let probe = mcast_v6_probe("ff01::1", 64);
    let copies = mcast_ttl_packet_copies(ETHERTYPE_IPV6, &probe)?;
    assert_eq!(
        copies, 0,
        "ff01:: should be rejected regardless of hop_limit"
    );
    Ok(())
}

// Link-local multicast with hop_limit=1 reaches the scrimlet on port 0,
// wrapped in the sidecar header (ethertype 0x0901).
#[test]
fn ipv6_mcast_ff02_to_scrimlet() -> Result<(), anyhow::Error> {
    // A link-local destination permits hop_limit=1.
    let probe = mcast_v6_probe("ff02::1", 1);
    assert_v6_to_scrimlet(&probe, "ff02:: packet")
}

#[test]
fn ipv6_mcast_ff02_hop_limit_zero_to_scrimlet() -> Result<(), anyhow::Error> {
    let probe = mcast_v6_probe("ff02::1", 0);
    assert_v6_to_scrimlet(&probe, "ff02:: packet with hop_limit=0")
}

fn assert_v6_to_scrimlet(
    probe: &[u8],
    what: &str,
) -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // Send from port 1 so scrimlet (port 0) can receive it.
    phy1.send(&[TxFrame::new(
        l2_dst(phy0.mac, ETHERTYPE_IPV6, probe),
        ETHERTYPE_IPV6,
        probe,
    )])?;

    wait_for(
        || phy0.recv_buffer_len() > 0,
        &format!("scrimlet should receive {what}"),
    );
    let fs = phy0.recv();

    // fwd_to_scrimlet sets ethernet.ether_type = 0x0901 (sidecar header).
    assert_eq!(
        fs[0].ethertype, ETHERTYPE_SIDECAR,
        "{what} should arrive with sidecar header ethertype"
    );

    Ok(())
}

#[test]
fn ipv6_mcast_ff12_not_link_local() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let probe = mcast_v6_probe("ff12::1", 1);
    phy1.send(&[TxFrame::new(
        l2_dst(phy0.mac, ETHERTYPE_IPV6, &probe),
        ETHERTYPE_IPV6,
        &probe,
    )])?;
    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV6, &sentinel_v6())])?;

    let leaked_pkts = recv_until_sentinel(&phy0, "sentinel");
    assert!(
        leaked_pkts.is_empty(),
        "ff12:: with hop_limit 1 must not reach the scrimlet"
    );
    Ok(())
}

// Prefix `l3` with the 24-byte sidecar header that the scrimlet sends:
// sc_ingress and sc_egress (big-endian) both carry `egress`, and
// sc_ether_type carries the inner L3 ethertype.
fn sidecar_wrap(egress: u16, ethertype: u16, l3: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; SIDECAR_HDR_LEN];
    frame[2..4].copy_from_slice(&egress.to_be_bytes());
    frame[4..6].copy_from_slice(&egress.to_be_bytes());
    frame[6..8].copy_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(l3);
    frame
}

// Send `probe` from the scrimlet side (port 0) toward port 1 and collect what
// exits port 1.
//
// No replication group or NAT entry is installed: ingress returns early through
// fwd_from_scrimlet, which forwards out sc_egress without looking at the
// multicast tables.
fn scrimlet_mcast_copies(
    ethertype: u16,
    probe: &[u8],
) -> Result<Vec<OwnedFrame>, anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let mut rewrite_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    rewrite_mac.reverse();
    pipeline.add_egress_mcast_src_mac_entry(
        "rewrite_src_mac",
        &1u16.to_le_bytes(),
        &rewrite_mac,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let frame = sidecar_wrap(1, ethertype, probe);
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_SIDECAR, &frame)])?;

    wait_for(
        || phy1.recv_buffer_len() > 0,
        "scrimlet multicast on port 1",
    );
    let frames = phy1.recv();
    for f in &frames {
        assert_eq!(f.src, phy0.mac, "scrimlet src MAC not rewritten");
        assert_eq!(f.dst, phy1.mac, "scrimlet dst MAC not rewritten");
    }
    Ok(frames)
}

// The scrimlet's own TTL-1 multicast (e.g., IGMP reports) is a
// transmission vs being a forwarding hop. The packet leaves unchanged, while
// the same packet from a front port is dropped.
#[test]
fn scrimlet_ipv4_mcast_ttl1_forwarded() -> Result<(), anyhow::Error> {
    let probe = mcast_v4_probe("238.1.1.1", 1);
    let fs = scrimlet_mcast_copies(ETHERTYPE_IPV4, &probe)?;
    assert_eq!(fs.len(), 1, "one copy out the sidecar egress port");
    assert_eq!(fs[0].ethertype, ETHERTYPE_IPV4, "sidecar header stripped");
    let ip = Ipv4Packet::new(&fs[0].payload).unwrap();
    assert_eq!(ip.get_ttl(), 1, "scrimlet transmission keeps its TTL");
    Ok(())
}

// IPv6 counterpart of the above.
//
// The group is ff0e because the parser already admits link-local multicast
// at hop_limit 1 and should not exercise the exemption.
#[test]
fn scrimlet_ipv6_mcast_hop_limit1_forwarded() -> Result<(), anyhow::Error> {
    let probe = mcast_v6_probe("ff0e::1", 1);
    let fs = scrimlet_mcast_copies(ETHERTYPE_IPV6, &probe)?;
    assert_eq!(fs.len(), 1, "one copy out the sidecar egress port");
    assert_eq!(fs[0].ethertype, ETHERTYPE_IPV6, "sidecar header stripped");
    let ip = Ipv6Packet::new(&fs[0].payload).unwrap();
    assert_eq!(ip.get_hop_limit(), 1, "scrimlet transmission keeps its hop");
    Ok(())
}

// Assert a received frame payload is a geneve-over-IPv6 packet encapsulated
// toward `target` carrying `vni`, i.e. the end-user multicast packet was
// NAT-encapsulated to its underlay group.
fn assert_nat_encap(payload: &[u8], target: &str, vni: u32) {
    let ip = Ipv6Packet::new(payload).expect("outer IPv6 header");
    assert_eq!(
        ip.get_destination(),
        target.parse::<Ipv6Addr>().unwrap(),
        "encapsulated toward the wrong underlay target",
    );
    let udp = UdpPacket::new(ip.payload()).expect("outer UDP header");
    assert_eq!(udp.get_source(), GENEVE_UDP_PORT);
    assert_eq!(udp.get_destination(), GENEVE_UDP_PORT);
    let geneve = GenevePacket::new(udp.payload()).expect("geneve header");
    assert_eq!(geneve.get_protocol_type(), GENEVE_PROTO_ETH);
    assert_eq!(geneve.get_vni(), vni, "Received wrong geneve VNI");

    assert_eq!(
        ip.get_source(),
        "fd00:99::1".parse::<Ipv6Addr>().unwrap(),
        "outer IPv6 source is the boundary services address"
    );
    assert_eq!(ip.get_traffic_class(), 0, "outer traffic class zeroed");
    assert_eq!(ip.get_flow_label(), 0, "outer flow label zeroed");
    let opts_len = 4 * geneve.get_options_len() as usize;
    let inner_eth = EthernetPacket::new(&geneve.payload()[opts_len..])
        .expect("inner ethernet header");
    assert_eq!(
        inner_eth.get_source(),
        MacAddr::zero(),
        "inner ethernet source zeroed"
    );
}

fn assert_mcast_nat_encap(
    install: impl FnOnce(&mut main_pipeline),
    ethertype: u16,
    frame: &[u8],
    vni: u32,
) -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);
    install(&mut pipeline);

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    npu.run();

    phy1.send(&[TxFrame::new(
        l2_dst(phy0.mac, ethertype, frame),
        ethertype,
        frame,
    )])?;

    wait_for(|| phy0.recv_buffer_len() > 0, "NAT-encapped mcast packet");
    let fs = phy0.recv();
    assert_nat_encap(&fs[0].payload, "fd00:1::1", vni);
    Ok(())
}

// An untagged IPv4 end-user multicast packet hits `nat_v4_mcast_untagged` and
// is NAT-encapsulated toward its underlay group (here, the fd00:1::/64 route
// stands in for the underlay target).
#[test]
fn mcast_nat_v4_untagged() -> Result<(), anyhow::Error> {
    let install = |p: &mut main_pipeline| {
        let (key_buf, param_buf) = nat_mcast_v4_untagged_entry(
            "224.1.1.1",
            "fd00:1::1",
            4444,
            [0x0a; 6],
        );
        p.add_ingress_nat_nat_v4_mcast_untagged_entry(
            "forward_to_sled",
            &key_buf,
            &param_buf,
            0,
        );
    };
    let l3 = ipv4_mcast_l3("10.0.0.1", "224.1.1.1");
    assert_mcast_nat_encap(install, ETHERTYPE_IPV4, &l3, 4444)
}

// A VLAN-tagged IPv4 end-user multicast packet hits `nat_v4_mcast` on the
// matching (dst, vid) key and is NAT-encapsulated.
#[test]
fn mcast_nat_v4_tagged() -> Result<(), anyhow::Error> {
    let install = |p: &mut main_pipeline| {
        let (key_buf, param_buf) =
            nat_mcast_v4_entry("224.2.2.2", 10, "fd00:1::1", 5555, [0x0a; 6]);
        p.add_ingress_nat_nat_v4_mcast_entry(
            "forward_to_sled",
            &key_buf,
            &param_buf,
            0,
        );
    };
    let l3 = ipv4_mcast_l3("10.0.0.1", "224.2.2.2");
    let frame = vlan_tagged(10, ETHERTYPE_IPV4, &l3);
    assert_mcast_nat_encap(install, ETHERTYPE_VLAN, &frame, 5555)
}

// A VLAN-tagged packet with a VLAN does not match the programmed group misses
// `nat_v4_mcast` and is not NAT-encapsulated to the wrong underlay group.
#[test]
fn mcast_nat_v4_wrong_vlan_miss() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = nat_mcast_v4_entry(
        "224.3.3.3",
        10,
        "fd00:1::1",
        5555,
        [0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a],
    );
    pipeline.add_ingress_nat_nat_v4_mcast_entry(
        "forward_to_sled",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    npu.run();

    // Group programmed on VLAN 10, packet arrives on VLAN 20.
    let l3 = ipv4_mcast_l3("10.0.0.1", "224.3.3.3");
    let frame = vlan_tagged(20, ETHERTYPE_IPV4, &l3);
    phy1.send(&[TxFrame::new(
        l2_dst(phy0.mac, ETHERTYPE_VLAN, &frame),
        ETHERTYPE_VLAN,
        &frame,
    )])?;

    // A sentinel sent from the probe's ingress port and routed to port 0
    // confirms the pipeline drained, while a second frame on port 0 would be
    // the mismatched packet NAT-encapsulated.
    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV6, &sentinel_v6())])?;
    let leaked_pkts = recv_until_sentinel(&phy0, "sentinel to drain pipeline");
    assert!(
        leaked_pkts.is_empty(),
        "wrong-VLAN multicast packet was NAT-encapsulated",
    );

    Ok(())
}

// An untagged IPv6 end-user multicast packet hits `nat_v6_mcast_untagged` and
// is NAT-encapsulated toward its underlay group.
#[test]
fn mcast_nat_v6_untagged() -> Result<(), anyhow::Error> {
    let install = |p: &mut main_pipeline| {
        let (key_buf, param_buf) = nat_mcast_v6_untagged_entry(
            "ff0e::1",
            "fd00:1::1",
            6666,
            [0x0a; 6],
        );
        p.add_ingress_nat_nat_v6_mcast_untagged_entry(
            "forward_to_sled",
            &key_buf,
            &param_buf,
            0,
        );
    };
    let l3 = ipv6_mcast_l3("fd00:2::1", "ff0e::1");
    assert_mcast_nat_encap(install, ETHERTYPE_IPV6, &l3, 6666)
}

// A VLAN-tagged IPv6 end-user multicast packet hits `nat_v6_mcast` on the
// matching (dst, vid) key and is NAT-encapsulated.
#[test]
fn mcast_nat_v6_tagged() -> Result<(), anyhow::Error> {
    let install = |p: &mut main_pipeline| {
        let (key_buf, param_buf) =
            nat_mcast_v6_entry("ff0e::2", 10, "fd00:1::1", 7000, [0x0a; 6]);
        p.add_ingress_nat_nat_v6_mcast_entry(
            "forward_to_sled",
            &key_buf,
            &param_buf,
            0,
        );
    };
    let l3 = ipv6_mcast_l3("fd00:2::1", "ff0e::2");
    let frame = vlan_tagged(10, ETHERTYPE_IPV6, &l3);
    assert_mcast_nat_encap(install, ETHERTYPE_VLAN, &frame, 7000)
}

fn install_v4_source_filter(pipeline: &mut main_pipeline) {
    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );
}

fn install_v6_source_filter(pipeline: &mut main_pipeline) {
    let (key_buf, param_buf) =
        mcast_source_filter_v6_entry("fd00::", 16, "ff0e::99");
    pipeline.add_ingress_mcast_mcast_source_filter_v6_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );
}

fn source_filter_copies(
    install: fn(&mut main_pipeline),
    probe: &[u8],
) -> Result<(Vec<OwnedFrame>, Vec<OwnedFrame>), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);
    install(&mut pipeline);

    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[1], &[2], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );
    let port2_sentinel = sentinel_route_v4(&mut pipeline, 2);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, probe),
        ETHERTYPE_IPV6,
        probe,
    )])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    phy0.send(&[TxFrame::new(
        phy2.mac,
        ETHERTYPE_IPV4,
        &sentinel_v4_to(&port2_sentinel),
    )])?;

    let port1 = recv_until_sentinel(&phy1, "port 1 sentinel");
    let port2 = recv_until_sentinel(&phy2, "port 2 sentinel");
    Ok((port1, port2))
}

// Multicast source filter allows matching (S,G) pairs to proceed
// to replication group lookup.
#[test]
fn mcast_source_filter_allows() -> Result<(), anyhow::Error> {
    // Source filter matches (10.0.0.1 in 10.0.0.0/8), replication proceeds.
    let probe =
        geneve_mcast_v4_pkt("fd00:1::1", "ff0e::1", "10.0.0.1", "238.1.1.1");
    let (port1, port2) =
        source_filter_copies(install_v4_source_filter, &probe)?;
    assert_eq!(port1.len(), 1, "port 1 mcast copy (external)");
    assert_eq!(port2.len(), 1, "port 2 mcast copy (underlay)");
    Ok(())
}

// Source filter denies traffic from outside the allowed prefix.
#[test]
fn mcast_source_filter_denies() -> Result<(), anyhow::Error> {
    // Inner src 192.168.0.1 is outside the allowed 10.0.0.0/8 prefix.
    // Source filter should deny, no replication.
    let probe =
        geneve_mcast_v4_pkt("fd00:1::1", "ff0e::1", "192.168.0.1", "238.1.1.1");
    let (port1, port2) =
        source_filter_copies(install_v4_source_filter, &probe)?;
    assert!(
        port1.is_empty(),
        "port 1 should not receive mcast copy when source filter denies"
    );
    assert!(
        port2.is_empty(),
        "port 2 should not receive mcast copy when source filter denies"
    );
    Ok(())
}

// When hdr.oxg_mcast.mcast_tag == 0 (External), the underlay bitmap is
// suppressed and the packet is decapsulated in ingress. Only external bitmap
// ports receive copies, carrying the inner IPv4 packet.
#[test]
fn mcast_repl_suppresses_underlay() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let inner_mcast_dst = "238.1.1.1";

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, inner_mcast_dst);
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[1], &[2], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let port2_sentinel = sentinel_route_v4(&mut pipeline, 2);

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
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    // External ports (port 1) should get a copy and underlay (port 2)
    // suppressed.
    wait_for(
        || phy1.recv_buffer_len() > 0,
        "port 1 mcast copy (external)",
    );

    let fs = phy1.recv();
    let f = &fs[0];
    assert_eq!(f.ethertype, ETHERTYPE_IPV4, "external copy decapsulated");
    let inner_ip = Ipv4Packet::new(&f.payload).unwrap();
    assert_eq!(
        inner_ip.get_destination(),
        inner_mcast_dst.parse::<Ipv4Addr>().unwrap(),
        "inner IPv4 dst preserved"
    );
    assert_eq!(inner_ip.get_ttl(), 63, "inner TTL decremented by decap");

    phy0.send(&[TxFrame::new(
        phy2.mac,
        ETHERTYPE_IPV4,
        &sentinel_v4_to(&port2_sentinel),
    )])?;
    let port2_leaked_pkts = recv_until_sentinel(&phy2, "port 2 sentinel");
    assert!(
        port2_leaked_pkts.is_empty(),
        "port 2 should not receive copy when underlay suppressed"
    );

    Ok(())
}

// When hdr.oxg_mcast.mcast_tag == 1 (Underlay), the external bitmap is
// suppressed. Only underlay bitmap ports receive copies.
#[test]
fn mcast_repl_suppresses_external() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let inner_mcast_dst = "238.1.1.1";

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, inner_mcast_dst);
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[1], &[2], 1);
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

    // hdr.oxg_mcast.mcast_tag == 1 (Underlay) -> suppress external bitmap.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        inner_mcast_dst,
        Some(MCAST_TAG_UNDERLAY),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    // Underlay ports (port 2) should get a copy; external (port 1) suppressed.
    wait_for(
        || phy2.recv_buffer_len() > 0,
        "port 2 mcast copy (underlay)",
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    let port1_leaked_pkts = recv_until_sentinel(&phy1, "port 1 sentinel");
    assert!(
        port1_leaked_pkts.is_empty(),
        "port 1 should not receive copy when external suppressed"
    );

    Ok(())
}

#[test]
fn mcast_strips_ingress_vlan_before_repl() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[1], &[2], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy2 = npu.phy(2);

    npu.run();

    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY),
    );
    let frame = vlan_tagged(10, ETHERTYPE_IPV6, &ip_data);
    phy0.send(&[TxFrame::new(
        l2_dst(phy2.mac, ETHERTYPE_VLAN, &frame),
        ETHERTYPE_VLAN,
        &frame,
    )])?;

    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 underlay copy");
    let fs = phy2.recv();
    let f = &fs[0];
    assert_eq!(f.vid, None, "ingress VLAN tag stripped");
    assert_eq!(
        f.ethertype, ETHERTYPE_IPV6,
        "underlay copy stays encapsulated"
    );
    let ip = Ipv6Packet::new(&f.payload).unwrap();
    let udp = UdpPacket::new(ip.payload()).unwrap();
    assert_eq!(udp.get_destination(), GENEVE_UDP_PORT, "geneve intact");

    Ok(())
}

// Replication group ff0e::1 with inner source filter
// (10.0.0.0/8, 238.1.1.1).
fn mcast_ff0e_pipeline(external: &[u16], underlay: &[u16]) -> main_pipeline {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_repl_v6_entry("ff0e::1", external, underlay, 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    pipeline
}

// Multicast where the destination MAC does not map from the IPv6 destination
// (RFC 2464 §7) is dropped in ingress, matching dendrite's Filter control.
#[test]
fn mcast_drops_bad_dst_mac_v6() -> Result<(), anyhow::Error> {
    let pipeline = mcast_ff0e_pipeline(&[1], &[]);
    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV6, &ip_data)])?;
    phy0.send(&[TxFrame::new(
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x02],
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;

    let leaked_pkts = recv_until_sentinel(&phy1, "sentinel");
    assert!(leaked_pkts.is_empty(), "only the sentinel arrives");

    Ok(())
}

// IPv4 multicast where the destination MAC does not map from the IPv4
// destination (RFC 1112 §6.4) is dropped before NAT ingress.
#[test]
fn mcast_nat_v4_drops_bad_dst_mac() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = nat_mcast_v4_untagged_entry(
        "224.1.1.1",
        "fd00:1::1",
        4444,
        [0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a],
    );
    pipeline.add_ingress_nat_nat_v4_mcast_untagged_entry(
        "forward_to_sled",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    npu.run();

    let ip_data = ipv4_mcast_l3("10.0.0.1", "224.1.1.1");
    for dst in [
        phy0.mac,
        [0x01, 0x00, 0x5e, 0x01, 0x01, 0x02],
        [0x01, 0x00, 0x5e, 0x81, 0x01, 0x01],
    ] {
        phy1.send(&[TxFrame::new(dst, ETHERTYPE_IPV4, &ip_data)])?;
    }
    phy1.send(&[TxFrame::new(phy0.mac, ETHERTYPE_IPV6, &sentinel_v6())])?;

    let leaked_pkts = recv_until_sentinel(&phy0, "sentinel");
    assert!(leaked_pkts.is_empty(), "only the sentinel arrives");

    Ok(())
}

fn assert_packet_leaks(
    inner_dst: &str,
    inner_proto: Option<u8>,
) -> Result<(), anyhow::Error> {
    let mut pipeline = mcast_ff0e_pipeline(&[1], &[2]);
    let port2_sentinel = sentinel_route_v4(&mut pipeline, 2);
    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let mut ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        inner_dst,
        Some(MCAST_TAG_EXTERNAL),
    );
    if let Some(proto) = inner_proto {
        ip_data[INNER_IPV4_PROTO_OFFSET_MCAST] = proto;
    }
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    phy0.send(&[TxFrame::new(
        phy2.mac,
        ETHERTYPE_IPV4,
        &sentinel_v4_to(&port2_sentinel),
    )])?;

    let port1_leaked_pkts = recv_until_sentinel(&phy1, "port 1 sentinel");
    assert!(port1_leaked_pkts.is_empty(), "only the sentinel arrives");
    let port2_leaked_pkts = recv_until_sentinel(&phy2, "port 2 sentinel");
    assert!(port2_leaked_pkts.is_empty(), "underlay suppressed");
    Ok(())
}

// A tag-0 (External) packet where the inner destination is unicast is dropped
// instead of being decapsulated onto external ports, as dendrite's
// MulticastRouter4/6 misses on the inner unicast address.
#[test]
fn mcast_external_decap_drops_unicast_inner() -> Result<(), anyhow::Error> {
    assert_packet_leaks("10.1.1.1", None)
}

// A tag-0 (External) packet where the inner L4 is not TCP, UDP or ICMP is
// dropped, matching dendrite's nat_egress default action.
#[test]
fn mcast_external_decap_drops_non_l4_inner() -> Result<(), anyhow::Error> {
    assert_packet_leaks("238.1.1.1", Some(2))
}

// IPv6 inner multicast source filtering: allow path.
// Uses inner IPv6 dst ff0e::99 (full-byte slice [127:120] == 0xff, no
// x4c workaround needed).
#[test]
fn mcast_source_filter_v6_inner_allows() -> Result<(), anyhow::Error> {
    let probe = geneve_mcast_v6_inner_pkt(
        "fd00:1::1",
        "ff0e::1",
        "fd00::1",
        "ff0e::99",
    );
    let (port1, port2) =
        source_filter_copies(install_v6_source_filter, &probe)?;
    assert_eq!(port1.len(), 1, "port 1 mcast copy (external)");
    assert_eq!(port2.len(), 1, "port 2 mcast copy (underlay)");
    Ok(())
}

// IPv6 inner source filter deny path.
#[test]
fn mcast_source_filter_v6_inner_denies() -> Result<(), anyhow::Error> {
    // Inner src fe80::1 is outside the allowed fd00::/16.
    let probe = geneve_mcast_v6_inner_pkt(
        "fd00:1::1",
        "ff0e::1",
        "fe80::1",
        "ff0e::99",
    );
    let (port1, port2) =
        source_filter_copies(install_v6_source_filter, &probe)?;
    assert!(
        port1.is_empty(),
        "port 1 should not receive copy when v6 source filter denies"
    );
    assert!(
        port2.is_empty(),
        "port 2 should not receive copy when v6 source filter denies"
    );
    Ok(())
}

// Multicast that misses ingress NAT remains unencapsulated and is dropped
// (not replicated), matching dendrite's drop_mcastv4_no_group and
// drop_mcastv6_no_group semantics.
//
// The IPv6 case installs a replication entry for its own destination,
// which means a replicated copy would show up on port 1.
fn nat_miss_mcast_copies(
    ethertype: u16,
    probe: &[u8],
) -> Result<usize, anyhow::Error> {
    let mut pipeline = main_pipeline::new(2);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[1], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(2, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ethertype, probe),
        ethertype,
        probe,
    )])?;
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;

    Ok(recv_until_sentinel(&phy1, "sentinel").len())
}

#[test]
fn mcast_nat_miss_v4_dropped() -> Result<(), anyhow::Error> {
    let probe = mcast_v4_probe("238.1.1.1", 64);
    let copies = nat_miss_mcast_copies(ETHERTYPE_IPV4, &probe)?;
    assert_eq!(copies, 0, "IPv4 multicast NAT miss must not be replicated");
    Ok(())
}

#[test]
fn mcast_nat_miss_v6_dropped() -> Result<(), anyhow::Error> {
    let probe = mcast_v6_probe("ff0e::1", 64);
    let copies = nat_miss_mcast_copies(ETHERTYPE_IPV6, &probe)?;
    assert_eq!(copies, 0, "IPv6 multicast NAT miss must not be replicated");
    Ok(())
}

// Non-multicast inner destination in geneve bypasses source filtering.
#[test]
fn mcast_non_mcast_inner_bypasses_source_filter() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    // No source filter entries. Non-mcast inner should bypass.
    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[1], &[2], 1);
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

    // Inner dst 10.0.0.2 is unicast / not multicast. Source filter bypassed.
    let ip_data =
        geneve_mcast_v4_pkt("fd00:1::1", "ff0e::1", "10.0.0.1", "10.0.0.2");
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

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
// with its geneve options unchanged and skips decap even when a decap table
// entry exists for the egress port.
//
// Egress decap requires oxg_mcast.isValid() and mcast_tag == 2, while
// ingress decap requires mcast_tag == 0.
#[test]
fn mcast_egress_untagged_passthrough() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_repl_v6_entry(UNDERLAY_MCAST_DST, &[1], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Decap entry for port 1 (by its logical number), but the packet has no
    // mcast tag.
    let (key_buf, param_buf) = tbl_decap_ports_entry(1, &[logical_port(1)]);
    pipeline.add_egress_tbl_decap_ports_entry(
        "set_decap_ports",
        &key_buf,
        &param_buf,
        0,
    );
    map_asic_ids(&mut pipeline, &[1, 2]);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let ip_data = geneve_mcast_v4_pkt(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

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

    // Dst MAC derived from outer IPv6 dst (ff04::1).
    // RFC 2464: 33:33 + lower 32 bits = 33:33:00:00:00:01.
    assert_eq!(
        f.dst,
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
        "encapsulated copy dst MAC from outer IPv6 (ff04::1)"
    );

    Ok(())
}

// Egress preserves an existing mcast option. The option count and tag
// value pass through unchanged (read-only egress model).
#[test]
fn mcast_egress_preserves_existing_mcast_tag() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[], &[1], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    // Existing mcast option with mcast_tag=1 (Underlay, suppresses external).
    // Tag preserved through pipeline (read-only egress model). Tag 0 would
    // decapsulate in ingress, leaving no option to inspect.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

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
    assert_eq!(mcast.get_mcast_tag(), 1, "tag preserved through pipeline");

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

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_repl_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Decap entry for port 2, by its logical number.
    let (key_buf, param_buf) = tbl_decap_ports_entry(1, &[logical_port(2)]);
    pipeline.add_egress_tbl_decap_ports_entry(
        "set_decap_ports",
        &key_buf,
        &param_buf,
        0,
    );
    map_asic_ids(&mut pipeline, &[1, 2]);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Send with mcast_tag=2 (Both) so egress decap applies.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

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
    assert_eq!(
        ip1.get_hop_limit(),
        63,
        "outer hop_limit decremented on the encapsulated copy"
    );
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

#[test]
fn mcast_egress_decap_per_group_rid() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let group_a = UNDERLAY_MCAST_DST;
    let group_b = "ff04::2";
    for (group, decap_port, rid) in [(group_a, 2, 1), (group_b, 1, 2)] {
        let (key_buf, param_buf) =
            mcast_repl_v6_entry(group, &[1, 2], &[], rid);
        pipeline.add_ingress_mcast_mcast_replication_v6_entry(
            "set_port_bitmap",
            &key_buf,
            &param_buf,
            0,
        );

        let (key_buf, param_buf) =
            tbl_decap_ports_entry(rid, &[logical_port(decap_port)]);
        pipeline.add_egress_tbl_decap_ports_entry(
            "set_decap_ports",
            &key_buf,
            &param_buf,
            0,
        );
    }
    map_asic_ids(&mut pipeline, &[1, 2]);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    for (group, encap_phy, decap_phy) in
        [(group_a, &phy1, &phy2), (group_b, &phy2, &phy1)]
    {
        let ip_data = geneve_mcast_v4_pkt_repl(
            "fd00:1::1",
            group,
            "10.0.0.1",
            "238.1.1.1",
            Some(MCAST_TAG_UNDERLAY_EXTERNAL),
        );
        phy0.send(&[TxFrame::new(
            l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
            ETHERTYPE_IPV6,
            &ip_data,
        )])?;

        wait_for(|| encap_phy.recv_buffer_len() > 0, "encapped copy");
        wait_for(|| decap_phy.recv_buffer_len() > 0, "decapped copy");

        let encapped = encap_phy.recv();
        assert_eq!(
            encapped[0].ethertype, ETHERTYPE_IPV6,
            "{group}: copy outside the rid's decap set keeps encap"
        );

        let decapped = decap_phy.recv();
        assert_eq!(
            decapped[0].ethertype, ETHERTYPE_IPV4,
            "{group}: copy in the rid's decap set is decapped"
        );
    }

    Ok(())
}

#[test]
fn mcast_egress_decap_unmapped_port_keeps_encap() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_repl_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        tbl_decap_ports_entry(1, &[logical_port(1), logical_port(2)]);
    pipeline.add_egress_tbl_decap_ports_entry(
        "set_decap_ports",
        &key_buf,
        &param_buf,
        0,
    );
    map_asic_ids(&mut pipeline, &[1]);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 decapped copy");
    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 encapped copy");

    let fs1 = phy1.recv();
    assert_eq!(fs1[0].ethertype, ETHERTYPE_IPV4, "mapped port 1 decapped");

    let fs2 = phy2.recv();
    assert_eq!(
        fs2[0].ethertype, ETHERTYPE_IPV6,
        "unmapped port 2 keeps encap"
    );

    Ok(())
}

fn egress_decap_pipeline() -> main_pipeline {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_repl_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Port 1 in external only (keeps encap, no decap entry).
    // Port 2 in external (decap entry below).
    let (key_buf, param_buf) = tbl_decap_ports_entry(1, &[logical_port(2)]);
    pipeline.add_egress_tbl_decap_ports_entry(
        "set_decap_ports",
        &key_buf,
        &param_buf,
        0,
    );
    map_asic_ids(&mut pipeline, &[1, 2]);

    pipeline
}

fn egress_decap_inner_ttl_copies(
    ttl: u8,
) -> Result<(usize, usize), anyhow::Error> {
    let mut pipeline = egress_decap_pipeline();
    let port2_sentinel = sentinel_route_v4(&mut pipeline, 2);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // The mcast option adds 8 bytes, shifting the inner TTL offset.
    let mut ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    ip_data[INNER_IPV4_TTL_OFFSET_MCAST] = ttl;
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    // Port 1 keeps its copy encapsulated. Each egress is drained through
    // its own sentinel.
    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 encapped copy");
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    phy0.send(&[TxFrame::new(
        phy2.mac,
        ETHERTYPE_IPV4,
        &sentinel_v4_to(&port2_sentinel),
    )])?;
    let port1 = recv_until_sentinel(&phy1, "port 1 sentinel").len();
    let port2 = recv_until_sentinel(&phy2, "port 2 sentinel").len();

    Ok((port1, port2))
}

// Inner TTL=1 must be dropped before the decap decrement.
#[test]
fn mcast_egress_decap_drops_inner_ttl1() -> Result<(), anyhow::Error> {
    let (port1, port2) = egress_decap_inner_ttl_copies(1)?;
    assert_eq!(port1, 1, "port 1 receives one encapped copy");
    assert_eq!(
        port2, 0,
        "decap must drop inner packet with TTL=1 (would become 0)"
    );
    Ok(())
}

// Inner TTL=0 must be dropped before it can wrap to 255.
#[test]
fn mcast_egress_decap_drops_inner_ttl0() -> Result<(), anyhow::Error> {
    let (port1, port2) = egress_decap_inner_ttl_copies(0)?;
    assert_eq!(port1, 1, "port 1 receives one encapped copy");
    assert_eq!(
        port2, 0,
        "decap must drop inner packet with TTL=0 (would wrap to 255)"
    );
    Ok(())
}

fn external_decap_copies(
    decap_vlan: Option<u16>,
    mapped: &[u16],
) -> Result<Vec<OwnedFrame>, anyhow::Error> {
    let mut pipeline = mcast_ff0e_pipeline(&[1, 2], &[]);
    let decap_ports = [logical_port(1), logical_port(2)];
    let (key_buf, param_buf) = match decap_vlan {
        Some(vid) => tbl_decap_ports_vlan_entry(1, &decap_ports, vid),
        None => tbl_decap_ports_entry(1, &decap_ports),
    };
    let action = match decap_vlan {
        Some(_) => "set_decap_ports_and_vlan",
        None => "set_decap_ports",
    };
    pipeline.add_egress_tbl_decap_ports_entry(action, &key_buf, &param_buf, 0);
    map_asic_ids(&mut pipeline, mapped);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 decapped copy");
    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 decapped copy");
    let mut frames = phy1.recv();
    frames.extend(phy2.recv());
    Ok(frames)
}

#[test]
fn mcast_external_decap_applies_group_vlan() -> Result<(), anyhow::Error> {
    let frames = external_decap_copies(Some(300), &[1, 2])?;
    assert_eq!(frames.len(), 2, "one copy per external port");
    for f in &frames {
        assert_eq!(f.vid, Some(300), "tag-0 copy carries the group VLAN");
        assert_eq!(f.ethertype, ETHERTYPE_IPV4, "inner ethertype is IPv4");
        let inner_ip = Ipv4Packet::new(&f.payload).unwrap();
        assert_eq!(inner_ip.get_ttl(), 63, "inner TTL decremented");
    }
    Ok(())
}

#[test]
fn mcast_external_decap_unmapped_port_untagged() -> Result<(), anyhow::Error> {
    let frames = external_decap_copies(Some(300), &[1])?;
    assert_eq!(frames.len(), 2, "one copy per external port");
    assert_eq!(frames[0].vid, Some(300), "mapped port 1 carries the VLAN");
    assert_eq!(frames[1].vid, None, "unmapped port 2 stays untagged");
    for f in &frames {
        assert_eq!(f.ethertype, ETHERTYPE_IPV4, "inner ethertype is IPv4");
    }
    Ok(())
}

#[test]
fn mcast_external_decap_without_vlan_untagged() -> Result<(), anyhow::Error> {
    let frames = external_decap_copies(None, &[1, 2])?;
    assert_eq!(frames.len(), 2, "one copy per external port");
    for f in &frames {
        assert_eq!(f.vid, None, "no group VLAN leaves the copy untagged");
        assert_eq!(f.ethertype, ETHERTYPE_IPV4, "inner ethertype is IPv4");
        let inner_ip = Ipv4Packet::new(&f.payload).unwrap();
        assert_eq!(inner_ip.get_ttl(), 63, "inner TTL decremented");
    }
    Ok(())
}

// Ingress decap for mcast_tag == 0 (External) applies the same inner TTL
// rules as egress decap. An inner TTL of 1 is dropped, and the following
// packet arrives decapsulated with its TTL decremented.
#[test]
fn mcast_external_decap_drops_inner_ttl1() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[1], &[2], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let port2_sentinel = sentinel_route_v4(&mut pipeline, 2);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let mut expired = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_EXTERNAL),
    );
    expired[INNER_IPV4_TTL_OFFSET_MCAST] = 1;
    let live = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &expired),
        ETHERTYPE_IPV6,
        &expired,
    )])?;
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &live),
        ETHERTYPE_IPV6,
        &live,
    )])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 live copy");
    let fs = phy1.recv();
    assert_eq!(fs.len(), 1, "expired copy must be dropped");
    assert_eq!(fs[0].ethertype, ETHERTYPE_IPV4, "live copy decapsulated");
    let inner_ip = Ipv4Packet::new(&fs[0].payload).unwrap();
    assert_eq!(inner_ip.get_ttl(), 63, "live copy TTL decremented");

    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    phy0.send(&[TxFrame::new(
        phy2.mac,
        ETHERTYPE_IPV4,
        &sentinel_v4_to(&port2_sentinel),
    )])?;
    let port1_leaked_pkts = recv_until_sentinel(&phy1, "port 1 sentinel");
    assert!(port1_leaked_pkts.is_empty(), "expired copy must be dropped");
    let port2_leaked_pkts = recv_until_sentinel(&phy2, "port 2 sentinel");
    assert!(port2_leaked_pkts.is_empty(), "underlay suppressed");

    Ok(())
}

fn set_inner_ipv4_checksum(ip_data: &mut [u8], target: u16) {
    let hdr = INNER_IPV4_TTL_OFFSET_MCAST - IPV4_TTL_FIELD_OFFSET;
    for id in 0..=u16::MAX {
        let mut ip = MutableIpv4Packet::new(&mut ip_data[hdr..]).unwrap();
        ip.set_identification(id);
        let csum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        if csum == target {
            ip.set_checksum(csum);
            return;
        }
    }
    panic!("no identification yields inner checksum {target:#06x}");
}

fn assert_decap_checksum_zero_boundary(f: &OwnedFrame) {
    assert_eq!(f.ethertype, ETHERTYPE_IPV4, "copy decapsulated");
    let inner_ip = Ipv4Packet::new(&f.payload).unwrap();
    assert_eq!(inner_ip.get_ttl(), 63, "inner TTL decremented");
    assert_eq!(
        inner_ip.get_checksum(),
        pnet::packet::ipv4::checksum(&inner_ip),
        "incremental update matches a full recompute"
    );
    assert_eq!(
        inner_ip.get_checksum(),
        0x0000,
        "0xfeff before decrement yields 0x0000, not 0xffff"
    );
}

#[test]
fn mcast_external_decap_checksum_zero_boundary() -> Result<(), anyhow::Error> {
    let pipeline = mcast_ff0e_pipeline(&[1], &[]);
    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let mut ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_EXTERNAL),
    );
    set_inner_ipv4_checksum(&mut ip_data, 0xfeff);
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy1.recv_buffer_len() > 0, "port 1 decapped copy");
    let fs = phy1.recv();
    assert_decap_checksum_zero_boundary(&fs[0]);

    Ok(())
}

#[test]
fn mcast_egress_decap_checksum_zero_boundary() -> Result<(), anyhow::Error> {
    let pipeline = egress_decap_pipeline();
    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let mut ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    set_inner_ipv4_checksum(&mut ip_data, 0xfeff);
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 decapped copy");
    let fs = phy2.recv();
    assert_decap_checksum_zero_boundary(&fs[0]);

    Ok(())
}

// Egress decapsulates inner IPv6 payloads, decrementing hop_limit and
// setting ethertype to 0x86dd.
#[test]
fn mcast_egress_decap_v6_inner() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v6_entry("fd00::", 16, "ff0e::99");
    pipeline.add_ingress_mcast_mcast_source_filter_v6_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_repl_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    // Port 1 in external only.
    // Port 2 in external, triggers decap.

    // Decap entry for port 2, by its logical number.
    let (key_buf, param_buf) = tbl_decap_ports_entry(1, &[logical_port(2)]);
    pipeline.add_egress_tbl_decap_ports_entry(
        "set_decap_ports",
        &key_buf,
        &param_buf,
        0,
    );
    map_asic_ids(&mut pipeline, &[1, 2]);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // Send with mcast_tag=2 (Both) so egress decap applies.
    let eth = inner_mcast_v6_frame("fd00::1", "ff0e::99");
    let ip_data = wrap_geneve(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        &eth,
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

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

// A decap VLAN ID above 255 and the mcast_src_mac rewrite work end-to-end.
//
// Both are encoded as scadm sends them -> a little-endian VLAN ID and a
// byte-reversed MAC.
#[test]
fn mcast_egress_decap_wide_vlan_and_src_mac() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_repl_v6_entry(UNDERLAY_MCAST_DST, &[1, 2], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        tbl_decap_ports_vlan_entry(1, &[logical_port(2)], 300);
    pipeline.add_egress_tbl_decap_ports_entry(
        "set_decap_ports_and_vlan",
        &key_buf,
        &param_buf,
        0,
    );
    map_asic_ids(&mut pipeline, &[1, 2]);

    let src_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    let mut src_mac_param = src_mac;
    src_mac_param.reverse();
    pipeline.add_egress_mcast_src_mac_entry(
        "rewrite_src_mac",
        &2u16.to_le_bytes(),
        &src_mac_param,
        0,
    );

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        UNDERLAY_MCAST_DST,
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_UNDERLAY_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    wait_for(|| phy2.recv_buffer_len() > 0, "port 2 vlan decapped copy");
    let fs = phy2.recv();
    let f = &fs[0];

    assert_eq!(f.src, src_mac, "src MAC from mcast_src_mac");
    assert_eq!(f.vid, Some(300), "VLAN tag present with vid=300");
    assert_eq!(f.ethertype, ETHERTYPE_IPV4, "inner ethertype is IPv4");
    assert_eq!(
        f.dst,
        [0x01, 0x00, 0x5e, 0x01, 0x01, 0x01],
        "mcast dst MAC derived from inner IPv4"
    );
    let inner_ip = Ipv4Packet::new(&f.payload).unwrap();
    assert_eq!(inner_ip.get_ttl(), 63, "inner TTL decremented");

    Ok(())
}

// Port in the external bitmap, sent with tag=Both(2), but has no
// tbl_decap_ports entry.
//
// Geneve encapsulation remains intact.
#[test]
fn mcast_both_tag_without_decap_keeps_encap() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    let (key_buf, param_buf) =
        mcast_repl_v6_entry(UNDERLAY_MCAST_DST, &[2], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

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
    phy0.send(&[TxFrame::new(
        l2_dst(phy2.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

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

// Replication filters out the ingress port.
#[test]
fn mcast_ingress_port_suppressed() -> Result<(), anyhow::Error> {
    let mut pipeline = main_pipeline::new(3);
    pipeline_init(&mut pipeline);

    let (key_buf, param_buf) =
        mcast_source_filter_v4_entry("10.0.0.0", 8, "238.1.1.1");
    pipeline.add_ingress_mcast_mcast_source_filter_v4_entry(
        "allow_source",
        &key_buf,
        &param_buf,
        0,
    );

    // External bitmap includes port 0 (ingress) and port 1.
    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[0, 1], &[], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);

    npu.run();

    let ip_data =
        geneve_mcast_v4_pkt("fd00:1::1", "ff0e::1", "10.0.0.1", "238.1.1.1");

    // Send from port 0.
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    // The test runtime publishes egress queues in port order.
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
    let (key_buf, param_buf) = mcast_repl_v6_entry("ff0e::1", &[], &[2], 1);
    pipeline.add_ingress_mcast_mcast_replication_v6_entry(
        "set_port_bitmap",
        &key_buf,
        &param_buf,
        0,
    );

    let port2_sentinel = sentinel_route_v4(&mut pipeline, 2);

    let mut npu = SoftNpu::new(3, pipeline, false);
    let phy0 = npu.phy(0);
    let phy1 = npu.phy(1);
    let phy2 = npu.phy(2);

    npu.run();

    // mcast_tag=0 (External): suppresses underlay. External is empty. No
    // copies.
    let ip_data = geneve_mcast_v4_pkt_repl(
        "fd00:1::1",
        "ff0e::1",
        "10.0.0.1",
        "238.1.1.1",
        Some(MCAST_TAG_EXTERNAL),
    );
    phy0.send(&[TxFrame::new(
        l2_dst(phy1.mac, ETHERTYPE_IPV6, &ip_data),
        ETHERTYPE_IPV6,
        &ip_data,
    )])?;

    // Send a sentinel to each egress from the probe's ingress port.
    phy0.send(&[TxFrame::new(phy1.mac, ETHERTYPE_IPV4, &sentinel_v4())])?;
    phy0.send(&[TxFrame::new(
        phy2.mac,
        ETHERTYPE_IPV4,
        &sentinel_v4_to(&port2_sentinel),
    )])?;

    let port1_leaked_pkts = recv_until_sentinel(&phy1, "sentinel on port 1");
    assert!(
        port1_leaked_pkts.is_empty(),
        "only the sentinel reaches port 1; the suppressed mcast packet is dropped"
    );
    let port2_leaked_pkts = recv_until_sentinel(&phy2, "sentinel on port 2");
    assert!(
        port2_leaked_pkts.is_empty(),
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
fn router_forward_entry(idx: u16, gw: &str, port: u16) -> (Vec<u8>, Vec<u8>) {
    let key_buf = idx.to_le_bytes().to_vec();

    let mut param_buf = port.to_le_bytes().to_vec();

    let mut nexthop_buf = match gw.parse().unwrap() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    nexthop_buf.reverse();
    param_buf.extend_from_slice(&nexthop_buf);

    (key_buf, param_buf)
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

// `forward_to_sled(target, vni, mac)` action parameter buffer, which is shared
// by the unicast and multicast NAT tables. `target` is the underlay group the
// end-user packet is NAT-encapsulated toward.
fn forward_to_sled_param(target: &str, vni: u32, mac: [u8; 6]) -> Vec<u8> {
    let target: Ipv6Addr = target.parse().unwrap();
    let mut param = target.octets().to_vec();
    param.reverse();
    param.extend_from_slice(&vni.to_le_bytes()[..3]);
    param.extend_from_slice(&mac);
    param
}

// `nat_v4_mcast` entry, keyed on (ipv4.dst, vlan.vid).
fn nat_mcast_v4_entry(
    dst: &str,
    vid: u16,
    target: &str,
    vni: u32,
    mac: [u8; 6],
) -> (Vec<u8>, Vec<u8>) {
    let dst: Ipv4Addr = dst.parse().unwrap();
    let mut key_buf = dst.octets().to_vec();
    key_buf.reverse();
    key_buf.extend_from_slice(&vid.to_le_bytes());
    (key_buf, forward_to_sled_param(target, vni, mac))
}

// `nat_v4_mcast_untagged` entry, keyed on (ipv4.dst).
fn nat_mcast_v4_untagged_entry(
    dst: &str,
    target: &str,
    vni: u32,
    mac: [u8; 6],
) -> (Vec<u8>, Vec<u8>) {
    let dst: Ipv4Addr = dst.parse().unwrap();
    let mut key_buf = dst.octets().to_vec();
    key_buf.reverse();
    (key_buf, forward_to_sled_param(target, vni, mac))
}

// `nat_v6_mcast` entry, keyed on (ipv6.dst, vlan.vid).
fn nat_mcast_v6_entry(
    dst: &str,
    vid: u16,
    target: &str,
    vni: u32,
    mac: [u8; 6],
) -> (Vec<u8>, Vec<u8>) {
    let dst: Ipv6Addr = dst.parse().unwrap();
    let mut key_buf = dst.octets().to_vec();
    key_buf.reverse();
    key_buf.extend_from_slice(&vid.to_le_bytes());
    (key_buf, forward_to_sled_param(target, vni, mac))
}

// `nat_v6_mcast_untagged` entry, which is keyed on (ipv6.dst).
fn nat_mcast_v6_untagged_entry(
    dst: &str,
    target: &str,
    vni: u32,
    mac: [u8; 6],
) -> (Vec<u8>, Vec<u8>) {
    let dst: Ipv6Addr = dst.parse().unwrap();
    let mut key_buf = dst.octets().to_vec();
    key_buf.reverse();
    (key_buf, forward_to_sled_param(target, vni, mac))
}

// Destination MAC for a test frame.
//
// Multicast L3 destinations map to their derived group MAC (RFC 1112 §6.4,
// RFC 2464 §7), matching the ingress MAC check. Anything else uses the given
// unicast MAC.
fn l2_dst(unicast: [u8; 6], ethertype: u16, data: &[u8]) -> [u8; 6] {
    let (ethertype, l3) = if ethertype == ETHERTYPE_VLAN {
        (u16::from_be_bytes([data[2], data[3]]), &data[4..])
    } else {
        (ethertype, data)
    };

    match ethertype {
        ETHERTYPE_IPV4 if l3[16] & 0xf0 == 0xe0 => {
            [0x01, 0x00, 0x5e, l3[17] & 0x7f, l3[18], l3[19]]
        }
        ETHERTYPE_IPV6 if l3[24] == 0xff => {
            [0x33, 0x33, l3[36], l3[37], l3[38], l3[39]]
        }
        _ => unicast,
    }
}

// 802.1Q tag bytes: TCI (pcp=0, dei=0, vid) followed by the encapsulated
// ether_type, prepended to an L3 payload behind an 0x8100 ethernet frame.
fn vlan_tagged(vid: u16, inner_ethertype: u16, l3: &[u8]) -> Vec<u8> {
    debug_assert!(vid <= 0x0fff, "vid {vid} does not fit in 12 bits");
    let tci = vid & 0x0fff;
    let mut buf = Vec::with_capacity(4 + l3.len());
    buf.extend_from_slice(&tci.to_be_bytes());
    buf.extend_from_slice(&inner_ethertype.to_be_bytes());
    buf.extend_from_slice(l3);
    buf
}

// Non-geneve IPv4 multicast packet for exercising the NAT-ingress
// multicast tables. TTL defaults high enough to clear the ingress RFC 1112
// expiry check.
fn ipv4_mcast_l3(src: &str, dst: &str) -> Vec<u8> {
    let payload = [0u8; 8];
    let mut ip_data = vec![0u8; 20 + payload.len()];
    let mut ip = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_source(src.parse().unwrap());
    ip.set_destination(dst.parse().unwrap());
    ip.set_total_length(20 + payload.len() as u16);
    ip.set_next_level_protocol(IpNextHeaderProtocol::new(17));
    ip.set_ttl(64);
    ip.set_payload(&payload);
    ip_data
}

// Non-geneve IPv6 multicast packet for the NAT-ingress multicast
// tables. hop_limit clears the ingress non-link-local expiry check.
fn ipv6_mcast_l3(src: &str, dst: &str) -> Vec<u8> {
    let payload = [0u8; 8];
    let mut ip_data = vec![0u8; 40 + payload.len()];
    let mut ip = MutableIpv6Packet::new(&mut ip_data).unwrap();
    ip.set_version(6);
    ip.set_source(src.parse().unwrap());
    ip.set_destination(dst.parse().unwrap());
    ip.set_payload_length(payload.len() as u16);
    ip.set_next_header(IpNextHeaderProtocol::new(17));
    ip.set_hop_limit(64);
    ip.set_payload(&payload);
    ip_data
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
//
// Little-endian encoded, meaning bit N (value 2^N) corresponds to index N,
// matching how p4rs arithmetic (shl_le, load_le, replicate) interprets bitvec
// storage. The index is an egress port for replication bitmaps and a logical
// port number (see `logical_port`) for decap bitmaps.
//
// The bitmap is 128 bits (16 bytes).
fn port_bitmap(ports: &[u16]) -> Vec<u8> {
    let byte_len = 16;
    let mut bitmap = vec![0u8; byte_len];
    for &p in ports {
        let byte_idx = (p / 8) as usize;
        let bit_idx = p % 8;
        assert!(byte_idx < byte_len, "port {p} exceeds bitmap width");
        bitmap[byte_idx] |= 1 << bit_idx;
    }
    bitmap
}

// Multicast replication bitmap lookup for IPv6 outer destination.
//
// Key bytes are reversed to match the codegen's byte-reversed storage
// of header fields wider than 8 bits (hdr.ipv6.dst is 128 bits).
// Action has three parameters: external bitmap, underlay bitmap, and rid.
fn mcast_repl_v6_entry(
    dst: &str,
    external_ports: &[u16],
    underlay_ports: &[u16],
    rid: u16,
) -> (Vec<u8>, Vec<u8>) {
    let addr: Ipv6Addr = dst.parse().unwrap();
    let mut key_buf = addr.octets().to_vec();
    key_buf.reverse();

    let mut param_buf = port_bitmap(external_ports);
    param_buf.extend_from_slice(&port_bitmap(underlay_ports));
    param_buf.extend_from_slice(&rid.to_le_bytes());

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

    // LPM key: network order (IpAddr::from expects big-endian)
    let mut key_buf = src_addr.octets().to_vec();
    key_buf.push(src_prefix_len);
    // Exact key: reversed to match byte-reversed header storage
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

    // LPM key: network order (IpAddr::from expects big-endian)
    let mut key_buf = src_addr.octets().to_vec();
    key_buf.push(src_prefix_len);
    // Exact key: reversed to match byte-reversed header storage
    let mut dst_bytes = dst_addr.octets().to_vec();
    dst_bytes.reverse();
    key_buf.extend_from_slice(&dst_bytes);

    (key_buf, Vec::new())
}

// Decap port bitmap entry keyed on RID.
// The bitmap indicates which logical ports receive decapped traffic.
fn tbl_decap_ports_entry(rid: u16, ports: &[u16]) -> (Vec<u8>, Vec<u8>) {
    let key_buf = rid.to_le_bytes().to_vec();
    let param_buf = port_bitmap(ports);
    (key_buf, param_buf)
}

fn tbl_decap_ports_vlan_entry(
    rid: u16,
    ports: &[u16],
    vlan_id: u16,
) -> (Vec<u8>, Vec<u8>) {
    let key_buf = rid.to_le_bytes().to_vec();
    let mut param_buf = port_bitmap(ports);
    param_buf.extend_from_slice(&vlan_id.to_le_bytes());
    (key_buf, param_buf)
}

// SoftNPU egress port N (port 0 is the CPU) maps to front-panel port N - 1,
// the logical number that decap bitmaps index on ~ logical, responsible,
// practical.
fn logical_port(port: u16) -> u16 {
    port - 1
}

fn asic_id_to_port_entry(port: u16) -> (Vec<u8>, Vec<u8>) {
    let key_buf = port.to_le_bytes().to_vec();
    let param_buf = vec![u8::try_from(logical_port(port)).unwrap()];
    (key_buf, param_buf)
}

fn map_asic_ids(pipeline: &mut main_pipeline, ports: &[u16]) {
    for &port in ports {
        let (key_buf, param_buf) = asic_id_to_port_entry(port);
        pipeline.add_egress_asic_id_to_port_entry(
            "set_port_number",
            &key_buf,
            &param_buf,
            0,
        );
    }
}

// Wrap an inner ethernet frame in geneve-over-IPv6 with an Oxide
// external tag. When `mcast_tag` is `Some(v)`, also includes the
// oxg_mcast option (0 = External, 1 = Underlay, 2 = Both).
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

// Inner IPv4/ICMP multicast ethernet frame.
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

// Inner IPv6/ICMPv6 multicast ethernet frame.
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

// Geneve-over-IPv6 with inner IPv4/ICMP, no mcast tag.
fn geneve_mcast_v4_pkt(
    outer_src: &str,
    outer_dst: &str,
    inner_src: &str,
    inner_dst: &str,
) -> Vec<u8> {
    geneve_mcast_v4_pkt_repl(outer_src, outer_dst, inner_src, inner_dst, None)
}

// Geneve-over-IPv6 with inner IPv4/ICMP and optional mcast tag.
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

// Geneve-over-IPv6 with inner IPv6/ICMPv6.
fn geneve_mcast_v6_inner_pkt(
    outer_src: &str,
    outer_dst: &str,
    inner_src: &str,
    inner_dst: &str,
) -> Vec<u8> {
    let eth = inner_mcast_v6_frame(inner_src, inner_dst);
    wrap_geneve(outer_src, outer_dst, &eth, None)
}
