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
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet_macros::Packet as PktDerive;
use pnet_macros_support::types::{u1, u16be, u2, u24be, u3, u5, u6, u7};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::println;

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

fn pipeline_init(pipeline: &mut main_pipeline) {
    // router entry upstream
    // Add a single path for 0.0.0.0/0 pointing at data in slot 2.
    let (key_buf, param_buf) = router_idx_entry("0.0.0.0", 0, 2, 0);
    pipeline
        .add_ingress_router_v4_idx_rtr_entry("index", &key_buf, &param_buf, 0);

    // At slot 2, add a forwarding entry gw=1.2.3.1, port=1
    let (key_buf, param_buf) = router_forward_entry(2, "1.2.3.1", 1);
    pipeline.add_ingress_router_v4_route_rtr_entry(
        "forward", &key_buf, &param_buf, 0,
    );

    // router entry downstream
    let (key_buf, param_buf) = router_entry("fd00:1::", 64, "fe80::1", 0);
    pipeline
        .add_ingress_router_v6_rtr_entry("forward", &key_buf, &param_buf, 0);

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
    eth.set_ethertype(EtherType(0x0800));
    eth.set_payload(&inner_ip_data);

    n += 8;
    let mut geneve_data: Vec<u8> =
        vec![0x00, 0x00, 0x65, 0x58, 0x11, 0x11, 0x11, 0x00];
    geneve_data.extend_from_slice(&eth_data);

    n += 8;
    let mut udp_data: Vec<u8> = vec![0; n];
    let mut udp = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp.set_source(100);
    udp.set_destination(6081);
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

    phy0.send(&[TxFrame::new(phy1.mac, 0x86dd, &ip_data)])?;

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
    phy1.send(&[TxFrame::new(phy0.mac, 0x0800, &ip_data)])?;
    std::thread::sleep(std::time::Duration::from_millis(250));
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

    assert_eq!(udp.get_source(), 6081);
    assert_eq!(udp.get_destination(), 6081);

    assert_eq!(geneve.get_version(), 0);
    assert_eq!(geneve.get_options_len(), 1);
    assert_eq!(geneve.get_control_packet(), 0);
    assert_eq!(geneve.get_has_critical_option(), 0);
    assert_eq!(geneve.get_protocol_type(), 0x6558);
    assert_eq!(geneve.get_vni(), 7777);

    assert_eq!(geneve_opt.get_option_class(), 0x0129);
    assert_eq!(geneve_opt.get_critical_option(), 0);
    assert_eq!(geneve_opt.get_option_type(), 0);
    assert_eq!(geneve_opt.get_option_len(), 0);

    Ok(())
}

// Create an entry for the multipath cidr -> index table
fn router_idx_entry(
    dst: &str,
    prefix_len: u8,
    idx: u16,
    mask: u16,
) -> (Vec<u8>, Vec<u8>) {
    let mut key_buf = match dst.parse().unwrap() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    key_buf.push(prefix_len);

    let mut param_buf = idx.to_le_bytes().to_vec();
    let mask_buf = mask.to_le_bytes().to_vec();
    param_buf.extend_from_slice(&mask_buf);

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

fn router_entry(
    dst: &str,
    prefix_len: u8,
    gw: &str,
    port: u16,
) -> (Vec<u8>, Vec<u8>) {
    let mut key_buf = match dst.parse().unwrap() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    key_buf.push(prefix_len);

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
