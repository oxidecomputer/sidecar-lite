// Copyright 2026 Oxide Computer Company

#include <core.p4>
#include <softnpu.p4>
#include <headers.p4>
#include <parser.p4>

SoftNPU(
    parse(),
    ingress(),
    egress()
) main;

control ingress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    attached()           attached;
    local()              local;
    router()             router;
    nat_ingress()        nat;
    resolver()           resolver;
    mac_rewrite()        mac;
    proxy_arp()          pxarp;
    mcast_ingress()      mcast;
    Replicate()          mcast_rep;

    apply {
        //
        // Check if this is a packet coming from the scrimlet. If so just
        // forward it out the source port indicated by the sidecar header.
        //
        if (hdr.sidecar.isValid()) { fwd_from_scrimlet(); return; }

        ///
        /// Check if we need to proxy arp this packet.
        ///
        if (hdr.arp.isValid()) {
            bool proxied = false;
            pxarp.apply(hdr, ingress, egress, proxied);
            if (proxied) { return; }
        }

        //
        // If the packet has a local destination, create the sidecar header and
        // send it to the scrimlet.
        //
        bool local_dst = false;
        local.apply(ingress, hdr, local_dst);
        if (local_dst) {
            // If this is boundary services packet, it should have a geneve
            // header. Decap and attempt to route.
            if (hdr.geneve.isValid()) { decap_geneve(); }
            // If there is no geneve header this is a packet from outside the
            // rack and should be sent to the scrimlet.
            else { fwd_to_scrimlet(); return; }
        } else {
            attached.apply(ingress, hdr);
            nat.apply(hdr, ingress, egress); // check for ingress nat
        }

        //
        // After local and NAT processing, basic packet forwarding happens.
        //
        router.apply(hdr, ingress, egress);
        mcast.apply(hdr, ingress, egress);
        mcast_rep.replicate(egress.port_bitmap);
        resolver.apply(hdr, egress);
        mac.apply(hdr, egress);

        // Prevent reflection.
        if (ingress.port == egress.port) { egress.drop = true; }
    }

    action decap_geneve() {
        hdr.geneve.setInvalid();
        hdr.oxg_external_tag.setInvalid();
        hdr.oxg_mcast_tag.setInvalid();
        hdr.oxg_mcast.setInvalid();
        hdr.oxg_mss_tag.setInvalid();
        hdr.oxg_mss.setInvalid();
        hdr.ethernet = hdr.inner_eth;
        hdr.inner_eth.setInvalid();
        if (hdr.inner_ipv4.isValid()) {
            hdr.ipv4 = hdr.inner_ipv4;
            hdr.ipv4.setValid();
            hdr.ipv6.setInvalid();
            hdr.inner_ipv4.setInvalid();
        }
        if (hdr.inner_ipv6.isValid()) {
            hdr.ipv6 = hdr.inner_ipv6;
            hdr.ipv6.setValid();
            hdr.ipv4.setInvalid();
            hdr.inner_ipv6.setInvalid();
        }
        if (hdr.inner_tcp.isValid()) {
            hdr.tcp = hdr.inner_tcp;
            hdr.udp.setInvalid();
            hdr.tcp.setValid();
            hdr.inner_tcp.setInvalid();
        }
        if (hdr.inner_udp.isValid()) {
            hdr.udp = hdr.inner_udp;
            hdr.udp.setValid();
            hdr.inner_udp.setInvalid();
        }
        if (hdr.inner_icmp.isValid()) {
            hdr.icmp = hdr.inner_icmp;
            hdr.udp.setInvalid();
            hdr.icmp.setValid();
            hdr.inner_icmp.setInvalid();
        }
    }

    action fwd_to_scrimlet() {
        hdr.sidecar.setValid();
        hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = 16w0x0901;
        hdr.sidecar.sc_code = 8w0x01; //SC_FORWARD_TO_USERSPACE
        hdr.sidecar.sc_ingress = ingress.port;
        hdr.sidecar.sc_egress = ingress.port;
        hdr.sidecar.sc_payload = 128w0x1701d;

        // TODO simply stating 0 here causes bad conversion, initializes
        // egress.port as a 128 bit value due to
        // StatementGenerator::converter using int_to_bitvec
        egress.port = 16w0; // scrimlet port
    }

    action fwd_from_scrimlet() {
        //  Direct packets to the sidecar port corresponding to the scrimlet
        //  port they came from.
        egress.port = hdr.sidecar.sc_egress;
        // Decap the sidecar header.
        hdr.ethernet.ether_type = hdr.sidecar.sc_ether_type;
        hdr.sidecar.setInvalid();
    }
}

control nat_ingress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    Checksum() csum;

    table nat_v4 {
        key = {
            hdr.ipv4.dst:   exact;
            ingress.nat_id: range;
        }
        actions = { forward_to_sled; }
        default_action = NoAction;
    }

    table nat_v6 {
        key = {
            hdr.ipv6.dst:   exact;
            ingress.nat_id: range;
        }
        actions = { forward_to_sled; }
        default_action = NoAction;
    }

    apply {
        if (ingress.forward_needed == false) {
            if (hdr.ipv4.isValid()) { nat_v4.apply(); }
            if (hdr.ipv6.isValid()) { nat_v6.apply(); }
        }
        if (ingress.forward_needed == true) {
            forward_packet();
        }
    }

    action forward_to_sled(bit<128> target, bit<24> vni, bit<48> mac) {
        ingress.forward_tgt = target;
        ingress.forward_vni = vni;
        ingress.forward_mac = mac;
        ingress.forward_needed = true;
    }

    action forward_packet() {
        bit<16> orig_l3_len = 0;
        bit<16> orig_l3_csum = 0;

        hdr.inner_eth = hdr.ethernet;
        hdr.inner_eth.dst = ingress.forward_mac;
        hdr.inner_eth.setValid();
        if (hdr.vlan.isValid()) {
            hdr.inner_eth.ether_type = hdr.vlan.ether_type;
            hdr.vlan.setInvalid();
        }

        // fix up outer L2
        hdr.ethernet.ether_type = 16w0x86dd;

        // move L3 to inner L3
        if (hdr.ipv4.isValid()) {
            hdr.inner_ipv4 = hdr.ipv4;
            orig_l3_len = hdr.ipv4.total_len;
            hdr.inner_ipv4.setValid();
        }
        if (hdr.ipv6.isValid()) {
            hdr.inner_ipv6 = hdr.ipv6;
            orig_l3_len = hdr.ipv6.payload_len + 16w40;
            hdr.inner_ipv6.setValid();
        }

        // move L4 to inner L4
        if (hdr.tcp.isValid()) {
            hdr.inner_tcp = hdr.tcp;
            hdr.inner_tcp.setValid();
            hdr.tcp.setInvalid();
        }
        if (hdr.udp.isValid()) {
            orig_l3_csum = hdr.udp.checksum;
            hdr.inner_udp = hdr.udp;
            hdr.inner_udp.setValid();
        }
        if (hdr.icmp.isValid()) {
            hdr.inner_icmp = hdr.icmp;
            hdr.inner_icmp.setValid();
            hdr.icmp.setInvalid();
        }

        // set up outer l3
        hdr.ipv4.setInvalid();

        hdr.ipv6.version = 4w6;
        // original l2 + original l3 + encapsulating udp + encapsulating geneve + geneve opt
        hdr.ipv6.payload_len = 16w14 + orig_l3_len + 16w8 + 16w8 + 16w4;
        hdr.ipv6.next_hdr = 8w17;
        hdr.ipv6.hop_limit = 8w255;
        // XXX hardcoded boundary services addr
        hdr.ipv6.src = 128w0xfd000099000000000000000000000001;
        hdr.ipv6.dst = ingress.forward_tgt;
        hdr.ipv6.setValid();

        // set up outer udp
        hdr.udp.src_port = 16w6081;
        hdr.udp.dst_port = 16w6081;
        hdr.udp.len = hdr.ipv6.payload_len;
        hdr.udp.checksum = 16w0;
        hdr.udp.setValid();

        // set up geneve
        hdr.geneve.version = 2w0;
        hdr.geneve.opt_len = 6w1;
        hdr.geneve.ctrl = 1w0;
        hdr.geneve.crit = 1w0;
        hdr.geneve.reserved = 6w0;
        hdr.geneve.protocol = 16w0x6558;
        hdr.geneve.vni = ingress.forward_vni;
        hdr.geneve.reserved2 = 8w0;
        hdr.geneve.setValid();

        // 4-byte option -- 'VPC-external packet'.
        // XXX: const GENEVE_OPT_CLASS_OXIDE not recognised here by x4c.
        hdr.oxg_external_tag.class = 16w0x0129;
        hdr.oxg_external_tag.crit = 1w0;
        hdr.oxg_external_tag.rtype = 7w0x00;
        hdr.oxg_external_tag.reserved = 3w0;
        hdr.oxg_external_tag.opt_len = 5w0;
        hdr.oxg_external_tag.setValid();

        /// TODO: this is broken so just set to zero for now.
        hdr.udp.checksum = csum.run({
            hdr.ipv6.src,
            hdr.ipv6.dst,
            orig_l3_len + 16w14 + 16w8 + 16w8 + 16w4, // orig + eth + udp + geneve + opt
            8w17, // udp next header
            16w6081, 16w6081, // geneve src/dst port
            orig_l3_len + 16w14 + 16w8 + 16w8 + 16w4, // orig + eth + udp + geneve + opt
            // geneve body
            16w0x0100,
            hdr.geneve.protocol,
            hdr.geneve.vni,
            8w0x00,
            hdr.oxg_external_tag.class,
            orig_l3_csum,
        });
        hdr.udp.checksum = 16w0;
    }
}

control local(
    inout ingress_metadata_t ingress,
    inout headers_t hdr,
    out bool is_local,
) {
    table local_v6 {
        key = { hdr.ipv6.dst: exact; }
        actions = { local; nonlocal; }
        default_action = nonlocal;
    }

    table local_v4 {
        key = { hdr.ipv4.dst: exact; }
        actions = { local; nonlocal; }
        default_action = nonlocal;
    }

    apply {
        if(hdr.ipv6.isValid()) {
            local_v6.apply();
            if(hdr.ipv6.dst[127:112] == 16w0xff02) { is_local = true; }
        }
        if(hdr.ipv4.isValid()) { local_v4.apply(); }
        if(hdr.arp.isValid())  { is_local = true; }
        if(ingress.lldp)       { is_local = true; }
    }

    action nonlocal() { is_local = false; }
    action local()    { is_local = true; }
}

control attached(
    inout ingress_metadata_t ingress,
    inout headers_t hdr,
) {
    table attached_subnet_v4 {
        key = {
            hdr.ipv4.dst:   lpm;
        }
        actions = { forward_to_sled; }
        default_action = NoAction;
    }

    table attached_subnet_v6 {
        key = {
            hdr.ipv6.dst:   lpm;
        }
        actions = { forward_to_sled; }
        default_action = NoAction;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            attached_subnet_v4.apply();
        } else if (hdr.ipv6.isValid()) {
            attached_subnet_v6.apply();
        }
    }

    action forward_to_sled(bit<128> target, bit<24> vni, bit<48> mac) {
        ingress.forward_tgt = target;
        ingress.forward_vni = vni;
        ingress.forward_mac = mac;
        ingress.forward_needed = true;
    }
}

control resolver(
    inout headers_t hdr,
    inout egress_metadata_t egress,
) {
    table resolver_v4 {
        key = { egress.nexthop_v4: exact; }
        actions = { rewrite_dst; drop; }
        default_action = drop;
    }

    table resolver_v6 {
        key = { egress.nexthop_v6: exact; }
        actions = { rewrite_dst; drop; }
        default_action = drop;
    }

    apply {
        if (egress.nexthop_v4 != 32w0) { resolver_v4.apply(); }
        if (egress.nexthop_v6 != 128w0) { resolver_v6.apply(); }
    }

    action rewrite_dst(bit<48> dst) { hdr.ethernet.dst = dst; }
    action drop()                   { egress.drop = true; }
}

control router_v4_route(
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    table rtr {
        key = {
            ingress.path_idx: exact;
            ingress.route_ttl_is_1: exact;
        }
        actions = { forward; forward_v6; forward_vlan; forward_vlan_v6; ttl_exceeded; }
        // should never happen, but the compiler requires a default
        default_action = drop;
    }

    apply { rtr.apply(); }

    action drop() { egress.drop = true; }
    action ttl_exceeded() { egress.drop = true; }

    action forward(bit<16> port, bit<32> nexthop) {
        egress.port = port;
        egress.vlan_id = 12w0;
        egress.nexthop_v4 = nexthop;
        egress.nexthop_v6 = 128w0;
        egress.drop = false;
    }

    action forward_v6(bit<16> port, bit<128> nexthop) {
        egress.port = port;
        egress.vlan_id = 12w0;
        egress.nexthop_v6 = nexthop;
        egress.nexthop_v4 = 32w0;
        egress.drop = false;
    }

    action forward_vlan(bit<16> port, bit<32> nexthop, bit<12> vlan_id) {
        egress.port = port;
        egress.vlan_id = vlan_id;
        egress.nexthop_v4 = nexthop;
        egress.nexthop_v6 = 128w0;
        egress.drop = false;
    }

    action forward_vlan_v6(bit<16> port, bit<128> nexthop, bit<12> vlan_id) {
        egress.port = port;
        egress.vlan_id = vlan_id;
        egress.nexthop_v6 = nexthop;
        egress.nexthop_v4 = 32w0;
        egress.drop = false;
    }
}

control router_v4_idx(
    in bit<32> dst_addr,
    in bit<32> src_addr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    Checksum() csum;

    table rtr {
        key = { dst_addr: lpm; }
        actions = { drop; index; }
        default_action = drop;
    }

    apply { rtr.apply(); }

    action drop() { egress.drop = true; }

    action index(bit<16> idx, bit<8> slots) {
        bit<16> hash = csum.run({dst_addr, src_addr});
        bit<16> extended_slots = slots;
        bit<16> offset = hash % extended_slots;
        ingress.path_idx = idx + offset;
    }
}

control router_v6_route(
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    table rtr {
        key = {
            ingress.path_idx: exact;
            ingress.route_ttl_is_1: exact;
        }
        actions = { forward; forward_vlan; ttl_exceeded; }
        // should never happen, but the compiler requires a default
        default_action = drop;
    }

    apply { rtr.apply(); }

    action drop() { egress.drop = true; }
    action ttl_exceeded() { egress.drop = true; }

    action forward(bit<16> port, bit<128> nexthop) {
        egress.port = port;
        egress.vlan_id = 12w0;
        egress.nexthop_v6 = nexthop;
        egress.nexthop_v4 = 32w0;
        egress.drop = false;
    }

    action forward_vlan(bit<16> port, bit<128> nexthop, bit<12> vlan_id) {
        egress.port = port;
        egress.vlan_id = vlan_id;
        egress.nexthop_v6 = nexthop;
        egress.nexthop_v4 = 32w0;
        egress.drop = false;
    }
}

control router_v6_idx(
    in bit<128> dst_addr,
    in bit<128> src_addr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    Checksum() csum;

    table rtr {
        key = { dst_addr: lpm; }
        actions = { drop; index; }
        default_action = drop;
    }

    apply { rtr.apply(); }

    action drop() { egress.drop = true; }

    action index(bit<16> idx, bit<8> slots) {
        bit<16> hash = csum.run({dst_addr, src_addr});
        bit<16> extended_slots = slots;
        bit<16> offset = hash % extended_slots;
        ingress.path_idx = idx + offset;
    }
}

control router(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    router_v4_idx() v4_idx;
    router_v4_route() v4_route;
    router_v6_idx() v6_idx;
    router_v6_route() v6_route;

    apply {
        bit<16> outport = 0;

        if (hdr.ipv4.isValid()) {
            v4_idx.apply(hdr.ipv4.dst, hdr.ipv4.src, ingress, egress);
            if (egress.drop == true) { return; }
            if (hdr.ipv4.ttl == 8w1) { ingress.route_ttl_is_1 = 1w1; }
            v4_route.apply(ingress, egress);
        }
        if (hdr.ipv6.isValid()) {
            v6_idx.apply(hdr.ipv6.dst, hdr.ipv6.src, ingress, egress);
            if (egress.drop == true) { return; }
            if (hdr.ipv6.hop_limit == 8w1) { ingress.route_ttl_is_1 = 1w1; }
            v6_route.apply(ingress, egress);
        }
        outport = egress.port;
        if (egress.vlan_id != 12w0) {
            hdr.vlan.pcp = 3w0;
            hdr.vlan.dei = 1w0;
            hdr.vlan.vid = egress.vlan_id;
            hdr.vlan.ether_type = hdr.ethernet.ether_type;
            hdr.vlan.setValid();
            hdr.ethernet.ether_type = 16w0x8100;
        }
    }
}

control mac_rewrite(
    inout headers_t hdr,
    inout egress_metadata_t egress,
) {
    table mac_rewrite {
        key = { egress.port: exact; }
        actions = { rewrite; }
        default_action = NoAction;
    }

    apply { mac_rewrite.apply(); }

    action rewrite(bit<48> mac) { hdr.ethernet.src = mac; }
}

control proxy_arp(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
    out bool is_proxied,
) {
    table proxy_arp {
        key = { hdr.arp.target_ip: range; }
        actions = { proxy_arp_reply; }
        default_action = NoAction;
    }

    apply { proxy_arp.apply(); }

    action proxy_arp_reply(bit<48> mac) {
        egress.port = ingress.port;
        hdr.ethernet.dst = hdr.ethernet.src;
        hdr.ethernet.src = mac;
        hdr.arp.target_mac = hdr.arp.sender_mac;
        hdr.arp.sender_mac = mac;
        hdr.arp.opcode = 16w2;
        bit<32> tmp = hdr.arp.sender_ip;
        hdr.arp.sender_ip = hdr.arp.target_ip;
        hdr.arp.target_ip = tmp;

        is_proxied = true;
    }
}

control mcast_ingress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    table mcast_replication_v6 {
        key = { hdr.ipv6.dst: exact; }
        actions = { set_port_bitmap; }
        default_action = NoAction;
    }

    table mcast_replication_v4 {
        key = { hdr.ipv4.dst: exact; }
        actions = { set_port_bitmap; }
        default_action = NoAction;
    }

    table mcast_source_filter_v4 {
        key = {
            hdr.inner_ipv4.src: lpm;
            hdr.inner_ipv4.dst: exact;
        }
        actions = { allow_source; }
        default_action = NoAction;
    }

    table mcast_source_filter_v6 {
        key = {
            hdr.inner_ipv6.src: lpm;
            hdr.inner_ipv6.dst: exact;
        }
        actions = { allow_source; }
        default_action = NoAction;
    }

    apply {
        // Source filtering for geneve-encapsulated multicast traffic.
        //
        // Check inner destination is a multicast address before applying
        // the source filter table.
        if (hdr.geneve.isValid()) {
            if (hdr.inner_ipv4.isValid()) {
                // 224.0.0.0/4
                if (hdr.inner_ipv4.dst[31:28] == 4w0xe) {
                    mcast_source_filter_v4.apply();
                } else {
                    ingress.allow_source_mcast = true;
                }
            } else if (hdr.inner_ipv6.isValid()) {
                // ff00::/8
                if (hdr.inner_ipv6.dst[127:120] == 8w0xff) {
                    mcast_source_filter_v6.apply();
                } else {
                    ingress.allow_source_mcast = true;
                }
            }
        } else {
            // Non-encapsulated traffic skips source filtering.
            ingress.allow_source_mcast = true;
        }

        // Replication only proceeds if source filtering passed.
        if (ingress.allow_source_mcast) {
            if (hdr.ipv6.isValid()) { mcast_replication_v6.apply(); }
            if (hdr.ipv4.isValid()) { mcast_replication_v4.apply(); }
        }

        // Per-packet tag suppression. If the packet carries a geneve
        // multicast option, zero the bitmap for the group that has
        // already been served:
        //   0 (external)  -> suppress bitmap_b (underlay)
        //   1 (underlay)  -> suppress bitmap_a (external)
        //   2 (both)      -> neither suppressed
        if (hdr.oxg_mcast.isValid()) {
            if (hdr.oxg_mcast.mcast_tag == 2w0) {
                egress.underlay_bitmap = 128w0;
            }
            if (hdr.oxg_mcast.mcast_tag == 2w1) {
                egress.external_bitmap = 128w0;
            }
        }

        // Merge both bitmaps into the final replication bitmap.
        egress.port_bitmap = egress.external_bitmap | egress.underlay_bitmap;
    }

    action set_port_bitmap(bit<128> external, bit<128> underlay) {
        egress.external_bitmap = external;
        egress.underlay_bitmap = underlay;
    }

    action allow_source() {
        ingress.allow_source_mcast = true;
    }
}

control egress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    // Per-port decapsulation for multicast replicated copies.
    //
    // Ports in this table receive decapsulated (customer-facing) traffic.
    // Ports not in the table keep encapsulation intact (sled-bound,
    // OPTE handles decap). Equivalent to DPD's tbl_decap_ports.
    table mcast_egress_decap {
        key = { egress.port: exact; }
        actions = { decap; decap_vlan; }
        default_action = NoAction;
    }

    // Source MAC rewrite per egress port. Runs on every replicated
    // copy so both encapsulated and decapsulated packets leave with
    // the correct source MAC for the egress port.
    table mcast_src_mac {
        key = { egress.port: exact; }
        actions = { rewrite_src_mac; }
        default_action = NoAction;
    }

    action rewrite_src_mac(bit<48> mac) { hdr.ethernet.src = mac; }

    apply {
        // Validate that the packet is actually multicast by checking
        // the outer IP destination range before applying any multicast-specific
        // egress processing.
        bool is_mcast_pkt = false;

        if (hdr.ipv6.isValid()) {
            // ff00::/8
            if (hdr.ipv6.dst[127:120] == 8w0xff) { is_mcast_pkt = true; }
        }
        if (hdr.ipv4.isValid()) {
            // 224.0.0.0/4
            if (hdr.ipv4.dst[31:28] == 4w0xe) { is_mcast_pkt = true; }
        }

        if (is_mcast_pkt == false) { return; }

        // Per-port decap only for UNDERLAY_EXTERNAL (tag=2) replicas
        // on the reserved underlay multicast subnet (ff04::/64),
        // matching Dendrite's egress mcast_tag_check. Tag=0 and tag=1
        // copies pass through without decap consideration.
        if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.dst[127:64] == 64w0xff04000000000000) {
                if (hdr.geneve.isValid()) {
                    if (hdr.oxg_mcast.isValid()) {
                        if (hdr.oxg_mcast.mcast_tag == 2w2) {
                            mcast_egress_decap.apply();
                        }
                    }
                }
            }
        }

        // Derive multicast dst MAC from the IP destination
        // (RFC 1112 section 6.4 for IPv4, RFC 2464 for IPv6).
        // Encapsulated copies use the outer IP. Decapped copies
        // use the inner IP (outer is stripped).
        if (hdr.ipv6.isValid()) {
            hdr.ethernet.dst[47:32] = 16w0x3333;
            hdr.ethernet.dst[31:0] = hdr.ipv6.dst[31:0];
        }
        if (hdr.ipv4.isValid()) {
            hdr.ethernet.dst[47:24] = 24w0x01005e;
            hdr.ethernet.dst[23:16] = hdr.ipv4.dst[23:16];
            hdr.ethernet.dst[15:0] = hdr.ipv4.dst[15:0];
            hdr.ethernet.dst[23:23] = 1w0;
        }
        if (hdr.geneve.isValid() == false) {
            if (hdr.inner_ipv4.isValid()) {
                hdr.ethernet.dst[47:24] = 24w0x01005e;
                hdr.ethernet.dst[23:16] = hdr.inner_ipv4.dst[23:16];
                hdr.ethernet.dst[15:0] = hdr.inner_ipv4.dst[15:0];
                hdr.ethernet.dst[23:23] = 1w0;
            }
            if (hdr.inner_ipv6.isValid()) {
                hdr.ethernet.dst[47:32] = 16w0x3333;
                hdr.ethernet.dst[31:0] = hdr.inner_ipv6.dst[31:0];
            }
        }

        // Rewrite source MAC for the egress port.
        mcast_src_mac.apply();
    }

    action decap() {
        strip_decap();
        hdr.vlan.setInvalid();
    }

    action decap_vlan(bit<12> vlan_id) {
        strip_decap();
        hdr.vlan.setValid();
        hdr.vlan.pcp = 3w0;
        hdr.vlan.dei = 1w0;
        hdr.vlan.vid = vlan_id;
        // Inner ethertype moves into VLAN header.
        hdr.vlan.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = 16w0x8100;
    }

    // Shared decap: validate and decrement inner TTL, restore inner
    // ethernet header, and strip outer headers.
    //
    // Sets egress.drop on expired TTL. Callers still run but the
    // packet is dropped before emission.
    action strip_decap() {
        // Drop expired inner packets instead of wrapping TTL/hop_limit.
        if (hdr.inner_ipv4.isValid()) {
            if (hdr.inner_ipv4.ttl == 8w0) { egress.drop = true; }
            if (hdr.inner_ipv4.ttl == 8w1) { egress.drop = true; }
            if (egress.drop == false) {
                hdr.inner_ipv4.ttl = hdr.inner_ipv4.ttl - 8w1;
                // Incremental IPv4 header checksum update (RFC 1624).
                // TTL occupies the high byte of a 16-bit word, so
                // decrementing TTL by 1 adds 0x0100. Detect overflow
                // and fold the carry for ones-complement correctness.
                bit<16> old_csum = hdr.inner_ipv4.hdr_checksum;
                bit<16> new_csum = old_csum + 16w0x0100;
                if (new_csum < old_csum) {
                    new_csum = new_csum + 16w1;
                }
                hdr.inner_ipv4.hdr_checksum = new_csum;
            }
        }

        if (hdr.inner_ipv6.isValid()) {
            if (hdr.inner_ipv6.hop_limit == 8w0) { egress.drop = true; }
            if (hdr.inner_ipv6.hop_limit == 8w1) { egress.drop = true; }
            if (egress.drop == false) {
                hdr.inner_ipv6.hop_limit = hdr.inner_ipv6.hop_limit - 8w1;
            }
        }

        if (egress.drop == true) { return; }

        // Restore inner ethernet header, then strip encapsulation.
        hdr.ethernet = hdr.inner_eth;
        hdr.inner_eth.setInvalid();

        // Set ethertype based on inner IP version.
        if (hdr.inner_ipv4.isValid()) {
            hdr.ethernet.ether_type = 16w0x0800;
        }
        if (hdr.inner_ipv6.isValid()) {
            hdr.ethernet.ether_type = 16w0x86dd;
        }

        // Strip outer headers.
        hdr.ipv6.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
        hdr.tcp.setInvalid();
        hdr.geneve.setInvalid();
        hdr.oxg_external_tag.setInvalid();
        hdr.oxg_mcast_tag.setInvalid();
        hdr.oxg_mcast.setInvalid();
        hdr.oxg_mss_tag.setInvalid();
        hdr.oxg_mss.setInvalid();
    }
}
