// Copyright 2025 Oxide Computer Company

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
    local()         local;
    router()        router;
    nat_ingress()   nat;
    resolver()      resolver;
    mac_rewrite()   mac;
    proxy_arp()     pxarp;

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
            nat.apply(hdr, ingress, egress); // check for ingress nat
        }

        //
        // After local and NAT processing, basic packet forwarding happens.
        //
        router.apply(hdr, ingress, egress); // router table lookups
        resolver.apply(hdr, egress);        // resolve the nexthop
        mac.apply(hdr, egress);             // source mac rewrite

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
        if (hdr.ipv4.isValid()) { nat_v4.apply(); }
        if (hdr.ipv6.isValid()) { nat_v6.apply(); }
    }

    action forward_to_sled(bit<128> target, bit<24> vni, bit<48> mac) {
        ingress.nat = true;

        bit<16> orig_l3_len = 0;
        bit<16> orig_l3_csum = 0;

        hdr.inner_eth = hdr.ethernet;
        hdr.inner_eth.dst = mac;
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
        hdr.ipv6.dst = target;
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
        hdr.geneve.vni = vni;
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
        if (hdr.ipv4.isValid()) { resolver_v4.apply(); }
        if (hdr.ipv6.isValid()) { resolver_v6.apply(); }
    }

    action rewrite_dst(bit<48> dst) { hdr.ethernet.dst = dst; }
    action drop()                   { egress.drop = true; }
}

control router_v4_route(
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) {
    table rtr {
        key = { ingress.path_idx: exact; }
        actions = { forward; forward_vlan; }
        // should never happen, but the compiler requires a default
        default_action = drop;
    }

    apply { rtr.apply(); }

    action drop() { egress.drop = true; }

    action forward(bit<16> port, bit<32> nexthop) {
        egress.port = port;
        egress.vlan_id = 12w0;
        egress.nexthop_v4 = nexthop;
        egress.drop = false;
    }

    action forward_vlan(bit<16> port, bit<32> nexthop, bit<12> vlan_id) {
        egress.port = port;
        egress.vlan_id = vlan_id;
        egress.nexthop_v4 = nexthop;
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
        key = { ingress.path_idx: exact; }
        actions = { forward; forward_vlan; }
        // should never happen, but the compiler requires a default
        default_action = drop;
    }

    apply { rtr.apply(); }

    action drop() { egress.drop = true; }

    action forward(bit<16> port, bit<128> nexthop) {
        egress.port = port;
        egress.vlan_id = 12w0;
        egress.nexthop_v6 = nexthop;
        egress.drop = false;
    }

    action forward_vlan(bit<16> port, bit<128> nexthop, bit<12> vlan_id) {
        egress.port = port;
        egress.vlan_id = vlan_id;
        egress.nexthop_v6 = nexthop;
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
            v4_route.apply(ingress, egress);
        }
        if (hdr.ipv6.isValid()) {
            v6_idx.apply(hdr.ipv6.dst, hdr.ipv6.src, ingress, egress);
            if (egress.drop == true) { return; }
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


control egress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress,
) { }
