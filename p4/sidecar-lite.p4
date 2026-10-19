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
    attached()      attached;
    local()         local;
    router()        router;
    nat_ingress()   nat;
    resolver()      resolver;
    mac_rewrite()   mac;
    proxy_arp()     pxarp;
    mcast_ingress() mcast;
    ipv4_ttl_decrement() ttl_dec;

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

        bool mcast_dst = false;
        if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.dst[127:120] == 8w0xff) { mcast_dst = true; }
        }
        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.dst[31:28] == 4w0xe) { mcast_dst = true; }
        }

        if (mcast_dst) {
            if (hdr.ipv4.isValid()) {
                // 01:00:5e + zero bit, then the low 23 bits of the
                // group (RFC 1112 section 6.4).
                if (hdr.ethernet.dst[47:23] != 25w0x0200bc) {
                    egress.drop = true;
                    return;
                }
                if (hdr.ethernet.dst[22:0] != hdr.ipv4.dst[22:0]) {
                    egress.drop = true;
                    return;
                }
            }

            if (hdr.ipv6.isValid()) {
                if (hdr.ethernet.dst[47:32] != 16w0x3333) {
                    egress.drop = true;
                    return;
                }
                if (hdr.ethernet.dst[31:0] != hdr.ipv6.dst[31:0]) {
                    egress.drop = true;
                    return;
                }
            }
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
            if (hdr.geneve.isValid()) {
                ingress.nat_egress_hit = true;
                decap_geneve();
            }
            // If there is no geneve header this is a packet from outside the
            // rack and should be sent to the scrimlet.
            else { fwd_to_scrimlet(); return; }
        } else {
            // Multicast with TTL/hop_limit <= 1 must not be forwarded
            // (RFC 1112, RFC 8200 section 3). The check lives here, not in
            // the parser, because scrimlet transmissions return earlier
            // through fwd_from_scrimlet and must not be dropped.
            if (mcast_dst) {
                if (hdr.ipv4.isValid()) {
                    if (hdr.ipv4.ttl <= 8w1) { egress.drop = true; return; }
                }
                if (hdr.ipv6.isValid()) {
                    if (hdr.ipv6.hop_limit <= 8w1) {
                        egress.drop = true;
                        return;
                    }
                }
            } else {
                attached.apply(ingress, hdr);
            }
            if (hdr.geneve.isValid() == false) {
                nat.apply(hdr, ingress, egress); // check for ingress nat
            }
        }

        //
        // After local and NAT processing, basic packet forwarding happens.
        //
        // Unicast and multicast are bifurcated, mirroring dendrite's
        // sidecar.p4 (the meta.is_mcast metadata check). Multicast traffic
        // is replicated and bypasses the unicast nexthop resolver,
        // whose default_action is drop. Each replica's destination and
        // source MACs are derived in the egress control instead.
        //
        // IPv6 link-local multicast (ff02::/16) never reaches this point; it is
        // marked local and handled by the earlier local path. The parser
        // rejects interface-local scope multicast, while expired multicast
        // (TTL/hop_limit <= 1) gets dropped on the non-local path above.
        //
        // IPv4 local network control (224.0.0.0/24, RFC 5771 section 4) is
        // not dropped by address. The TTL check covers IGMP, OSPF and
        // PIM, but senders such as mDNS and VRRP can use TTL 255.
        bool is_mcast = false;
        if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.dst[127:120] == 8w0xff) { is_mcast = true; }
        }
        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.dst[31:28] == 4w0xe) { is_mcast = true; }
        }

        if (is_mcast) {
            if (hdr.vlan.isValid()) {
                hdr.ethernet.ether_type = hdr.vlan.ether_type;
                hdr.vlan.setInvalid();
            }
            mcast.apply(hdr, ingress, egress);
            // Packet copies that keep their encapsulation are forwarded on the
            // outer IPv6 header, losing a hop like dendrite's
            // MulticastRouter6 (RFC 8200 section 3). Decapsulated copies
            // have the inner header decremented before decap_geneve executes.
            if (ingress.mcast_decap) {
                validate_mcast_external();
                if (egress.drop == false) {
                    if (hdr.inner_ipv4.isValid()) {
                        ttl_dec.apply(hdr.inner_ipv4);
                    }
                    if (hdr.inner_ipv6.isValid()) {
                        hdr.inner_ipv6.hop_limit =
                            hdr.inner_ipv6.hop_limit - 8w1;
                    }
                    decap_geneve();
                }
            } else {
                if (hdr.ipv6.isValid()) {
                    if (hdr.ipv6.hop_limit <= 8w1) { egress.drop = true; }
                    if (egress.drop == false) {
                        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 8w1;
                    }
                }
            }
            // An empty bitmap is equivalent to having no multicast group
            // configured, and the packet is dropped.
            //
            // This matches the default action of dendrite's
            // mcast_replication_ipv6 (drop_mcastv6_admin_scoped_no_group).
            // Neither pipeline sends an ICMP error for multicast (RFC 1812
            // section 4.3.2.7).
            if (egress.port_bitmap == 128w0) {
                egress.drop = true;
            }
        } else {
            router.apply(hdr, ingress, egress);
            resolver.apply(hdr, egress);
            mac.apply(hdr, egress);

            // Prevent reflection. Multicast ingress-port suppression is
            // handled in the replication bitmap, so this applies to
            // unicast only.
            if (ingress.port == egress.port) { egress.drop = true; }
        }
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

    action validate_mcast_external() {
        bool inner_mcast = false;
        if (hdr.inner_ipv4.isValid()) {
            if (hdr.inner_ipv4.dst[31:28] == 4w0xe) { inner_mcast = true; }
        }
        if (hdr.inner_ipv6.isValid()) {
            if (hdr.inner_ipv6.dst[127:120] == 8w0xff) { inner_mcast = true; }
        }
        if (inner_mcast == false) { egress.drop = true; }

        bool inner_l4 = false;
        if (hdr.inner_tcp.isValid()) { inner_l4 = true; }
        if (hdr.inner_udp.isValid()) { inner_l4 = true; }
        if (hdr.inner_icmp.isValid()) { inner_l4 = true; }
        if (inner_l4 == false) { egress.drop = true; }

        if (hdr.inner_ipv4.isValid()) {
            if (hdr.inner_ipv4.ttl <= 8w1) { egress.drop = true; }
        }

        if (hdr.inner_ipv6.isValid()) {
            if (hdr.inner_ipv6.hop_limit <= 8w1) { egress.drop = true; }
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
        actions = { forward_to_sled; NoAction; }
        default_action = NoAction;
    }

    table nat_v6 {
        key = {
            hdr.ipv6.dst:   exact;
            ingress.nat_id: range;
        }
        actions = { forward_to_sled; NoAction; }
        default_action = NoAction;
    }

    // Multicast NAT tables.
    //
    // These are keyed on both the destination address and VLAN ID.
    //
    // Packets with a mismatched VLAN miss the table and are not NAT'd
    // to the wrong underlay group. VLAN header validity is checked
    // inline in the apply block since x4c does not support isValid()
    // as a table key field.
    table nat_v4_mcast {
        key = {
            hdr.ipv4.dst:   exact;
            hdr.vlan.vid:   exact;
        }
        actions = { forward_to_sled; NoAction; }
        default_action = NoAction;
    }

    table nat_v6_mcast {
        key = {
            hdr.ipv6.dst:   exact;
            hdr.vlan.vid:   exact;
        }
        actions = { forward_to_sled; NoAction; }
        default_action = NoAction;
    }

    // Multicast NAT tables for untagged traffic.
    table nat_v4_mcast_untagged {
        key = {
            hdr.ipv4.dst:   exact;
        }
        actions = { forward_to_sled; NoAction; }
        default_action = NoAction;
    }

    table nat_v6_mcast_untagged {
        key = {
            hdr.ipv6.dst:   exact;
        }
        actions = { forward_to_sled; NoAction; }
        default_action = NoAction;
    }

    apply {
        if (ingress.forward_needed == false) {
            if (hdr.ipv4.isValid()) {
                // High nibble 0xe (0b1110) is the 224.0.0.0/4 multicast
                // range. Anything else is unicast and falls to nat_v4.
                if (hdr.ipv4.dst[31:28] == 4w0xe) {
                    if (hdr.vlan.isValid()) {
                        nat_v4_mcast.apply();
                    } else {
                        nat_v4_mcast_untagged.apply();
                    }
                } else {
                    nat_v4.apply();
                }
            }
            if (hdr.ipv6.isValid()) {
                // High octet 0xff is the ff00::/8 multicast range.
                // Anything else is unicast and falls to nat_v6.
                if (hdr.ipv6.dst[127:120] == 8w0xff) {
                    if (hdr.vlan.isValid()) {
                        nat_v6_mcast.apply();
                    } else {
                        nat_v6_mcast_untagged.apply();
                    }
                } else {
                    nat_v6.apply();
                }
            }
        }
        if (ingress.forward_needed == true) {
            if (hdr.ipv4.isValid()) {
                if (hdr.ipv4.ttl == 8w0) { egress.drop = true; return; }
            }
            if (hdr.ipv6.isValid()) {
                if (hdr.ipv6.hop_limit == 8w0) { egress.drop = true; return; }
            }
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
        hdr.inner_eth.src = 48w0;
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
        hdr.ipv6.traffic_class = 8w0;
        hdr.ipv6.flow_label = 20w0;
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
        actions = { forward_to_sled; NoAction; }
        default_action = NoAction;
    }

    table attached_subnet_v6 {
        key = {
            hdr.ipv6.dst:   lpm;
        }
        actions = { forward_to_sled; NoAction; }
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
        key = { ingress.path_idx: exact; }
        actions = { forward; forward_v6; forward_vlan; forward_vlan_v6; drop; }
        // should never happen, but the compiler requires a default
        default_action = drop;
    }

    apply { rtr.apply(); }

    action drop() { egress.drop = true; }

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
        key = { ingress.path_idx: exact; }
        actions = { forward; forward_vlan; drop; }
        // should never happen, but the compiler requires a default
        default_action = drop;
    }

    apply { rtr.apply(); }

    action drop() { egress.drop = true; }

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

// TODO: Use a top-level action once x4c supports top-level actions and
// writes out/inout argument changes back to the caller.
//
// <https://github.com/oxidecomputer/p4/blob/c8b190f46901d4c1b8eef1ca35be243b18653471/p4/src/parser.rs#L676-L696>
// <https://github.com/oxidecomputer/p4/blob/c8b190f46901d4c1b8eef1ca35be243b18653471/codegen/rust/src/statement.rs#L399-L407>
control ipv4_ttl_decrement(
    inout ipv4_h ip,
) {
    apply {
        ip.ttl = ip.ttl - 8w1;

        // Incremental IPv4 header checksum update, RFC 1624 eqn. 3:
        // HC' = ~(~HC + ~m + m') (HC -> header checksum; m and m'
        // are the old and new 16-bit words). TTL is the high byte of
        // its 16-bit word, where decrementing makes ~m + m' equal to
        // 0xfeff. Unlike HC + 0x0100 (RFC 1141), this yields 0x0000,
        // not 0xffff at the zero boundary, matching a full recompute
        // cycle.
        //
        // Note: x4c does not parse unary ~ yet; XOR with 0xffff
        // stands in instead.
        bit<16> neg_csum = ip.hdr_checksum ^ 16w0xffff;
        bit<32> csum32 = neg_csum;
        csum32 = csum32 + 32w0xfeff;
        bit<16> lo = csum32[15:0];
        bit<16> carry = csum32[31:16];
        bit<16> folded = lo + carry;
        ip.hdr_checksum = folded ^ 16w0xffff;
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
    ipv4_ttl_decrement() ttl_dec;

    apply {
        bit<16> outport = 0;

        // nat_ingress and this router control drop a TTL/hop_limit of 0 on
        // forwarding paths (RFC 1812 section 4.2.2.9 still has the switch
        // receive it on the local path), although the boundary services
        // (Geneve decap) path is exempt from this drop and is still routed
        // for an inner TTL of 0, matching dendrite's Router4/Router6.
        //
        // Nonzero ports drop a TTL/hop_limit <= 1 after route lookup.
        if (hdr.ipv4.isValid()) {
            if (ingress.nat_egress_hit == false) {
                if (hdr.ipv4.ttl == 8w0) { egress.drop = true; return; }
            }
            v4_idx.apply(hdr.ipv4.dst, hdr.ipv4.src, ingress, egress);
            if (egress.drop == true) { return; }
            v4_route.apply(ingress, egress);
            if (egress.drop == true) { return; }
            if (egress.port != 16w0) {
                if (hdr.ipv4.ttl <= 8w1) { egress.drop = true; return; }
                ttl_dec.apply(hdr.ipv4);
            }
        }
        if (hdr.ipv6.isValid()) {
            if (ingress.nat_egress_hit == false) {
                if (hdr.ipv6.hop_limit == 8w0) {
                    egress.drop = true;
                    return;
                }
            }
            v6_idx.apply(hdr.ipv6.dst, hdr.ipv6.src, ingress, egress);
            if (egress.drop == true) { return; }
            v6_route.apply(ingress, egress);
            if (egress.drop == true) { return; }
            if (egress.port != 16w0) {
                if (hdr.ipv6.hop_limit <= 8w1) { egress.drop = true; return; }
                hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 8w1;
            }
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
        actions = { rewrite; NoAction; }
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
        actions = { proxy_arp_reply; NoAction; }
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
        actions = { set_port_bitmap; NoAction; }
        default_action = NoAction;
    }

    table mcast_source_filter_v4 {
        key = {
            hdr.inner_ipv4.src: lpm;
            hdr.inner_ipv4.dst: exact;
        }
        actions = { allow_source; NoAction; }
        default_action = NoAction;
    }

    table mcast_source_filter_v6 {
        key = {
            hdr.inner_ipv6.src: lpm;
            hdr.inner_ipv6.dst: exact;
        }
        actions = { allow_source; NoAction; }
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
        }

        // Only Geneve-encapsulated multicast is replicated.
        //
        // Otherwise, multicast that missed ingress NAT keeps
        // allow_source_mcast unset and is dropped on the empty bitmap,
        // matching dendrite's drop_mcastv4_no_group/drop_mcastv6_no_group
        // semantics in MulticastIngress.
        //
        // Replication keys on the outer IPv6 destination only.
        if (ingress.allow_source_mcast) {
            if (hdr.ipv6.isValid()) { mcast_replication_v6.apply(); }
        }

        // Per-packet tag suppression. If the packet carries a geneve
        // multicast option, zero the bitmap for the group that has
        // already been served:
        //   0 (external)  -> suppress underlay_bitmap and decap
        //   1 (underlay)  -> suppress external_bitmap
        //   2 (both)      -> neither suppressed
        //
        // External-only copies leave decapsulated, matching dendrite's
        // invalidate_underlay_grp_and_set_decap (mcast_tag_check), which strips
        // the outer headers in ingress before replication.
        if (hdr.oxg_mcast.isValid()) {
            if (hdr.oxg_mcast.mcast_tag == 2w0) {
                egress.underlay_bitmap = 128w0;
                ingress.mcast_decap = true;
            } else if (hdr.oxg_mcast.mcast_tag == 2w1) {
                egress.external_bitmap = 128w0;
            }
        }

        // Merge both bitmaps into the final replication bitmap.
        egress.port_bitmap = egress.external_bitmap | egress.underlay_bitmap;
    }

    action set_port_bitmap(bit<128> external, bit<128> underlay, bit<16> rid) {
        egress.external_bitmap = external;
        egress.underlay_bitmap = underlay;
        egress.rid = rid;
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
    ipv4_ttl_decrement() ttl_dec;

    // Decap port bitmap table keyed on RID (replication ID), which
    // set_port_bitmap inscribes per group, essentially replacing Tofino's
    // egress_rid.
    //
    // Returns a 128-bit bitmap of logical ports that receive decapsulated
    // traffic. Ports not in the bitmap keep encapsulation intact.
    //
    // This is semantically equivalent to sidecar.p4's tbl_decap_ports
    // + asic_id_to_port + port_bitmap_check, with the bit test simplified
    // via a "<<" shift on the logical port number.
    table tbl_decap_ports {
        key = { egress.rid: exact; }
        actions = { set_decap_ports; set_decap_ports_and_vlan; NoAction; }
        default_action = NoAction;
    }

    // Source MAC rewrite per egress port.
    //
    // This runs on every replicated copy, meaning that both encapsulated
    // and decapsulated packets leave with the correct source MAC for the
    // keyed egress port.
    table mcast_src_mac {
        key = { egress.port: exact; }
        actions = { rewrite_src_mac; NoAction; }
        default_action = NoAction;
    }

    table asic_id_to_port {
        key = { egress.port: exact; }
        actions = { set_port_number; NoAction; }
        default_action = NoAction;
    }

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
        if (egress.port_bitmap == 128w0) { return; }

        asic_id_to_port.apply();

        if (ingress.mcast_decap) {
            tbl_decap_ports.apply();

            if (egress.port_number_valid) {
                bit<128> ext_port_idx = egress.port_number;
                bit<128> ext_port_mask = 128w1 << ext_port_idx;
                bit<128> ext_hit = egress.decap_bitmap & ext_port_mask;

                if (ext_hit != 128w0) {
                    if (egress.decap_has_vlan) {
                        add_vlan(egress.decap_vlan_id);
                    }
                }
            }
        }

        // Per-port decap only for UNDERLAY_EXTERNAL (tag=2) replicas
        // on the reserved underlay multicast subnet (ff04::/64),
        // matching Dendrite's egress mcast_tag_check. Tag=0 and tag=1
        // copies pass through without decap consideration.
        //
        // Note: this decap only applies to IPv6-outer underlay multicast.
        //
        // TODO: Collapse these nested conditionals once x4c parses `&&` and
        // `||` (P4-16 section 8.5, Expressions on Booleans). The lexer
        // tokenizes `&&` but treats `||` as two separate `|` tokens.
        // `try_parse_binop` handles neither of these logical operators.
        //
        // <https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html#sec-bool-exprs>
        // <https://github.com/oxidecomputer/p4/blob/4645231880ccae40efd2bc583b643944ab0f0a20/p4/src/parser.rs#L435-L457>
        if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.dst[127:64] == 64w0xff04000000000000) {
                if (hdr.geneve.isValid()) {
                    if (hdr.oxg_mcast.isValid()) {
                        if (hdr.oxg_mcast.mcast_tag == 2w2) {
                            tbl_decap_ports.apply();

                            if (egress.port_number_valid) {
                                bit<128> port_idx = egress.port_number;
                                bit<128> port_mask = 128w1 << port_idx;
                                bit<128> hit = egress.decap_bitmap & port_mask;

                                if (hit != 128w0) {
                                    validate_decap();
                                    if (egress.drop == false) {
                                        if (hdr.inner_ipv4.isValid()) {
                                            ttl_dec.apply(hdr.inner_ipv4);
                                        }
                                        if (hdr.inner_ipv6.isValid()) {
                                            hdr.inner_ipv6.hop_limit =
                                                hdr.inner_ipv6.hop_limit - 8w1;
                                        }
                                        if (egress.decap_has_vlan) {
                                            decap_vlan(egress.decap_vlan_id);
                                        } else {
                                            decap();
                                        }
                                    }
                                }
                            }
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

    action set_decap_ports(bit<128> ports) {
        egress.decap_bitmap = ports;
        egress.decap_has_vlan = false;
    }

    action set_decap_ports_and_vlan(bit<128> ports, bit<12> vlan_id) {
        egress.decap_bitmap = ports;
        egress.decap_has_vlan = true;
        egress.decap_vlan_id = vlan_id;
    }

    action rewrite_src_mac(bit<48> mac) { hdr.ethernet.src = mac; }

    action set_port_number(bit<8> port_number) {
        egress.port_number = port_number;
        egress.port_number_valid = true;
    }

    action decap() {
        strip_decap();
        hdr.vlan.setInvalid();
    }

    action decap_vlan(bit<12> vlan_id) {
        strip_decap();
        add_vlan(vlan_id);
    }

    action add_vlan(bit<12> vlan_id) {
        hdr.vlan.setValid();
        hdr.vlan.pcp = 3w0;
        hdr.vlan.dei = 1w0;
        hdr.vlan.vid = vlan_id;
        // Inner ethertype moves into VLAN header.
        hdr.vlan.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = 16w0x8100;
    }

    // Shared decap -> restore inner ethernet header and strip outer
    // headers.
    //
    // Note: validate_decap and the inner TTL decrement run first.
    action strip_decap() {
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

    action validate_decap() {
        bool inner_mcast = false;
        if (hdr.inner_ipv4.isValid()) {
            if (hdr.inner_ipv4.dst[31:28] == 4w0xe) { inner_mcast = true; }
        }
        if (hdr.inner_ipv6.isValid()) {
            if (hdr.inner_ipv6.dst[127:120] == 8w0xff) { inner_mcast = true; }
        }
        if (inner_mcast == false) { egress.drop = true; return; }

        // Drop expired inner packets instead of wrapping TTL/hop_limit.
        if (hdr.inner_ipv4.isValid()) {
            if (hdr.inner_ipv4.ttl <= 8w1) { egress.drop = true; }
        }

        if (hdr.inner_ipv6.isValid()) {
            if (hdr.inner_ipv6.hop_limit <= 8w1) { egress.drop = true; }
        }
    }
}
