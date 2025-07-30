// Copyright 2024 Oxide Computer Company

parser parse(
    packet_in pkt,
    out headers_t hdr,
    inout ingress_metadata_t ingress,
){
    state start {
        pkt.extract(hdr.ethernet);
        if (hdr.ethernet.ether_type == 16w0x0800) { transition ipv4; }
        if (hdr.ethernet.ether_type == 16w0x88cc) { transition lldp; }
        if (hdr.ethernet.ether_type == 16w0x86dd) { transition ipv6; }
        if (hdr.ethernet.ether_type == 16w0x0901) { transition sidecar; }
        if (hdr.ethernet.ether_type == 16w0x0806) { transition arp; }
        if (hdr.ethernet.ether_type == 16w0x8100) { transition vlan; }
        transition reject;
    }

    state sidecar {
        pkt.extract(hdr.sidecar);
        if (hdr.sidecar.sc_ether_type == 16w0x86dd) { transition ipv6; }
        if (hdr.sidecar.sc_ether_type == 16w0x88cc) { transition lldp; }
        if (hdr.sidecar.sc_ether_type == 16w0x0800) { transition ipv4; }
        if (hdr.sidecar.sc_ether_type == 16w0x0806) { transition arp; }
        if (hdr.sidecar.sc_ether_type == 16w0x8100) { transition vlan; }
        transition reject;
    }

    state lldp {
	    ingress.lldp = true;
	    transition accept;
    }

    state vlan {
        pkt.extract(hdr.vlan);
        if (hdr.vlan.ether_type == 16w0x0800) { transition ipv4; }
        if (hdr.vlan.ether_type == 16w0x86dd) { transition ipv6; }
        if (hdr.vlan.ether_type == 16w0x0806) { transition arp; }
        transition reject;
    }

    state arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state ipv6 {
        pkt.extract(hdr.ipv6);
        if (hdr.ipv6.next_hdr == 8w0xdd) { transition ddm; }
        if (hdr.ipv6.next_hdr == 8w58)   { transition icmp; }
        if (hdr.ipv6.next_hdr == 8w17)   { transition udp; }
        if (hdr.ipv6.next_hdr == 8w6)    { transition tcp; }
        transition accept;
    }

    state ddm {
        pkt.extract(hdr.ddm);
        if (hdr.ddm.header_length >= 8w7) { pkt.extract(hdr.ddm0); }
        if (hdr.ddm.header_length >= 8w11) { pkt.extract(hdr.ddm1); }
        if (hdr.ddm.header_length >= 8w15) { pkt.extract(hdr.ddm2); }
        if (hdr.ddm.header_length >= 8w19) { pkt.extract(hdr.ddm3); }
        if (hdr.ddm.header_length >= 8w23) { pkt.extract(hdr.ddm4); }
        if (hdr.ddm.header_length >= 8w27) { pkt.extract(hdr.ddm5); }
        if (hdr.ddm.header_length >= 8w31) { pkt.extract(hdr.ddm6); }
        if (hdr.ddm.header_length >= 8w35) { pkt.extract(hdr.ddm7); }
        if (hdr.ddm.header_length >= 8w39) { pkt.extract(hdr.ddm8); }
        if (hdr.ddm.header_length >= 8w43) { pkt.extract(hdr.ddm9); }
        if (hdr.ddm.header_length >= 8w47) { pkt.extract(hdr.ddm10); }
        if (hdr.ddm.header_length >= 8w51) { pkt.extract(hdr.ddm11); }
        if (hdr.ddm.header_length >= 8w55) { pkt.extract(hdr.ddm12); }
        if (hdr.ddm.header_length >= 8w59) { pkt.extract(hdr.ddm13); }
        if (hdr.ddm.header_length >= 8w63) { pkt.extract(hdr.ddm14); }
        if (hdr.ddm.header_length >= 8w67) { pkt.extract(hdr.ddm15); }
        transition accept;
    }

    state icmp {
        pkt.extract(hdr.icmp);
        ingress.nat_id = hdr.icmp.identifier;
        transition accept;
    }

    state ipv4 {
        pkt.extract(hdr.ipv4);
        if (hdr.ipv4.protocol == 8w17) { transition udp; }
        if (hdr.ipv4.protocol == 8w6)  { transition tcp; }
        if (hdr.ipv4.protocol == 8w1)  { transition icmp; }
        transition accept;
    }

    state udp {
        pkt.extract(hdr.udp);
        ingress.nat_id = hdr.udp.dst_port;
        if (hdr.udp.dst_port == 16w6081) { transition geneve; }
        transition accept;
    }

    state tcp {
        pkt.extract(hdr.tcp);
        ingress.nat_id = hdr.tcp.dst_port;
        transition accept;
    }

    state geneve {
        pkt.extract(hdr.geneve);
        ingress.geneve_chunks = hdr.geneve.opt_len;
        if (hdr.geneve.opt_len == 6w0x00) {
            transition inner_eth;
        }
        transition geneve_opt;
    }

    state geneve_opt {
        pkt.extract(ingress.curr_opt);
        ingress.geneve_chunks = ingress.geneve_chunks - 6w1;
        // XXX: const GENEVE_OPT_CLASS_OXIDE not recognised here by x4c.
        if (ingress.curr_opt.class == 16w0x0129) { transition geneve_ox_opt; }
        transition reject;
    }

    state geneve_ox_opt {
        if (ingress.curr_opt.rtype == 7w0x00) { transition geneve_opt_external; }
        if (ingress.curr_opt.rtype == 7w0x01) { transition geneve_opt_mcast; }
        if (ingress.curr_opt.rtype == 7w0x02) { transition geneve_opt_mss; }

        transition reject;
    }

    state geneve_opt_external {
        if (ingress.curr_opt.opt_len != 5w0) { transition reject; }
        hdr.oxg_external_tag.setValid();
        hdr.oxg_external_tag = ingress.curr_opt;

        transition geneve_opt_done;
    }

    state geneve_opt_mcast {
        if (ingress.curr_opt.opt_len != 5w1) { transition reject; }
        ingress.geneve_chunks = ingress.geneve_chunks - 6w1;
        hdr.oxg_mcast_tag.setValid();
        hdr.oxg_mcast_tag = ingress.curr_opt;
        pkt.extract(hdr.oxg_mcast);

        transition geneve_opt_done;
    }

    state geneve_opt_mss {
        if (ingress.curr_opt.opt_len != 5w1) { transition reject; }
        ingress.geneve_chunks = ingress.geneve_chunks - 6w1;
        hdr.oxg_mss_tag.setValid();
        hdr.oxg_mss_tag = ingress.curr_opt;
        pkt.extract(hdr.oxg_mss);

        transition geneve_opt_done;
    }

    state geneve_opt_done {
        if (ingress.geneve_chunks == 6w0) { transition inner_eth; }
        if (ingress.geneve_chunks > 6w0) { transition geneve_opt; }
        transition reject;
    }

    state inner_eth {
        pkt.extract(hdr.inner_eth);
        if (hdr.inner_eth.ether_type == 16w0x0800) { transition inner_ipv4; }
        if (hdr.inner_eth.ether_type == 16w0x86dd) { transition inner_ipv6; }
        transition reject;
    }

    state inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
        if (hdr.inner_ipv4.protocol == 8w17) { transition inner_udp; }
        if (hdr.inner_ipv4.protocol == 8w6)  { transition inner_tcp; }
        if (hdr.inner_ipv4.protocol == 8w1)  { transition inner_icmp; }
        transition accept;
    }

    state inner_ipv6 {
        pkt.extract(hdr.inner_ipv6);
        if (hdr.inner_ipv6.next_hdr == 8w17) { transition inner_udp; }
        if (hdr.inner_ipv6.next_hdr == 8w6)  { transition inner_tcp; }
        if (hdr.inner_ipv6.next_hdr == 8w58) { transition inner_icmp; }
        transition accept;
    }

    state inner_icmp {
        pkt.extract(hdr.inner_icmp);
        ingress.nat_id = hdr.inner_icmp.identifier;
        transition accept;
    }

    state inner_udp {
        pkt.extract(hdr.inner_udp);
        transition accept;
    }

    state inner_tcp {
        pkt.extract(hdr.inner_tcp);
        transition accept;
    }
}
