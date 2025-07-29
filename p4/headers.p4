// Copyright 2025 Oxide Computer Company

header sidecar_h {
    bit<8> sc_code;
    bit<8> sc_pad;
    bit<16> sc_ingress;
    bit<16> sc_egress;
    bit<16> sc_ether_type;
    bit<128> sc_payload;
}

header ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ether_type;
}

header vlan_h {
    bit<3> pcp;
    bit<1> dei;
    bit<12> vid;
    bit<16> ether_type;
}

header ipv6_h {
    bit<4>      version;
    bit<8>      traffic_class;
    bit<20>     flow_label;
    bit<16>     payload_len;
    bit<8>      next_hdr;
    bit<8>      hop_limit;
    bit<128>    src;
    bit<128>    dst;
}

header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    bit<32>     src;
    bit<32>     dst;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header icmp_h {
    bit<8> type;
    bit<8> code;
    bit<16> hdr_checksum;
    bit<16> identifier;
    bit<16> seq;
}

header geneve_h {
    bit<2> version;
    bit<6> opt_len;
    bit<1> ctrl;
    bit<1> crit;
    bit<6> reserved;
    bit<16> protocol;
    bit<24> vni;
    bit<8> reserved2;
}

header geneve_opt_h {
    bit<16> class;
    bit<1> crit;
    bit<7> rtype;
    bit<3> reserved;
    bit<5> opt_len;
}

header oxg_opt_multicast_h {
    bit<2> replication;
    bit<30> reserved;
}

header oxg_opt_mss_h {
    bit<32> mss;
}

header arp_h {
	bit<16>		hw_type;
	bit<16>		proto_type;
	bit<8>		hw_addr_len;
	bit<8>		proto_addr_len;
	bit<16>		opcode;

	// In theory, the remaining fields should be <varbit>
	// based on the the two x_len fields.
	bit<48> sender_mac;
	bit<32> sender_ip;
	bit<48> target_mac;
	bit<32> target_ip;
}

header ddm_h {
    bit<8> next_header;
    bit<8> header_length;
    bit<8> version;
    bit<1> ack;
    bit<7> reserved;
}

header ddm_element_t {
    bit<8> id;
    bit<24> timestamp;
}

struct headers_t {
    ethernet_h ethernet;
    sidecar_h sidecar;
    vlan_h vlan;
    arp_h arp;
    ipv4_h ipv4;
    ipv6_h ipv6;

    ddm_h ddm;
    // The ddm original p4 code used a header stack, but Intel says this is not
    // efficient on Tofino, and x4c does not currently support header stacks. So
    // the following is an unrolled version. This is not easy on the eyes.
    ddm_element_t ddm0;
    ddm_element_t ddm1;
    ddm_element_t ddm2;
    ddm_element_t ddm3;
    ddm_element_t ddm4;
    ddm_element_t ddm5;
    ddm_element_t ddm6;
    ddm_element_t ddm7;
    ddm_element_t ddm8;
    ddm_element_t ddm9;
    ddm_element_t ddm10;
    ddm_element_t ddm11;
    ddm_element_t ddm12;
    ddm_element_t ddm13;
    ddm_element_t ddm14;
    ddm_element_t ddm15;

    icmp_h icmp;
    tcp_h tcp;
    udp_h udp;

    // As above, x4c does not support header stacks. We're assuming that OPTE
    // and SoftNPU will, for now, push at most one option. Sidecar also makes
    // the same assumption.
    geneve_h geneve;
    geneve_opt_h ox_opt_tag;
    oxg_opt_multicast_h ox_mcast_body;
    oxg_opt_mss_h ox_mss_body;

    ethernet_h inner_eth;
    ipv4_h inner_ipv4;
    ipv6_h inner_ipv6;
    icmp_h inner_icmp;
    tcp_h inner_tcp;
    udp_h inner_udp;
}
