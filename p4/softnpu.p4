// Copyright 2022 Oxide Computer Company

#include <headers.p4>

struct ingress_metadata_t {
    bit<128> forward_tgt;
    bit<24> forward_vni;
    bit<48> forward_mac;
    bit<16> port;
    bit<16> nat_id;
    bit<16> path_idx;
    bool forward_needed;
    bool lldp;

    // Used as mutable scratchpad shared between parser states.
    bit<6> geneve_chunks;
    geneve_opt_h curr_opt;
}

struct egress_metadata_t {
    bit<16> port;
    bit<128> nexthop_v6;
    bit<32> nexthop_v4;
    bit<12> vlan_id;
    bool drop;
    bool broadcast;
}

extern Checksum {
    bit<16> run<T>(in T data);
}
