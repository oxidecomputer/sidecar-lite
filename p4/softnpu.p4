// Copyright 2026 Oxide Computer Company

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
    bit<1> route_ttl_is_1;
    bool allow_source_mcast;

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
    // Merged replication bitmap.
    //
    // We keep this as separate fields (rather than
    // inlining external_bitmap | underlay_bitmap in the Replicate call)
    // so the post-suppression state is inspectable.
    bit<128> port_bitmap;
    bit<128> external_bitmap;
    bit<128> underlay_bitmap;
}

extern Checksum {
    bit<16> run<T>(in T data);
}

extern Replicate {
    void replicate(in bit<128> bitmap);
}
