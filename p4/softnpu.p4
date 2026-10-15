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
    bool allow_source_mcast;
    bool mcast_decap;

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
    // Merged replication bitmap, which is read by the pipeline after ingress.
    //
    // This is `external_bitmap | underlay_bitmap`. Both inputs stay as their
    // own fields, making post-suppression state inspectable.
    bit<128> port_bitmap;
    bit<128> external_bitmap;
    bit<128> underlay_bitmap;
    bit<16> rid;
    bit<128> decap_bitmap;
    bool decap_has_vlan;
    bit<12> decap_vlan_id;
    bit<8> port_number;
    bool port_number_valid;
}

extern Checksum {
    bit<16> run<T>(in T data);
}
