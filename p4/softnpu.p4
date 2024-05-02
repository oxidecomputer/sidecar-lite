// Copyright 2022 Oxide Computer Company

struct ingress_metadata_t {
    bit<16> port;
    bool nat;
    bit<16> nat_id;
    bit<16> path_idx;
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
