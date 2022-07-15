// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

#define _memcpy __builtin_memcpy

// meta data passed between bpf programs
typedef struct bpf_metadata {
    u32 prog_id;
    u32 rx_port_id;
} bpf_metadata_t;

typedef struct bpf_dest {
    u32 prog_id;
    u32 port_id;
} bpf_dest_t;

// use u64 to represent eth_addr.
// maintain the structure though to indicate the semantics
typedef struct eth_addr {
    u64 addr;
} eth_addr_t;

// Program table definitions for tail calls
BPF_PROG_ARRAY(jump, 16);

// physical endpoint manager (pem) tables which connects to boeht bridge 1 and bridge 2
// <port_id, bpf_dest>
BPF_ARRAY(pem_dest, bpf_dest_t, 256);
// <port_id, ifindex>
BPF_ARRAY(pem_port, u32, 256);
// <ifindex, port_id>
BPF_HASH(pem_ifindex, u32, u32, 256);
// <0, tx2vm_pkts>
BPF_ARRAY(pem_stats, u32, 1);

// bridge 1 (br1) tables
// <port_id, bpf_dest>
BPF_ARRAY(br1_dest, bpf_dest_t, 256);
// <eth_addr, port_id>
BPF_HASH(br1_mac, eth_addr_t, u32, 256);
// <0, rtr_ifindex>
BPF_ARRAY(br1_rtr, u32, 1);
// <mac, ifindex>
BPF_HASH(br1_mac_ifindex, eth_addr_t, u32, 1);

// bridge 2 (br2) tables
// <port_id, bpf_dest>
BPF_ARRAY(br2_dest, bpf_dest_t, 256);
// <eth_addr, port_id>
BPF_HASH(br2_mac, eth_addr_t, u32, 256);
// <0, rtr_ifindex>
BPF_ARRAY(br2_rtr, u32, 1);
// <mac, ifindex>
BPF_HASH(br2_mac_ifi