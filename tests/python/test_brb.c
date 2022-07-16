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
BPF_HASH(br2_mac_ifindex, eth_addr_t, u32, 1);

int pem(struct __sk_buff *skb) {
    bpf_metadata_t meta = {};
    u32 ifindex;
    u32 *tx_port_id_p;
    u32 tx_port_id;
    u32 rx_port;
    u32 *ifindex_p;
    bpf_dest_t *dest_p;

    // pem does not look at packet data
    if (skb->tc_index == 0) {
        skb->tc_index = 1;
        skb->cb[0] = skb->cb[1] = 0;
        meta.prog_id = meta.rx_port_id = 0;
    } else {
        meta.prog_id = skb->cb[0];
        asm volatile("" ::: "memory");
        meta.rx_port_id = skb->cb[1];
    }
    if (!meta.prog_id) {
        /* from external */
        ifindex = skb->ingress_ifindex;
        tx_port_id_p = pem_ifindex.lookup(&ifindex);
        if (tx_port_id_p) {
            tx_port_id = *tx_port_id_p;
            dest_p = pem_dest.lookup(&tx_port_id);
            if (dest_p) {
                skb->cb[0] = dest_p->prog_id;
                skb->cb[1] = dest_p->port_id;
                jump.call(skb, dest_p->prog_id);
            }
        }
    } else {
        /* from internal */
        rx_port = meta.rx_port_id;
        ifindex_p = pem_port.lookup(&rx_port);
        if (ifindex_p) {
#if 1
            /* accumulate stats, may hurt performance slightly */
            u32 index = 0;
            u32 *value = pem_stats.lookup(&index);
            if (value)
                lock_xadd(value, 1);
#endif
            bpf_clone_redirect(skb, *ifindex_p, 0);
        }
    }

    return 1;
}

static int br_common(struct __sk_buff *skb, int which_br) {
    u8 *cursor = 0;
    u16 proto;
    u16 arpop;
    eth_addr_t dmac;
    u8 *mac_p;
    u32 dip;
    u32 *tx_port_id_p;
    u32 tx_port_id;
    bpf_dest_t *dest_p;
    u32 index, *rtrif_p;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    /* handle ethernet packet header */
    {
        dmac.addr = ethernet->dst;
        /* skb->tc_index may be preserved across router namespace if router simply rewrite packet
         * and send it back.
         */
        if (skb->tc_index == 1) {
            /* packet from pem, send to the router, set tc_index to 2 */
          