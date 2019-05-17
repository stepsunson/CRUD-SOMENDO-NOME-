// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

BPF_HASH(vni2if, u32, int, 1024);

struct vni_key {
  u64 mac;
  int ifindex;
  int pad;
};
struct host {
  u32 tunnel_id;
  u32 remote_ipv4;
  u64 rx_pkts;
  u64 tx_pkts;
};
BPF_HASH(mac2host, struct vni_key, struct host);

struct config {
  int tunnel_ifindex;
};
BPF_HASH(conf, int, struct config, 1);

// Handle packets from the encap device, demux into the dest tenant
int handle_ingress(struct __sk_buff *skb) {
  u8 *cursor = 0;

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

  struct bpf_tunnel_key tkey = {};
  bpf_skb_get_tunnel_key(skb, &tkey,
      offsetof(struct bpf_tunnel_key, remote_ipv6[1]), 0);

  int *ifindex = vni2if.lookup(&tkey.tunnel_id);
  if (ifindex) {
    //bpf_trace_printk("ingress tunnel_id=%d ifindex=%d\n", tkey.tunnel_id, *ifindex);
    struct vni_key vk = {ethernet->src, *ifindex, 0};
    struct host *src_host = mac2host.lookup_or_try_init(&vk,
        &(struct host){tkey.tunnel_id, tkey.remote_ipv4, 0, 0});
    if (src_host) {
      lock_xadd(&src_host->rx_pkts, 1);
    }
    bpf_clone_redirect(skb, *ifindex, 1/*ingress*/);
  } else {
    bpf_trace_printk("ingress invalid tunnel_id=%d\n", tkey