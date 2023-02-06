#!/usr/bin/env python
#
# tcpv4tracer   Trace TCP connections.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4tracer [-h] [-v] [-p PID] [-N NETNS] [-4 | -6]
#
# You should generally try to avoid writing long scripts that measure multiple
# functions and walk multiple kernel structures, as they will be a burden to
# maintain as the kernel changes.
# The following code should be replaced, and simplified, when static TCP probes
# exist.
#
# Copyright 2017-2020 Kinvolk GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License")
from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers

import argparse as ap
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

parser = ap.ArgumentParser(description="Trace TCP connections",
                           formatter_class=ap.RawDescriptionHelpFormatter)
parser.add_argument("-t", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-p", "--pid", default=0, type=int,
                    help="trace this PID only")
parser.add_argument("-N", "--netns", default=0, type=int,
                    help="trace this Network Namespace only")
parser.add_argument("--cgroupmap",
                    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
                    help="trace mount namespaces in this BPF map only")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
                    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
                   help="trace IPv6 family only")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="include Network Namespace in the output")
parser.add_argument("--ebpf", action="store_true",
                    help=ap.SUPPRESS)
args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

#define TCP_EVENT_TYPE_CONNECT 1
#define TCP_EVENT_TYPE_ACCEPT  2
#define TCP_EVENT_TYPE_CLOSE   3

struct tcp_ipv4_event_t {
    u64 ts_ns;
    u32 type;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8 ip;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};
BPF_PERF_OUTPUT(tcp_ipv4_event);

struct tcp_ipv6_event_t {
    u64 ts_ns;
    u32 type;
    u32 pid;
    char comm[TASK_COMM_LEN];
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
    u8 ip;
};
BPF_PERF_OUTPUT(tcp_ipv6_event);

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};

struct ipv6_tuple_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};

struct pid_comm_t {
    u64 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(tuplepid_ipv4, struct ipv4_tuple_t, struct pid_comm_t);
BPF_HASH(tuplepid_ipv6, struct ipv6_tuple_t, struct pid_comm_t);

BPF_HASH(connectsock, u64, struct sock *);

static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp)
{
  u32 net_ns_inum = 0;
  u32 saddr = skp->__sk_common.skc_rcv_saddr;
  u32 daddr = skp->__sk_common.skc_daddr;
  struct inet_sock *sockp = (struct inet_sock *)skp;
  u16 sport = sockp->inet_sport;
  u16 dport = skp->__sk_common.skc_dport;
#ifdef CONFIG_NET_NS
  net_ns_inum = skp->__sk_common.skc_net.net->ns.inum;
#endif

  ##FILTER_NETNS##

  tuple->saddr = saddr;
  tuple->daddr = daddr;
  tuple->sport = sport;
  tuple->dport = dport;
  tuple->netns = net_ns_inum;

  // if addresses or ports are 0, ignore
  if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
      return 0;
  }

  return 1;
}

static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct sock *skp)
{
  u32 net_ns_inum = 0;
  unsigned __int128 saddr = 0, daddr = 0;
  struct inet_sock *sockp = (struct inet_sock *)skp;
  u16 sport = sockp->inet_sport;
  u16 dport = skp->__sk_common.skc_dport;
#ifdef CONFIG_NET_NS
  net_ns_inum = skp->__sk_common.skc_net.net->ns.inum;
#endif
  bpf_probe_read_kernel(&saddr, sizeof(saddr),
                 skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
  bpf_probe_read_kernel(&daddr, sizeof(daddr),
                 skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

  ##FILTER_NETNS##

  tuple->saddr = saddr;
  tuple->daddr = daddr;
  tuple->sport = sport;
  tuple->dport = dport;
  tuple->netns = net_ns_inum;

  // if addresses or ports are 0, ignore
  if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
      return 0;
  }

  return 1;
}

static bool check_family(struct sock *sk, u16 expected_family) {
  u64 zero = 0;
  u16 family = sk->__sk_common.skc_family;
  return family == expected_family;
}

int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
{
  if (container_should_be_filtered()) {
    return 0;
  }

  u64 pid = bpf_get_current_pid_tgid();

  ##FILTER_PID##
  
  u16 family = sk->__sk_common.skc_family;
  ##FILTER_FAMILY##


  // stash the sock ptr for lookup on return
  connectsock.update(&pid, &sk);

  return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
  int ret = PT_REGS_RC(ctx);
  u64 pid = bpf_get_current_pid_tgid();

  struct sock **skpp;
  skpp = connectsock.lookup(&pid);
  if (skpp == 0) {
      return 0;       // missed entry
  }

  connectsock.delete(&pid);

  if (ret != 0) {
      // failed to send SYNC packet, may not have populated
      // socket __sk_common.{skc_rcv_saddr, ...}
      return 0;
  }

  // pull in details
  struct sock *skp = *skpp;
  struct ipv4_tuple_t t = { };
  if (!read_i