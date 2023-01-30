#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpretrans    Trace or count TCP retransmits and TLPs.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpretrans [-c] [-h] [-l] [-4 | -6]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.
# 03-Nov-2017   Matthias Tafelmeier Extended this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep

# arguments
examples = """examples:
    ./tcpretrans           # trace TCP retransmits
    ./tcpretrans -l        # include TLP attempts
    ./tcpretrans -4        # trace IPv4 family only
    ./tcpretrans -6        # trace IPv6 family only
"""
parser = argparse.ArgumentParser(
    description="Trace TCP retransmits",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-s", "--sequence", action="store_true",
    help="display TCP sequence numbers")
parser.add_argument("-l", "--lossprobe", action="store_true",
    help="include tail loss probe attempts")
parser.add_argument("-c", "--count", action="store_true",
    help="count occurred retransmits per flow")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <bcc/proto.h>

#define RETRANSMIT  1
#define TLP         2

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u64 ip;
    u32 seq;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u32 seq;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv6_events);

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);
"""

bpf_text_kprobe = """
static int trace_event(struct pt_regs *ctx, struct sock *skp, struct sk_buff *skb, int type)
{
    struct tcp_skb_cb *tcb;
    u32 seq;

    if (skp == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // pull in details
    u16 family = skp->__sk_common.skc_family;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    char state = skp->__sk_common.skc_state;

    seq = 0;
    if (skb) {
        /* macro TCP_SKB_CB from net/tcp.h */
        tcb = ((struct tcp_skb_cb *)&((skb)->cb[0]));
        seq = tcb->seq;
    }

    FILTER_FAMILY

    if (family == AF_INET) {
        IPV4_INIT
        IPV4_CORE
    } else if (family == AF_INET6) {
        IPV6_INIT
        IPV6_CORE
    }
    // else drop

    return 0;
}
"""

bpf_text_kprobe_retransmit = """
int trace_retransmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    trace_event(ctx, sk, skb, RETRANSMIT);
    return 0;
}
"""

bpf_text_kprobe_tlp = """
int trace_tlp(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, NULL, TLP);
    return 0;
}
"""

bpf_text_tracepoint = """
TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
    struct tcp_skb_cb *tcb;
    u32 seq;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    const struct sock *skp = (const struct sock *)args->skaddr;
    const struct sk_buff *skb = (const struct sk_buff *)args->skbaddr;
    u16 lport = args->sport;
    u16 dport = args->dport;
    char state = skp->__sk_common.skc_state;
    u16 family = skp->__sk_common.skc_family;

    seq = 0;
    if (skb) {
        /* macro TCP_SKB_CB from net/tcp.h */
        tcb = ((struct tcp_skb_cb *)&((skb)->cb[0]));
        seq = tcb->seq;
    }

    FILTER_FAMILY

    if (family == AF_INET) {
        IPV4_CODE
    } else if (family == AF_INET6) {
        IPV6_CODE
    }
    return 0;
}
"""

struct_init = { 'ipv4':
        { 'count' :
            """
               struct ipv4_flow_key_t flow_key = {};
               flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
               flow_key.daddr = skp->__sk_common.skc_daddr;
               // lport is host order
               flow_key.lport = lport;
               flow_key.dport = ntohs(dport);""",
               'trace' :
               """
               struct ipv4_data_t data4 = {};
               data4.pid = pid;
               data4.ip = 4;
               data4.seq = seq;
               data4.type = type;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               // lport is host order
               data4.lport = lport;
               data4.dport = ntohs(dport);
               data4.state = state; """
               },
        'ipv6':
        { 'count' :
            """
                    struct ipv6_flow_key_t flow_key = {};
                    bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read_kernel(&flow_key.daddr, sizeof(flow_key.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    flow_key.lport = lport;
                    flow_key.dport = ntohs(dport);""",
          'trace' : """
                    struct ipv6_data_t data6 = {};
                    data6.pid = pid;
                    data6.ip = 6;
                    data6.seq = seq;
                    data6.type = type;
                    bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    data6.lport = lport;
                    data6.dport = ntohs(dport);
                    data6.state = state;"""
                }
        }

struct_init_tracepoint = { 'ipv4':
        { 'count' : """
               struct ipv4_flow_key_t flow_key = {};
               __builtin_memcpy(&flow_key.saddr, args->saddr, sizeof(flow_key.saddr));
               __builtin_memcpy(&flow_key.daddr, args->daddr, sizeof(flow_key.daddr));
               flow_key.lport = lport;
               flow_key.dport = dport;
               ipv4_count.increment(flow_key);
               """,
          'trace' : """
               struct ipv4_data_t data4 = {};
               data4.pid = pid;
               data4.lport = lport;
               data4.dport = dport;
               data4.type = RETRANSMIT;
               data4.ip = 4;
               data4.seq = seq;
               data4.state = state;
               __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
               __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
               ipv4_events.perf_submit(args, &data4, sizeof(data4));
               """
               },
        'ipv6':
        { 'count' : """
               struct ipv6_flow_key_t flow_key = {};
               __builtin_memcpy(&flow_key.saddr, args->saddr_v6, sizeof(flow_key.saddr));
               __builtin_memcpy(&flow_key.daddr, args->daddr_v6, sizeof(flow_key.daddr));
               flow_key.lport = lport;
               flow_key.dport = dport;
               ipv6_count.increment(flow_key);
               """,
          'trace' : """
               struct ipv6_data_t data6 = {};
               data6.pid = pid;
               data6.lport = lport;
               data6.dport = dport;
               data6.type = RETRANSMIT;
               data6.ip = 6;
               data6.seq = seq;
               data6.state = state;
               __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
               __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
               ipv6_events.perf_submit(args, &data6, sizeof(data6));
               """
               }
        }

count_core_base = """
        COUNT_STRUCT.increment(flow_key);
"""

if BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
    if args.count:
        bpf_text_tracepoint = bpf_text_tracepoint.replace("IPV4_CODE", struct_init_tracepoint['ipv4']['count'])
        bpf_text_tracepoint = bpf_text_tracepoint.replace("IPV6_CODE", struct_init_tracepoint['ipv6']['count'])
    else:
        bpf_text_tracepoint = bpf_text_tracepoint.replace("IPV4_CODE", struct_i