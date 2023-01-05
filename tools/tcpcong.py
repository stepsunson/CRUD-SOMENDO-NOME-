#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpcong  Measure tcp congestion control status duration.
#           For Linux, uses BCC, eBPF.
#
# USAGE: tcpcong [-h] [-T] [-L] [-R] [-m] [-d] [interval] [outputs]
#
# Copyright (c) Ping Gan.
#
# 27-Jan-2022   Ping Gan   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from struct import pack
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse

examples = """examples:
    ./tcpcong                 # show tcp congestion status duration
    ./tcpcong 1 10            # show 1 second summaries, 10 times
    ./tcpcong -L 3000-3006 1  # 1s summaries, local port 3000-3006
    ./tcpcong -R 5000-5005 1  # 1s summaries, remote port 5000-5005
    ./tcpcong -uT 1           # 1s summaries, microseconds, and timestamps
    ./tcpcong -d              # show the duration as histograms
"""

parser = argparse.ArgumentParser(
    description="Summarize tcp socket congestion control status duration",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-L", "--localport",
            help="trace local ports only")
parser.add_argument("-R", "--remoteport",
            help="trace the dest ports only")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="output in microseconds")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("outputs", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.outputs)
debug = 0

start_rport = end_rport = -1
if args.remoteport:
    rports = args.remoteport.split("-")
    if (len(rports) != 2) and (len(rports) != 1):
        print("unrecognized remote port range")
        exit(1)
    if len(rports) == 2:
        start_rport = int(rports[0])
        end_rport = int(rports[1])
    else:
        start_rport = int(rports[0])
        end_rport = int(rports[0])
if start_rport > end_rport:
    tmp = start_rport
    start_rport = end_rport
    end_rport = tmp

start_lport = end_lport = -1
if args.localport:
    lports = args.localport.split("-")
    if (len(lports) != 2) and (len(lports) != 1):
        print("unrecognized local port range")
        exit(1)
    if len(lports) == 2:
        start_lport = int(lports[0])
        end_lport = int(lports[1])
    else:
        start_lport = int(lports[0])
        end_lport = int(lports[0])
if start_lport > end_lport:
    tmp = start_lport
    start_lport = end_lport
    end_lport = tmp

# define BPF program
bpf_head_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

typedef struct ipv4_flow_key {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
} ipv4_flow_key_t;

typedef struct ipv6_flow_key {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
} ipv6_flow_key_t;

typedef struct data_val {
    DEF_TEXT
    u64  last_ts;
    u16  last_cong_stat;
} data_val_t;

BPF_HASH(ipv4_stat, ipv4_flow_key_t, data_val_t);
BPF_HASH(ipv6_stat, ipv6_flow_key_t, data_val_t);

HIST_TABLE
"""

bpf_extra_head = """
typedef struct process_key {
    char comm[TASK_COMM_LEN];
    u32  tid;
} process_key_t;

typedef struct ipv4_flow_val {
    ipv4_flow_key_t ipv4_key;
    u16  cong_state;
} ipv4_flow_val_t;

typedef struct ipv6_flow_val {
    ipv6_flow_key_t ipv6_key;
    u16  cong_state;
} ipv6_flow_val_t;

BPF_HASH(start_ipv4, process_key_t, ipv4_flow_val_t);
BPF_HASH(start_ipv6, process_key_t, ipv6_flow_val_t);
SOCK_STORE_DEF

typedef struct cong {
    u8  cong_stat:5,
        ca_inited:1,
        ca_setsockopt:1,
        ca_dstlocked:1;
} cong_status_t;
"""

bpf_no_ca_tp_body_text = """
static int entry_state_update_func(struct sock *sk)
{
    u16 dport = 0, lport = 0;
    u32 tid = bpf_get_current_pid_tgid();
    process_key_t key = {0};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.tid = tid;

    u64 family = sk->__sk_common.skc_family;
    struct inet_connection_sock *icsk = inet_csk(sk);
    cong_status_t cong_status;
    bpf_probe_read_kernel(&cong_status, sizeof(cong_status),
        (void *)((long)&icsk->icsk_retransmits) - 1);
    if (family == AF_INET) {
        ipv4_flow_val_t ipv4_val = {0};
        ipv4_val.ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_val.ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_val.ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        dport = ntohs(dport);
        lport = ipv4_val.ipv4_key.lport;
        FILTER_LPORT
        FILTER_DPORT
        ipv4_val.ipv4_key.dport = dport;
        ipv4_val.cong_state = cong_status.cong_stat + 1;
        start_ipv4.update(&key, &ipv4_val);
    } else if (family == AF_INET6) {
        ipv6_flow_val_t ipv6_val = {0};
        bpf_probe_read_kernel(&ipv6_val.ipv6_key.saddr,
            sizeof(ipv6_val.ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_val.ipv6_key.daddr,
            sizeof(ipv6_val.ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_val.ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        dport = ntohs(dport);
        lport = ipv6_val.ipv6_key.lport;
        FILTER_LPORT
        FILTER_DPORT
        ipv6_val.ipv6_key.dport = dport;
        ipv6_val.cong_state = cong_status.cong_stat + 1;
        start_ipv6.update(&key, &ipv6_val);
    }
    SOCK_STORE_ADD
    return 0;
}

static int ret_state_update_func(struct sock *sk)
{
    u64 ts, ts1;
    u16 family, last_cong_state;
    u16 dport = 0, lport = 0;
    u32 tid = bpf_get_current_pid_tgid();
    process_key_t key = {0};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.tid = tid;

    struct inet_connection_sock *icsk = inet_csk(sk);
    cong_status_t cong_status;
    bpf_probe_read_kernel(&cong_status, sizeof(cong_status),
        (void *)((long)&icsk->icsk_retransmits) - 1);
    data_val_t *datap, data = {0};
    STATE_KEY
    bpf_probe_read_kernel(&family, sizeof(family),
        &sk->__sk_common.skc_family);
    if (family == AF_INET) {
        ipv4_flow_val_t *val4 = start_ipv4.lookup(&key);
        if (val4 == 0) {
            SOCK_STORE_DEL
            return 0; //missed
        }
        ipv4_flow_key_t keyv4 = {0};
        bpf_probe_read_kernel(&keyv4, sizeof(ipv4_flow_key_t),
            &(val4->ipv4_key));
        dport = keyv4.dport;
        lport = keyv4.lport;
        FILTER_LPORT
        FILTER_DPORT
        datap = ipv4_stat.lookup(&keyv4);
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = val4->cong_state;
            ipv4_stat.update(&keyv4, &data);
        } else {
            last_cong_state = val4->cong_state;
            if ((cong_status.cong_stat + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = cong_status.cong_stat + 1;
                ts /= 1000;
                STORE
            }
        }
        start_ipv4.delete(&key);
    } else if (family == AF_INET6) {
        ipv6_flow_val_t *val6 = start_ipv6.lookup(&key);
        if (val6 == 0) {
            SOCK_STORE_DEL
            return 0; //missed
        }
        ipv6_flow_key_t keyv6 = {0};
        bpf_probe_read_kernel(&keyv6, sizeof(ipv6_flow_key_t),
            &(val6->ipv6_key));
        dport = keyv6.dport;
        lport = keyv6.lport;
        FILTER_LPORT
        FILTER_DPORT
        datap = ipv6_stat.lookup(&keyv6);
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = val6->cong_state;
            ipv6_stat.update(&keyv6, &data);
        } else {
    