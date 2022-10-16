#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# biotop  block device (disk) I/O by process.
#         For Linux, uses BCC, eBPF.
#
# USAGE: biotop.py [-h] [-C] [-r MAXROWS] [-p PID] [interval] [count]
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Feb-2016   Brendan Gregg   Created this.
# 17-Mar-2022   Rocky Xing      Added PID filter support.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
from subprocess import call

# arguments
examples = """examples:
    ./biotop            # block device I/O top, 1 second refresh
    ./biotop -C         # don't clear the screen
    ./biotop -p 181     # only trace PID 181
    ./biotop 5          # 5 second summaries
    ./biotop 5 10       # 5 second summaries, 10 times only
"""
parser = argparse.ArgumentParser(
    description="Block device (disk) I/O by process",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
    help="maximum rows to print, default 20")
parser.add_argument("-p", "--pid", type=int, metavar="PID",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
interval = int(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear)

# linux stats
loadavg = "/proc/loadavg"
diskstats = "/proc/diskstats"

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

// for saving the timestamp and __data_len of each request
struct start_req_t {
    u64 ts;
    u64 data_len;
};

// for saving process info by request
struct who_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

// the key for the output summary
struct info_t {
    u32 pid;
    int rwflag;
    int major;
    int minor;
    char name[TASK_COMM_LEN];
};

// the value of the output summary
struct val_t {
    u64 bytes;
    u64 us;
    u32 io;
};

BPF_HASH(start, struct request *, struct start_req_t);
BPF_HASH(whobyreq, struct request *, struct who_t);
BPF_HASH(counts, struct info_t, struct val_t);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct who_t who = {};
    u32 pid;

    if (bpf_get_current_comm(&who.name, sizeof(who.name)) == 0) {
        pid = bpf_get_current_pid_tgid() >> 32;
        if (FILTER_PID)
            return 0;

        who.pid = pid;
        whobyreq.update(&req, &who);
    }

    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len
    };
    start.update(&req, &start_req);
    return 0;
}

// output
int trace_req_comp