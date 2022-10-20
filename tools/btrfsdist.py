#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# btrfsdist  Summarize btrfs operation latency.
#            For Linux, uses BCC, eBPF.
#
# USAGE: btrfsdist [-h] [-T] [-m] [-p PID] [interval] [count]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# symbols
kallsyms = "/proc/kallsyms"

# arguments
examples = """examples:
    ./btrfsdist            # show operation latency as a histogram
    ./btrfsdist -p 181     # trace PID 181 only
    ./btrfsdist 1 10       # print 1 second summaries, 10 times
    ./btrfsdist -m 5       # 5s summaries, milliseconds
"""
parser = argparse.ArgumentParser(
    description="Summarize btrfs operation latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--notimestamp", action="store_true",
    help="don't include timestamp on interval output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="output in milliseconds")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?",
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
pid = args.pid
countdown = int(args.count)
if args.milliseconds:
    factor = 1000000
    label = "msecs"
else:
    factor = 1000
    label = "usecs"
if args.interval and int(args.interval) == 0:
    print("ERROR: interval 0. Exiting.")
    exit()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

#define OP_NAME_LEN 8
typedef struct dist_key {
    char op[OP_NAME_LEN];
    u64 slot;
} dist_key_t;
BPF_HASH(start, u32);
BPF_HISTOGRAM(dist, dist_key_t);

// time operation
int trace_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (FILTER_PID)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&tid, &ts);
    return 0;
}

// The current btrfs (Linux 4.5) uses generic_file_read_iter() instead of it's
// own read function. So we need to trace that and then filter on btrfs, which
// I do by checking file->f_op.
int trace_read_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (FILTER_PID)
        return 0;

    // btrfs filter on file->f_op == btrfs_file_operations
    struct file *fp = iocb->ki_filp;
    if ((u64)fp->f_op != BTRFS_FILE_OPERATIONS)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    start.update(&tid, &ts);
    return 0;
}

// The current btrfs (Linux 4.5) uses generic_file_open(), instead of it's own
// function. Same as with reads. Trace the generic path and filter:
