#!/usr/bin/python
#
# offcputime    Summarize off-CPU time by kernel stack trace
#               For Linux, uses BCC, eBPF.
#
# USAGE: offcputime [-h] [-u] [-p PID] [-v] [-f] [duration]
#
# The current implementation uses an unrolled loop for x86_64, and was written
# as a proof of concept. This implementation should be replaced in the future
# with an appropriate bpf_ call, when available.
#
# Currently limited to a stack trace depth of 21 (maxdepth + 1).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jan-2016	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    ./offcputime             # trace off-CPU stack time until Ctrl-C
    ./offcputime 5           # trace for 5 seconds only
    ./offcputime -f 5        # 5 seconds, and output in folded format
    ./offcputime -u          # don't include kernel threads (user only)
    ./offcputime -p 185      # trace fo PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Summarize off-CPU time by kernel stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-u", "--useronly", action="store_true",
    help="user threads only (no kernel threads)")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-v", "--verbose", action="store_true",
    help="show raw addresses")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format")
parser.add_argument("duration", nargs="?", default=99999999,
    help="duration of trace, in seconds")
args = parser.parse_args()
folded = args.folded
duration = int(args.duration)
debug = 0
maxdepth = 20    # and MAXDEPTH
if args.pid and args.useronly:
    print("ERROR: use either -p or -u.")
    exit()

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAXDEPTH	20
#define MINBLOCK_US	1

struct key_t {
    char name[TASK_COMM_LEN];
    // Skip saving the ip
    u64 ret[MAXDEPTH];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);

static u64 get_frame(u64 *bp) {
    if (*bp) {
        // The following stack walker is x86_64 specific
        u64 ret = 0;
        if (bpf_probe_read(&ret, sizeof(ret), (void *)(*bp+8)))
            return 0;
        if (bpf_probe_read(bp, sizeof(*bp), (void *)*bp))
            *bp = 0;
        if (ret < __START_KERNEL_map)
            return 0;
        return ret;
    }
    return 0;
}

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if (FILTER) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // calculate current thread's delta time
    pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);
    if (tsp == 0)
        return 0;        // missed start or filtered
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if (delta < MINBLOCK_US)
        return 0;

    // create map key
    u64 zero = 0, *val, bp = 0;
    int depth = 0;
    struct key_t key = {};
    bpf_get_current_comm(&key.name, sizeof(key.name));
    bp = ctx->bp;

    // unrolled loop (MAXDEPTH):
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!