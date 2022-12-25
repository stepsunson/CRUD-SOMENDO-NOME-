#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# softirqs  Summarize soft IRQ (interrupt) event time.
#           For Linux, uses BCC, eBPF.
#
# USAGE: softirqs [-h] [-T] [-N] [-C] [-d] [-c CPU] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Oct-2015   Brendan Gregg     Created this.
# 03-Apr-2017   Sasha Goldshtein  Migrated to kernel tracepoints.
# 07-Mar-2022   Rocky Xing        Added CPU filter support.
# 24-Mar-2022   Rocky Xing        Added event counting support.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import sys

# arguments
examples = """examples:
    ./softirqs            # sum soft irq event time
    ./softirqs -C         # show the number of soft irq events
    ./softirqs -d         # show soft irq event time as histograms
    ./softirqs 1 10       # print 1 second summaries, 10 times
    ./softirqs -NT 1      # 1s summaries, nanoseconds, and timestamps
    ./softirqs -c 1       # sum soft irq event time on CPU 1 only
"""
parser = argparse.ArgumentParser(
    description="Summarize soft irq event time as histograms.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("-C", "--events", action="store_true",
    help="show the number of soft irq events")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-c", "--cpu", type=int,
    help="trace this CPU only")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
if args.events and (args.dist or args.nanoseconds):
    print("The --events option can't be used with time-based options")
    exit()
if args.events:
    factor = 1
    label = "count"
elif args.nanoseconds:
    factor = 1
    label = "nsecs"
else:
    factor = 1000
    label = "usecs"
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

typedef struct entry_key {
    u32 pid;
    u32 cpu;
} entry_key_t;

typedef struct irq_key {
    u32 vec;
    u64 slot;
} irq_key_t;

typedef struct account_val {
    u64 ts;
    u32 vec;
} account_val_t;

BPF_HASH(start, entry_key_t, account_val_t);
BPF_HISTOGRAM(dist, irq_key_t);
"""

bpf_text_count = """
TRACEPOINT_PROBE(irq, softirq_entry)
{
    u32 cpu = bpf_get_smp_processor_id();

    FILTER_CPU

    irq_key_t key = { .slot = 0 /* ignore */ };
    key.vec = args->vec;

    dist.atomic_increment(key);

    return 0;
}
"""

bpf_text_time = """
TRACEPOINT_PROBE(irq, softirq_entry)
{
    account_val_t val = {};
    entry_key_t key = {};
    u32 cpu = bpf_get_smp_processor_id();

    FILTER_CPU

    key.pid = bpf_get_current_pid_tgid();
    key.cpu = cpu;
    val.ts = bpf_ktime_get_ns();
    val.vec = args->vec;

    start.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(irq, softirq_exit)
{
    u64 delta;
    u32 vec;
    account_val_t *valp;
    irq_key_t key = {0};
    entry_key_t entry_key = {};
    u32 cpu = bpf_get_smp_processor_id();

    FILTER_CPU

    entry_key.pid = bpf_get_current_pid_tgid();
    entry_key.cpu = cpu;

    // fetch timestamp and calculate delta
    valp = start.lookup(&entry_key);
    if (valp == 0) {
        return 0;   // missed start
    }
    delta = bpf_ktime_get_ns() - valp->ts;
    vec = valp->vec;

    // store as sum or histogram
    STORE

    start.delete(&entry_k