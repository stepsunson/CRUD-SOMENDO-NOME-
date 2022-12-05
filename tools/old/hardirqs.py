#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# hardirqs  Summarize hard IRQ (interrupt) event time.
#           For Linux, uses BCC, eBPF.
#
# USAGE: hardirqs [-h] [-T] [-N] [-C] [-d] [interval] [outputs]
#
# Thanks Amer Ather for help understanding irq behavior.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    ./hardirqs            # sum hard irq event time
    ./hardirqs -d         # show hard irq event time as histograms
    ./hardirqs 1 10       # print 1 second summaries, 10 times
    ./hardirqs -NT 1      # 1s summaries, nanoseconds, and timestamps
"""
parser = argparse.ArgumentParser(
    description="Summarize hard irq event time as histograms",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("-C", "--count", action="store_true",
    help="show event counts instead of timing")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("outputs", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.outputs)
if args.count and (args.dist or args.nanoseconds):
    print("The --count option can't be used with time-based options")
    exit()
if args.count:
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
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

typedef struct irq_key {
    char name[32];
    u64 slot;
} irq_key_t;
BPF_HASH(start, u32);
BPF_HASH(irqdesc, u32, struct irq_desc *);
BPF_HISTOGRAM(dist, irq_key_t);

// count IRQ
int count_only(struct pt_regs *ctx, struct irq_desc *desc)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct irqaction *action = desc->action;
    char *name = (char *)action->name;

    irq_key_t key = {.slot = 0 /* ignore */};
    bpf_probe_read_kernel(&key.name, sizeof(key.name), name);
    dist.increment(key);

    return 0;
}

// time IRQ
int trace_start(struct pt_regs *ctx, struct irq_desc *desc)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    irqdesc.update(&pid, &desc);
    return 0;
}

int trace_completion(struct pt_regs *ctx)
{
    u64 *tsp, delta;
    struct irq_desc **descp;
    u32 pid = bpf_get_current_pid_tgid();

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    descp = irqdesc.lookup(&pid);
    if (tsp == 0 || descp == 0) {
       