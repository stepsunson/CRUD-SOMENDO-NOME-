#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# softirqs  Summarize soft IRQ (interrupt) event time.
#           For Linux, uses BCC, eBPF.
#
# USAGE: softirqs [-h] [-T] [-N] [-d] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Oct-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    ./softirqs            # sum soft irq event time
    ./softirqs -d         # show soft irq event time as histograms
    ./softirqs 1 10       # print 1 second summaries, 10 times
    ./softirqs -NT 1      # 1s summaries, nanoseconds, and timestamps
"""
parser = argparse.ArgumentParser(
    description="Summarize soft irq event time as histograms",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-C", "--bycpu", action="store_true",
    help="break down softirqs to individual cpus")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
args = parser.parse_args()
countdown = int(args.count)
if args.nanoseconds:
    factor = 1
    label = "nsecs"
else:
    factor = 1000
    label = "usecs"
debug = 0

# define BPF program
bpf_text = ""
if args.bycpu:
    bpf_text = """
    #include <uapi/linux/ptrace.h>

    typedef struct irq_cpu_key {
        s64 cpu;
        u6