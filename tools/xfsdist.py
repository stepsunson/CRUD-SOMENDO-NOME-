#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# xfsdist  Summarize XFS operation latency.
#          For Linux, uses BCC, eBPF.
#
# USAGE: xfsdist [-h] [-T] [-m] [-p PID] [interval] [count]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    ./xfsdist            # show operation latency as a histogram
    ./xfsdist -p 181     # trace PID 181 only
    ./xfsdist 1 10       # print 1 second summaries, 10 times
    ./xfsdist -m 5       # 5s summaries, milliseconds
"""
parser = argparse.ArgumentParser(
    description="Summarize XFS operation latency",
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