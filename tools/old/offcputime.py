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
maxdepth = 20    # and MAXDEPT