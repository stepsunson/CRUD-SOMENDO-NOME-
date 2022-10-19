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
parser.add_argument("-T", "--notimestamp", action="store_tru