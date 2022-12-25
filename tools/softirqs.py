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
parser.add_argument