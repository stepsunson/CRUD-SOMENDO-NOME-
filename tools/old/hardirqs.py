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
    help="include timestam