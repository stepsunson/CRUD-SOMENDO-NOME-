#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpaccept Trace TCP accept()s.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpaccept [-h] [-t] [-p PID]
#
# This uses dynamic tracing of the kernel inet_csk_accept() socket function
# (from tcp_prot.accept), and will need to be modified to match kernel changes.
#
# IPv4 addresses are printed as dotted quads. For IPv6 addresses, the last four
# bytes are printed after "..."; check for future versions with better IPv6
# support.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Oct-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./tcpaccept           # trace all TCP accept()s
    ./tcpaccept -t        # include timestamps
    ./tcpaccept -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace TCP accepts",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()
debug = 0

# define BP