
#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpdrop   Trace TCP kernel-dropped packets/segments.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# This provides information such as packet details, socket state, and kernel
# stack trace for packets/segments that were dropped via tcp_drop().
#
# USAGE: tcpdrop [-4 | -6] [-h]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2018 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-May-2018   Brendan Gregg   Created this.
# 15-Jun-2022   Rong Tao        Add tracepoint:skb:kfree_skb

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep
from bcc import tcp

# arguments
examples = """examples:
    ./tcpdrop           # trace kernel TCP drops
    ./tcpdrop -4        # trace IPv4 family only
    ./tcpdrop -6        # trace IPv6 family only
"""
parser = argparse.ArgumentParser(
    description="Trace TCP drops by the kernel",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
group = parser.add_mutually_exclusive_group()