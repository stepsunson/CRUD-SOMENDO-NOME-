#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpretrans    Trace or count TCP retransmits and TLPs.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpretrans [-c] [-h] [-l] [-4 | -6]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.
# 03-Nov-2017   Matthias Tafelmeier Extended this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep

# arguments
examples = """examples:
    ./tcpretrans           # trace TCP retransmits
    ./tcpretrans -l        # include TLP attempts
    ./tcpretrans -4        # trace IPv4 family only
    ./tcpr