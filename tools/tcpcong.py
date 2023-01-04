#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpcong  Measure tcp congestion control status duration.
#           For Linux, uses BCC, eBPF.
#
# USAGE: tcpcong [-h] [-T] [-L] [-R] [-m] [-d] [interval] [outputs]
#
# Copyright (c) Ping Gan.
#
# 27-Jan-2022   Ping Gan   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from struct import pack
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse

examples = """examples:
    ./tcpcong                 # show tcp congestion status duration
    ./tcpcong 1 10            # show 1 second summaries, 10 times
    ./tcpcong -L 3000-3006 1  # 1s summaries, local port 3000-3006
    ./tcpcong -R 5000-5005 1  # 1s summaries, remote port 5000-5005
    ./tcpcong -uT 1           # 1s summaries, microseconds, and timestamps
    ./tcpcong -d              # show the duration as histograms
"""

parser = argparse.ArgumentParser(
    description="Summarize tcp socket congestion control status duration",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-L", "--localport",
            help="trace local ports only")
parser.add_argument("-R", "--remoteport",
            help="trace the dest ports only")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="output in microseconds")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("outputs", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.outputs)
debug = 0

start_rport = end_rport = -1
if args.remoteport:
    rports = args.remoteport.split("-")
    if (len(rports) != 2) and (len(rports) != 1):
