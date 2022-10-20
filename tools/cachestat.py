
#!/usr/bin/env python
#
# cachestat     Count cache kernel function calls.
#               For Linux, uses BCC, eBPF. See .c file.
#
# USAGE: cachestat
# Taken from funccount by Brendan Gregg
# This is a rewrite of cachestat from perf to bcc
# https://github.com/brendangregg/perf-tools/blob/master/fs/cachestat
#
# Copyright (c) 2016 Allan McAleavy.
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Sep-2015   Brendan Gregg   Created this.
# 06-Nov-2015   Allan McAleavy
# 13-Jan-2016   Allan McAleavy  run pep8 against program
# 02-Feb-2019   Brendan Gregg   Column shuffle, bring back %ratio

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal
import re
from sys import argv

# signal handler
def signal_ignore(signal, frame):
    print()

# Function to gather data from /proc/meminfo
# return dictionary for quicker lookup of both values
def get_meminfo():
    result = dict()

    for line in open('/proc/meminfo'):
        k = line.split(':', 3)
        v = k[1].split()
        result[k[0]] = int(v[0])
    return result

# set global variables
mpa = 0
mbd = 0
apcl = 0
apd = 0
total = 0
misses = 0
hits = 0
debug = 0

# arguments
parser = argparse.ArgumentParser(
    description="Count cache kernel function calls",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")