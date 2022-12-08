
#!/usr/bin/python
#
# stackcount    Count kernel function calls and their stack traces.
#               For Linux, uses BCC, eBPF.
#
# USAGE: stackcount [-h] [-p PID] [-i INTERVAL] [-T] [-r] pattern
#
# The pattern is a string with optional '*' wildcards, similar to file
# globbing. If you'd prefer to use regular expressions, use the -r option.
#
# The current implementation uses an unrolled loop for x86_64, and was written
# as a proof of concept. This implementation should be replaced in the future
# with an appropriate bpf_ call, when available.
#
# Currently limited to a stack trace depth of 11 (maxdepth + 1).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Jan-2016	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    ./stackcount submit_bio       # count kernel stack traces for submit_bio
    ./stackcount ip_output        # count kernel stack traces for ip_output
    ./stackcount -s ip_output     # show symbol offsets
    ./stackcount -sv ip_output    # show offsets and raw addresses (verbose)
    ./stackcount 'tcp_send*'      # count stacks for funcs matching tcp_send*
    ./stackcount -r '^tcp_send.*' # same as above, using regular expressions
    ./stackcount -Ti 5 ip_output  # output every 5 seconds, with timestamps
    ./stackcount -p 185 ip_output # count ip_output stacks for PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Count kernel function calls and their stack traces",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-i", "--interval", default=99999999,
    help="summary interval, seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-r", "--regexp", action="store_true",
    help="use regular expressions. Default is \"*\" wildcards only.")
parser.add_argument("-s", "--offset", action="store_true",
    help="show address offsets")
parser.add_argument("-v", "--verbose", action="store_true",
    help="show raw addresses")
parser.add_argument("pattern",
    help="search expression for kernel functions")
args = parser.parse_args()
pattern = args.pattern
if not args.regexp:
    pattern = pattern.replace('*', '.*')