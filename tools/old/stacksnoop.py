#!/usr/bin/python
#
# stacksnoop    Trace a kernel function and print all kernel stack traces.
#               For Linux, uses BCC, eBPF, and currently x86_64 only. Inline C.
#
# USAGE: stacksnoop [-h] [-p PID] [-s] [-v] function
#
# The current implementation uses an unrolled loop for x86_64, and was written
# as a proof of concept. This implementation should be replaced in the future
# with an appropriate bpf_ call, when available.
#
# The stack depth is limited to 10 (+1 for the current instruction pointer).
# This could be tunable in a future version.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Jan-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./stacksnoop ext4_sync_fs    # print kernel stack traces for ext4_sync_fs
    ./stacksnoop -s ext4_sync_fs    # ... also show symbol offsets
    ./stacksnoop -v ext4_sync_fs    # ... show extra columns
    ./stacksnoop -p 185 ext4_sync_fs    # ... only when PID 185 is on-CPU
"""
parser = argparse.ArgumentParser(
    description="Trace and print kernel stack traces for a kernel function",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-s", "--offset", action="store_true",
    help="show address offsets")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print more fields")
parser.add_argument("function",
    help="kernel function name")
args = parser.parse_args()
function = args.function
offset = args.offset
verbose = args.verbose
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

static int print_frame(u64 *bp, int *depth) {
    if (*bp) {
        // The following stack walker is x86_64 specific
        u64 ret = 0;
        if (bpf_probe_read(&ret, sizeof(ret), (void *)(*bp+8)))
   