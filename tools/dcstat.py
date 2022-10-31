#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# dcstat   Directory entry cache (dcache) stats.
#          For Linux, uses BCC, eBPF.
#
# USAGE: dcstat [interval [count]]
#
# This uses kernel dynamic tracing of kernel functions, lookup_fast() and
# d_lookup(), which will need to be modified to match kernel changes. See
# code comments.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
from sys import argv

def usage():
    print("USAGE: %s [interval [count]]" % argv[0])
    exit()

# arguments
interval = 1
count = -1
if len(argv) > 1:
    try:
        interval = int(argv[1])
        if interval == 0:
            raise
        if len(argv) > 2:
            count = int(argv[2])
    except:  # also catches -h, --help
        usage()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

enum stats {
    S_REFS = 1,
    S_SLOW,
    S_MISS,
    S_MAXSTAT
};

BPF_ARRAY(stats, u64, S_MAXSTAT);

/*
 * How this is instru