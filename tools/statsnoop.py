#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# statsnoop Trace stat() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: statsnoop [-h] [-t] [-x] [-p PID]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Feb-2016   Brendan Gregg   Created this.
# 17-Feb-2016   Allan McAleavy  updated for BPF_PERF_OUTPUT
# 29-Nov-2022   Rocky Xing      Added stat() variants.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./statsnoop           # trace all stat() syscalls
    ./statsnoop -t        # include timestamps
    ./statsnoop -x        # only show failed stats
    ./statsnoop -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace stat() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed stats")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    const char *fname;
};

struct data_t {
    u32 pid;
    u64 ts_ns;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

static int trace_entry(struct