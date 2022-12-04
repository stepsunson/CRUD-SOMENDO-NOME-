#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# filelife    Trace the lifespan of short-lived files.
#             For Linux, uses BCC, eBPF. Embedded C.
#
# This traces the creation and deletion of files, providing information
# on who deleted the file, the file age, and the file name. The intent is to
# provide information on short-lived files, for debugging or performance
# analysis.
#
# USAGE: filelife [-h] [-p PID]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Feb-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./filelife           # trace all stat() syscalls
    ./filelife -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace stat() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

BPF_HASH(birth, struct dentry *);

// trace file creation time
int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    u64 ts = bpf_ktime_get_ns();
    birth.update(&dentry, &ts);

    return 0;
};

// trace file deletion and output details
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    u64 *tsp, delta;
    tsp = birth.lookup(&dentry);
    if (tsp == 0) {
        return 0;   // missed create
    