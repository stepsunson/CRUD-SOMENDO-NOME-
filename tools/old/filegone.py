#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# filegone    Trace why file gone (deleted or renamed).
#             For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: filegone [-h] [-p PID]
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Nov-2022 Curu. modified from filelife

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./filegone           # trace all file gone events
    ./filegone -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace why file gone (deleted or renamed)",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u8 action;
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
    char fname2[DNAME_INLINE_LEN];
};

BPF_PERF_OUTPUT(events);

// trace file deletion and output details
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
#else
int trace_unlink(struct pt_regs *ctx, struct user_namespace *ns, struct inode *dir, struct dentry *dentry)
#endif
{
    u32 pid =