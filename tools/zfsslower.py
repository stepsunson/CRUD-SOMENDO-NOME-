#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# zfsslower  Trace slow ZFS operations.
#            For Linux, uses BCC, eBPF.
#
# USAGE: zfsslower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common ZFS file operations: reads, writes, opens, and
# syncs. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these ZFS operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# This works by using kernel dynamic tracing of the ZPL interface, and will
# need updates to match any changes to this interface.
#
# By default, a minimum millisecond threshold of 10 is used.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.
# 16-Oct-2016   Dina Goldshtein -p to filter by process ID.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./zfsslower             # trace operations slower than 10 ms (default)
    ./zfsslower 1           # trace operations slower than 1 ms
    ./zfsslower -j 1        # ... 1 ms, parsable output (csv)
    ./zfsslower 0           # trace all operations (warning: verbose)
    ./zfsslower -p 185      # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Trace common ZFS file operations slower than a threshold",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-j", "--csv", action="store_true",
    help="just print fields: comma-separated values")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("min_ms", nargs="?", default='10',
    help="minimum I/O duration to trace, in ms (default 10)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
min_ms = int(args.min_ms)
pid = args.pid
csv = args.csv
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

// XXX: switch these to char's when supported
#define TRACE_READ      0
#define TRACE_WRITE     1
#define TRACE_OPEN      2
#define TRACE_FSYNC     3

struct val_t {
    u64 ts;
    u64 offset;
    struct file *fp;
};

struct data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 type;
    u32 size;
    u64 offset;
    u64 delta_us;
    u32 pid;
    char task[TASK_COMM_LEN];
    char file[DNAME_INLINE_LEN];
};

BPF_HASH(entryinfo, u64, struct val_t);
BPF_PERF_OUTPUT(events);

//
// Store timestamp and size on entry
//

// zpl_read(), zpl_write():
int trace_rw_entry(struct pt_regs *ctx, struct file *filp, char __user *buf,
    size_t len, loff_t *ppos)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = filp;
    val.offset = *ppos;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// zpl_open():
int trace_open_entry(struct pt_regs *ctx, struct inode *inode,
    struct file *filp)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = filp;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// zpl_fsync():
int trace_fsync_entry(struct pt_regs *ctx, struct file *filp)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filp and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = filp;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

//
// Output
//

static int trace_return(struct pt_regs *ctx, int type)
{
    struct val_t *valp;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    valp = entryinfo.lookup(&id);
    if (valp == 0) {
        // missed tracing issue or filtered
        return 0;
    }

    // calculate delta
    u64 ts = bpf_ktime_get_ns();
    u64 delta_us = (ts - valp->ts) / 1000;
    entryinfo.delete(&id);
    if (