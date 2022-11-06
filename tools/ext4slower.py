#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# ext4slower  Trace slow ext4 operations.
#             For Linux, uses BCC, eBPF.
#
# USAGE: ext4slower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common ext4 file operations: reads, writes, opens, and
# syncs. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these ext4 operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# By default, a minimum millisecond threshold of 10 is used.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Feb-2016   Brendan Gregg   Created this.
# 15-Oct-2016   Dina Goldshtein -p to filter by process ID.
# 13-Jun-2018   Joe Yin modify generic_file_read_iter to ext4_file_read_iter.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# symbols
kallsyms = "/proc/kallsyms"

# arguments
examples = """examples:
    ./ext4slower             # trace operations slower than 10 ms (default)
    ./ext4slower 1           # trace operations slower than 1 ms
    ./ext4slower -j 1        # ... 1 ms, parsable output (csv)
    ./ext4slower 0           # trace all operations (warning: verbose)
    ./ext4slower -p 185      # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Trace common ext4 file operations slower than a threshold",
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

// The current ext4 (Linux 4.5) uses generic_file_read_iter(), instead of it's
// own function, for reads. So we need to trace that and then filter on ext4,
// which I do by checking file->f_op.
// The new Linux version (since form 4.10) uses ext4_file_read_iter(), And if the 'CONFIG_FS_DAX' 
// is not set, then ext4_file_read_iter() will call generic_file_read_iter(), else it will call
// ext4_dax_read_iter(), and trace generic_file_read_iter() will fail.
int trace_read_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // ext4 filter on file->f_op == ext4_file_operations
    struct file *fp = iocb->ki_filp;
    if ((u64)fp->f_op != EXT4_FILE_OPERATIONS)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = fp;
    val.offset = iocb->ki_pos;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// ext4_file_write_iter():
int trace_write_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = iocb->ki_filp;
    val.offset = iocb->ki_pos;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// ext4_file_open():
int trace_open_entry(struct pt_regs *ctx, struct inode *inode,
    struct file *file)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    s