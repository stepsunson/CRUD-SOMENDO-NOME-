#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# vfsstat   Count some VFS calls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of counting multiple events as a stat tool.
#
# USAGE: vfsstat [-h] [-p PID] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Aug-2015   Brendan Gregg   Created this.
# 12-Oct-2022   Rocky Xing      Added PID filter support.

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
from sys import argv
import argparse

# arguments
examples = """examples:
    ./vfsstat             # count some VFS calls per second
    ./vfsstat -p 185      # trace PID 185 only
    ./vfsstat 2 5         # print 2 second summaries, 5 times
"""
parser = argparse.ArgumentParser(
    description="Count some VFS calls.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()
countdown = int(args.count)
debug = 0

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

enum stat_types {
    S_READ = 1,
    S_WRITE,
    S_FSYNC,
    S_OPEN,
    S_CREATE,
    S_MAXSTAT
};

BPF_ARRAY(stats, u64, S_MAXSTAT);

static void stats_try_increment(int key) {
    PID_FILTER
    stats.atomic_increment(key);
}
"""

bpf_text_kprobe = """
void do_read(struct pt_regs *ctx) { stats_try_increment(S_READ); }
void do_write(struct pt_regs *ctx) { stats_try_increment(S_WRITE); }
void do_fsync(struct pt_regs *ctx) { stats_try_increment(S_FSYNC); }
void do_open(struct pt_regs *ctx) { stats_try_increment(S_OPEN); }
void do_create(struct pt_regs *ctx) { stats_try_increment(S_CREATE); }
"""

bpf_text_kfunc = """
KFUNC_PROBE(vfs_read)         { stats_try_increment(S_READ); return 0; }
KFUNC_PROBE(vfs_write)        { stats_try_increment(S_WRITE); return 0; }
KFUNC_PROBE(vfs_fsync_range)  { stats_try_increment(S_FSYNC); return 0; }
KFUNC_PROBE(vfs_open)         { stats_try_increment(S_OPEN); return 0; }
KFUNC_PROBE(vfs_create)       { stats_try_increment(S_CREATE); return 0; }
"""

is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    bpf_text += bpf_text_kfunc
else:
    bpf_text += bpf_text_kprobe

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER', """
    u32 pid = bpf_get_current_pid_tgid(