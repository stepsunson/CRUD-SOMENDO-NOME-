
#!/usr/bin/python
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
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(args_filename, u32, const char *);

int trace_entry(struct pt_regs *ctx, const char __user *filename)
{
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    args_filename.update(&pid, &filename);

    return 0;
};

int trace_return(struct pt_regs *ctx)
{
    const char **filenamep;
    int ret = ctx->ax;
    u32 pid = bpf_get_current_pid_tgid();

    filenamep = args_filename.lookup(&pid);
    if (filenamep == 0) {
        // missed entry
        return 0;
    }

    bpf_trace_printk("%d %s\\n", ret, *filenamep);
    args_filename.delete(&pid);

    return 0;
}
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug:
    print(bpf_text)
