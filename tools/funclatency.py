#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# funclatency   Time functions and print latency as a histogram.
#               For Linux, uses BCC, eBPF.
#
# USAGE: funclatency [-h] [-p PID] [-i INTERVAL] [-T] [-u] [-m] [-F] [-r] [-v]
#                    pattern
#
# Run "funclatency -h" for full usage.
#
# The pattern is a string with optional '*' wildcards, similar to file
# globbing. If you'd prefer to use regular expressions, use the -r option.
#
# Without the '-l' option, only the innermost calls will be recorded.
# Use '-l LEVEL' to record the outermost n levels of nested/recursive functions.
#
# Copyright (c) 2015 Brendan Gregg.
# Copyright (c) 2021 Chenyue Zhou.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg       Created this.
# 06-Oct-2016   Sasha Goldshtein    Added user function support.
# 14-Apr-2021   Chenyue Zhou        Added nested or recursive function support.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    ./funclatency do_sys_open       # time the do_sys_open() kernel function
    ./funclatency c:read            # time the read() C library function
    ./funclatency -u vfs_read       # time vfs_read(), in microseconds
    ./funclatency -m do_nanosleep   # time do_nanosleep(), in milliseconds
    ./funclatency -i 2 -d 10 c:open # output every 2 seconds, for duration 10s
    ./funclatency -mTi 5 vfs_read   # output every 5 seconds, with timestamps
    ./funclatency -p 181 vfs_read   # time process 181 only
    ./funclatency 'vfs_fstat*'      # time both vfs_fstat() and vfs_fstatat()
    ./funclatency 'c:*printf'       # time the *printf family of functions
    ./funclatency -F 'vfs_r*'       # show one histogram per matched function
"""
parser = argparse.ArgumentParser(
    description="Time functions and print latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int,
    help="trace this PID only")
parser.add_argument("-i", "--interval", type=int,
    help="summary interval, in seconds")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="microsecond histogram")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-F", "--function", action="store_true",
    help="show a separate histogram per function")
parser.add_argument("-r", "--regexp", action="store_true",
    help="use regular expressions. Default is \"*\" wildcards only.")
parser.add_argument("-l", "--level", type=int,
    help="set the level of nested or recursive functions")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program (for debugging purposes)")
parser.add_argument("pattern",
    help="search expression for functions")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

def bail(error):
    print("Error: " + error)
    exit(1)

parts = args.pattern.split(':')
if len(parts) == 1:
    library = None
    pattern = args.pattern
elif len(parts) == 2:
    library = parts[0]
    libpath = BPF.find_library(library) or BPF.find_exe(library)
    if not libpath:
        bail("can't resolve library %s" % library)
    library = libpath
    pattern = parts[1]
else:
    bail("unrecognized pattern format '%s'" % args.pattern)

if not args.regexp:
    pattern = pattern.replace('*', '.*')
    pattern = '^' + pattern + '$'

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

typedef struct ip_pid {
    u64 ip;
    u64 pid;
} ip_pid_t;

typedef struct hist_key {
    ip_pid_t key;
    u64 slot;
} hist_key_t;

TYPEDEF

BPF_ARRAY(avg, u64, 2);
STORAGE
FUNCTION

int trace_func_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;
    u64 ts = bpf_ktime_get_ns();

    FILTER
    ENTRYSTORE

    return 0;
}

int trace_func_return(struct pt_regs *ctx)
{
    u64 *tsp, delta;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    // calculate delta time
    CALCULATE

    u32 lat = 0;
    u32 cnt = 1;
    avg.atomic_increment(lat, delta);
    avg.atomic_increment(cnt);

    FACTOR

    // store as histogram
    STORE

    return 0;
}
"""

# do we need to store the IP and pid for each invocation?
need_key = args.function or (library and not args.pid)

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (tgid != %d) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
elif args.microseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "nsecs"
if need_key:
    pid = '-1' if not library else 'tgid'

    if args.level and args.level > 1:
        bpf_text = bpf_text.replace('TYPEDEF',
            """
#define STACK_DEPTH %s

typedef struct {
    u64 ip;
    u64 start_ts;
} func_cache_t;

/* LIFO */
typedef struct {
    u32          head;
    func_cache_t cache[STACK_DEPTH];
} func_stack_t;
            """ % args.level)

        bpf_text = bpf_text.replace('STORAGE',
            """
BPF_HASH(func_stack, u32, func_stack_t);
BPF_HISTOGRAM(dist, hist_key_t);
            """)

        bpf_text = bpf_text.replace('FUNCTION',
            """
static inline int stack_pop(func_stack_t *stack, func_cache_t *cache) {
    if (stack->head <= 0) {
        return -1;
    }

    u32 index = --stack->head;
    if (index < STACK_DEPTH) {
        /* bound check */
        cache->ip       = stack->cache[index].ip;
        cache->start_ts = stack->cache[index].start_ts;
    }

    return 0;
}

static inline int stack_push(func_stack_t *stack, func_cache_t *cache) {
    u32 index = stack->head;

    if (index > STACK_DEPTH - 1) {
        /* bound check */
        return -1;
    }

    stack->head++;
    stack->cache[index].ip       = cache->ip;
    stack->cache[index].start_ts = cache->start_ts;

    return 0;
}
            """)

        bpf_text = bpf_text.replace('ENTRYSTORE',
            """
    u64 ip = PT_REGS_IP(ctx);
    func_cache_t cache = {
        .ip       = ip,
        .start_ts = ts,
    };

    func_stack_t *stack = func_stack.lookup(&pid);
    if (!stack) {
        func_stack_t new_stack = {
            .head = 0,
        };

        if (!stack_push(&new_stack, &cache)) {
            func_stack.update(&pid, &new_stack);
        }

        return 0;
    }

    if (!stack_push(stack, &cache)) {
        func_stack.update(&pid, stack);
    }
            """)

        bpf_text = bpf_text.replace('CALCULATE',
            """
    u64 ip, start_ts;
    func_stack_t *stack = func_stack.lookup(&pid);
    if (!stack) {
        /* miss start */
        return 0;
    }

    func_cache_t cache = {};
    if (stack_pop(stack, &cache)) {
        func_stack.delete(&pid);

        return 0;
    }
    ip       = cache.ip;
    start_ts = cache.start_ts;
    delta    = bpf_ktime_get_ns() - start_ts;
            """)

        bpf_text = bpf_text.replac