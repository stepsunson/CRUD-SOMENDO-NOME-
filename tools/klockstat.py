#!/usr/bin/env python
#
# klockstat traces lock events and display locks statistics.
#
# USAGE: klockstat
#

from __future__ import print_function
from bcc import BPF, USDT
import argparse
import subprocess
import ctypes as ct
from time import sleep, strftime
from datetime import datetime, timedelta
import errno
from sys import stderr

examples = """
    klockstat                           # trace system wide
    klockstat -d 5                      # trace for 5 seconds only
    klockstat -i 5                      # display stats every 5 seconds
    klockstat -p 123                    # trace locks for PID 123
    klockstat -t 321                    # trace locks for PID 321
    klockstat -c pipe_                  # display stats only for lock callers with 'pipe_' substring
    klockstat -S acq_count              # sort lock acquired results on acquired count
    klockstat -S hld_total              # sort lock held results on total held time
    klockstat -S acq_count,hld_total    # combination of above
    klockstat -n 3                      # display 3 locks
    klockstat -s 3                      # display 3 levels of stack
"""

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

time_group = parser.add_mutually_exclusive_group()
time_group.add_argument("-d", "--duration", type=int,
    help="total duration of trace in seconds")
time_group.add_argument("-i", "--interval", type=int,
    help="print summary at this interval (seconds)")
parser.add_argument("-n", "--locks", type=int, default=99999999,
    help="print given number of locks")
parser.add_argument("-s", "--stacks", type=int, default=1,
    help="print given number of stack entries")
parser.add_argument("-c", "--caller",
    help="print locks taken by given caller")
parser.add_argument("-S", "--sort",
    help="sort data on <aq_field,hd_field>, fields: acq_[max|total|count] hld_[max|total|count]")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("--stack-storage-size", default=16384,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
         "displayed (default 16384)")

args = parser.parse_args()

program = """
#include <uapi/linux/ptrace.h>

struct depth_id {
  u64 id;
  u64 depth;
};

BPF_ARRAY(enabled,   u64, 1);
BPF_HASH(track,      u64, u64);
BPF_HASH(time_aq,    u64, u64);
BPF_HASH(lock_depth, u64, u64);
BPF_HASH(time_held,  struct depth_id, u64);
BPF_HASH(stack,      struct depth_id, int);

BPF_HASH(aq_report_count, int, u64);
BPF_HASH(aq_report_max,   int, u64);
BPF_HASH(aq_report_total, int, u64);

BPF_HASH(hl_report_count, int, u64);
BPF_HASH(hl_report_max,   int, u64);
BPF_HASH(hl_report_total, int, u64);

BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

static bool is_enabled(void)
{
    int key = 0;
    u64 *ret;

    ret = enabled.lookup(&key);
    return ret && *ret == 1;
}

static bool allow_pid(u64 id)
{
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part

    FILTER

    return 1;
}

static int do_mutex_lock_enter(void *ctx, int skip)
{
    if (!is_enabled())
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    if (!allow_pid(id))
        return 0;

    u64 one = 1, zero = 0;

    track.update(&id, &one);

    u64 *depth = lock_depth.lookup(&id);

    if (!depth) {
        lock_depth.update(&id, &zero);

        depth = lock_depth.lookup(&id);
        /* something is wrong.. */
        if (!depth)
            return 0;
    }

    int stackid = stack_traces.get_stackid(ctx, skip);
    struct depth_id did = {
      .id    = id,
      .depth = *depth,
    };
    stack.update(&did, &stackid);

    u64 ts = bpf_ktime_get_ns();
    time_aq.update(&id, &ts);

    *depth += 1;
    return 0;
}

static void update_aq_report_count(int *stackid)
{
    u64 *count, one = 1;

    count = aq_report_count.lookup(stackid);
    if (!count) {
        aq_report_count.update(stackid, &one);
    } else {
        *count += 1;
    }
}

static void update_hl_report_count(int *stackid)
{
    u64 *count, one = 1;

    count = hl_report_count.lookup(stackid);
    if (!count) {
        hl_report_count.update(stackid, &one);
    } else {
        *count += 1;
    }
}

static void update_aq_report_max(int *stackid, u64 time)
{
    u64 *max;

    max = aq_report_max.lookup(stackid);
    if (!max || *max < time)
        aq_report_max.update(stackid, &time);
}

sta