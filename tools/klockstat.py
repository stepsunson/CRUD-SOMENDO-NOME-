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
BPF_HASH(track,      