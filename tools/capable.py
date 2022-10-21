#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# capable   Trace security capabilitiy checks (cap_capable()).
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: capable [-h] [-v] [-p PID] [-K] [-U]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Sep-2016   Brendan Gregg   Created this.

from __future__ import print_function
from os import getpid
from functools import partial
from bcc import BPF
from bcc.containers import filter_by_containers
import errno
import argparse
from time import strftime

# arguments
examples = """examples:
    ./capable             # trace capability checks
    ./capable -v          # verbose: include non-audit checks
    ./capable -p 181      # only trace PID 181
    ./capable -K          # add kernel stacks to trace
    ./capable -U          # add user-space stacks to trace
    ./capable -x          # extra fields: show TID and INSETID columns
    ./capable --unique    # don't repeat stacks for the same pid or cgroup
    ./capable --cgroupmap mappath  # only trace cgroups in this BPF map
    ./capable --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace security capability checks",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-v", "--verbose", action="store_true",
    help="include non-audit checks")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-K", "--kernel-stack", action="store_true",
    help="output kernel stack trace")
parser.add_argument("-U", "--user-stack", action="store_true",
    help="output user stack trace")
parser.add_argument("-x", "--extra", action="store_true",
    help="show extra fields in TID and INSETID columns")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("--unique", action="store_true",
    help="don't repeat stacks for the same pid or cgroup")
args = parser.parse_args()
debug = 0

# capabilities to names, generated from (and will need updating):
# awk '/^#define.CAP_.*[0-9]$/ { print "    " $3 ": \"" $2 "\"," }' \
#     include/uapi/linux/capability.h
capabilities = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

class Enum(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError

# Stack trace types
StackType = Enum(("Kernel", "User",))

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/security.h>

struct data_t {
   u32 tgid;
   u32 pid;
   u32 uid;
   in