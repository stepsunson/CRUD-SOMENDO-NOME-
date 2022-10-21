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
    help="output u