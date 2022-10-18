#!/usr/bin/env python
#
# bpflist   Display processes currently using BPF programs and maps,
#           pinned BPF programs and maps, and enabled probes.
#
# USAGE: bpflist [-v]
#
# Idea by Brendan Gregg.
#
# Copyright 2017, Sasha Goldshtein
# Licensed under the Apache License, Version 2.0
#
# 09-Mar-2017   Sasha Goldshtein   Created this.

from bcc import BPF, USDT
import argparse
import re
import os
import subprocess

examples = """examples:
    bpflist     # display all processes currently using BPF
    bpflist -v  # also count kprobes/uprobes
    bpflist -vv # display kprobes/uprobes and count them
"""
parser = argparse.ArgumentParser(
    description="Display processes currently using BPF programs and maps",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-v", "--verbosity", action="count", default=0,
    help="count and display kprobes/uprobes as well")
args = parser.parse_args()

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid).read().strip()
    except:
        return "[unknown]"

counts = {}

def parse_probes(typ):
    if args.verbosity > 1:
        print("open %ss:" % typ)
    for probe in open("/sys/kernel/debug/tracing/%s_events" % typ):
        # Probes opened by bcc have a specific pattern that includes the pid
        # of the requesting process.
        match = re.search('_bcc_(\\d+)\\s', probe)
        if match:
            pid = int(match.group(1))
            counts[(pid, typ)] = counts.get((pid, typ), 0) + 1
        if args.verbosity > 1:
            print(probe.strip())
    if args.ver