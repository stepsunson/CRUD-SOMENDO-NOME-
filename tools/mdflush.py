#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# mdflush  Trace md flush events.
#          For Linux, uses BCC, eBPF.
#
# Todo: add more details of the flush (latency, I/O count).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Feb-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import strftime

# define BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/blkdev.h>
#include <linux/bio.h>

struct data_t {
   