#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# readahead     Show performance of read-ahead cache
#               For Linux, uses BCC, eBPF
#
# Copyright (c) 2020 Suchakra Sharma <mail@suchakra.in>
# Licensed under the Apache License, Version 2.0 (the "License")
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-13: 9780136554820
# When copying or porting, include this comment.
#
# 20-Aug-2020   Suchakra Sharma     Ported from bpftrace to BCC
# 17-Sep-2021   Hengqi Chen         Migrated to kfunc
# 30-Jan-2023   Rong Tao            Support more kfunc/kprobe, introduce folio

from __future__ import print_function
from bcc import BPF
from time import sleep
import ctypes as ct
import argparse

# arguments
examples = """examples:
    ./readahead -d 20       # monitor for 20 seconds and generate stats
"""

parser = argparse.ArgumentParser(
    description="Monitor performance of read ahead cache",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-d", "--duration", type=int,
    help="total duration to monitor for, in seconds")
args = parser.parse_args()
if not args.duration:
    args.duration = 99999999

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

BPF_HASH(flag, u32, u8);            // used to track if we are in do_page_cache_readahead()
BPF_HASH(birth, struct page*, u64); // used to track timestamps of cache alloc'ed page
BPF_ARRAY(pages);                   // increment/decrement readahead pages
BPF_HISTOGRAM(dist);
"""

bpf_text_kprobe = """
int entry__do_page_cache_readahead(struct pt_reg