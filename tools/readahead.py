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
int entry__do_page_cache_readahead(struct pt_regs *ctx) {
    u32 pid;
    u8 one = 1;
    pid = bpf_get_current_pid_tgid();
    flag.update(&pid, &one);
    return 0;
}

int exit__do_page_cache_readahead(struct pt_regs *ctx) {
    u32 pid;
    u8 zero = 0;
    pid = bpf_get_current_pid_tgid();
    flag.update(&pid, &zero);
    return 0;
}

int exit__page_cache_alloc(struct pt_regs *ctx) {
    u32 pid;
    u64 ts;
    struct page *retval = (struct page*) GET_RETVAL_PAGE;
    u32 zero = 0; // static key for accessing pages[0]
    pid = bpf_get_current_pid_tgid();
    u8 *f = flag.lookup(&pid);
    if (f != NULL && *f == 1) {
        ts = bpf_ktime_get_ns();
        birth.update(&retval, &ts);
        pages.atomic_increment(zero);
    }
    return 0;
}

int entry_mark_page_accessed(struct pt_regs *ctx) {
    u64 ts, delta;
    struct page *arg0 = (struct page *) PT_REGS_PARM1(ctx);
    u32 zero = 0; // static key for accessing pages[0]
    u64 *bts = birth.lookup(&arg0);
    if (bts != NULL) {
        delta = bpf_ktime_get_ns() - *bts;
        dist.atomic_increment(bpf_log2l(delta/1000000));
        pages.atomic_increment(zero, -1);
        birth.delete(&arg0); // remove the entry from hashmap
    }
    return 0;
}
"""

bpf_text_kfunc = """
KFUNC_PROBE(RA_FUNC)
{
    u32 pid = bpf_get_current_pid_tgid();
    u8 one = 1;

    flag.update(&pid, &one);
    return 0;
}

KRETFUNC_PROBE(RA_FUNC)
{
    u32 pid = bpf_get_current_pid_tgid();
    u8 zero = 0;

    flag.update(&pid, &zero);
    return 0;
}

KFUNC_PROBE(mark_page_accessed, struct page *arg0)
{
    u64 ts, delta;
    u32 zero = 0; // static key for accessing pages[0]
    u64 *bts = birth.lookup(&arg0);

    if (bts != NULL) {
        delta = bpf_ktime_get_ns() - *bts;
        dist.atomic_increment(bpf_log2l(delta/1000000));
        pages.atomic_increment(zero, -1);
        birth.delete(&arg0); // remove the entry from hashmap
    }
    return 0;
}
"""

bpf_text_kfunc_cache_alloc_ret_page = """
KRETFUNC_PROBE(__page_cache_alloc, gfp_t gfp, struct page *retval)
{
    u64 ts;
    u32 zero = 0; // static key for accessing pages[0]
    u32 pid = 