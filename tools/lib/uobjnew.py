#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# uobjnew  Summarize object allocations in high-level languages.
#          For Linux, uses BCC, eBPF.
#
# USAGE: uobjnew [-h] [-T TOP] [-v] {c,java,ruby,tcl} pid [interval]
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, utils
from time import sleep
import os

# C needs to be the last language.
languages = ["c", "java", "ruby", "tcl"]

examples = """examples:
    ./uobjnew -l java 145         # summarize Java allocations in process 145
    ./uobjnew -l c 2020 1         # grab malloc() sizes and print every second
    ./uobjnew -l ruby 6712 -C 10  # top 10 Ruby types by number of allocations
    ./uobjnew -l ruby 6712 -S 10  # top 10 Ruby types by total size
"""
parser = argparse.ArgumentParser(
    description="Summarize object allocations in high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-l", "--language", choices=languages,
    help="language to trace")
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("interval", type=int, nargs='?',
    help="print every specified number of seconds")
parser.add_argument("-C", "--top-count", type=int,
    help="number of most frequently allocated types to print")
parser.add_argument("-S", "--top-size", type=int,
    help="number of largest types by allocated bytes to print")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

language = args.language
if not language:
    language = utils.detect_language(languages, args.pid)

program = """
#include <linux/ptrace.h>

struct key_t {
#if MALLOC_TRACING
    u64 size;
#else
    char name[50];
#endif
};

struct val_t {
    u64 total_size;
    u64 num_allocs;
};

BPF_HASH(allocs, struct key_t, struct val_t);
""".replace("MALLOC_TRACING", "1" if language == "c" else "0")

usdt = USDT(pid=args.pid)

#
# C
#
if language == "c":
    program += """
int alloc_entry(struct pt_regs *ctx, size_t size) {
    struct key_t key = {};
    struct val_t *valp, zero = {};
    key.size = size;
    valp = allocs.lookup_or_try_init(&key, &zero);
    if (valp) {
        valp->total_size += size;
        valp->num_allocs += 1;
    }
    return 0;
}
    """
#
# Java
#
elif language == "java":
    program += """
int alloc_entry(struct pt_regs *ctx) {
    struct key_t key = {};
    struct val_t *valp, zero = {};
    u64 classptr = 0, size = 0;
    u32 length = 0;
    bpf_usdt_readarg(2, ctx, &cl