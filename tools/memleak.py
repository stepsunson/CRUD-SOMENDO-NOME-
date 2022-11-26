
#!/usr/bin/env python
#
# memleak   Trace and display outstanding allocations to detect
#           memory leaks in user-mode processes and the kernel.
#
# USAGE: memleak [-h] [-p PID] [-t] [-a] [-o OLDER] [-c COMMAND]
#                [--combined-only] [--wa-missing-free] [-s SAMPLE_RATE]
#                [-T TOP] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJ]
#                [interval] [count]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF
from time import sleep
from datetime import datetime
import resource
import argparse
import subprocess
import os
import sys

class Allocation(object):
    def __init__(self, stack, size):
        self.stack = stack
        self.count = 1
        self.size = size

    def update(self, size):
        self.count += 1
        self.size += size

def run_command_get_output(command):
        p = subprocess.Popen(command.split(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return iter(p.stdout.readline, b'')

def run_command_get_pid(command):
        p = subprocess.Popen(command.split())
        return p.pid

examples = """
EXAMPLES:

./memleak -p $(pidof allocs)
        Trace allocations and display a summary of "leaked" (outstanding)
        allocations every 5 seconds
./memleak -p $(pidof allocs) -t
        Trace allocations and display each individual allocator function call
./memleak -ap $(pidof allocs) 10
        Trace allocations and display allocated addresses, sizes, and stacks
        every 10 seconds for outstanding allocations
./memleak -c "./allocs"
        Run the specified command and trace its allocations
./memleak
        Trace allocations in kernel mode and display a summary of outstanding
        allocations every 5 seconds
./memleak -o 60000
        Trace allocations in kernel mode and display a summary of outstanding
        allocations that are at least one minute (60 seconds) old
./memleak -s 5
        Trace roughly every 5th allocation, to reduce overhead
"""

description = """
Trace outstanding memory allocations that weren't freed.
Supports both user-mode allocations made with libc functions and kernel-mode
allocations made with kmalloc/kmem_cache_alloc/get_free_pages and corresponding
memory release functions.
"""

parser = argparse.ArgumentParser(description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-p", "--pid", type=int, default=-1,
        help="the PID to trace; if not specified, trace kernel allocs")
parser.add_argument("-t", "--trace", action="store_true",
        help="print trace messages for each alloc/free call")
parser.add_argument("interval", nargs="?", default=5, type=int,
        help="interval in seconds to print outstanding allocations")
parser.add_argument("count", nargs="?", type=int,
        help="number of times to print the report before exiting")
parser.add_argument("-a", "--show-allocs", default=False, action="store_true",
        help="show allocation addresses and sizes as well as call stacks")
parser.add_argument("-o", "--older", default=500, type=int,
        help="prune allocations younger than this age in milliseconds")
parser.add_argument("-c", "--command",
        help="execute and trace the specified command")
parser.add_argument("--combined-only", default=False, action="store_true",
        help="show combined allocation statistics only")
parser.add_argument("--wa-missing-free", default=False, action="store_true",
        help="Workaround to alleviate misjudgments when free is missing")
parser.add_argument("-s", "--sample-rate", default=1, type=int,
        help="sample every N-th allocation to decrease the overhead")
parser.add_argument("-T", "--top", type=int, default=10,
        help="display only this many top allocating stacks (by size)")
parser.add_argument("-z", "--min-size", type=int,
        help="capture only allocations larger than this size")
parser.add_argument("-Z", "--max-size", type=int,
        help="capture only allocations smaller than this size")
parser.add_argument("-O", "--obj", type=str, default="c",
        help="attach to allocator functions in the specified object")
parser.add_argument("--ebpf", action="store_true",
        help=argparse.SUPPRESS)
parser.add_argument("--percpu", default=False, action="store_true",
        help="trace percpu allocations")

args = parser.parse_args()

pid = args.pid
command = args.command
kernel_trace = (pid == -1 and command is None)
trace_all = args.trace
interval = args.interval
min_age_ns = 1e6 * args.older
sample_every_n = args.sample_rate
num_prints = args.count
top_stacks = args.top
min_size = args.min_size
max_size = args.max_size
obj = args.obj

if min_size is not None and max_size is not None and min_size > max_size:
        print("min_size (-z) can't be greater than max_size (-Z)")
        exit(1)

if command is not None:
        print("Executing '%s' and tracing the resulting process." % command)
        pid = run_command_get_pid(command)

bpf_source = """
#include <uapi/linux/ptrace.h>

struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
};

struct combined_alloc_info_t {
        u64 total_size;
        u64 number_of_allocs;
};

BPF_HASH(sizes, u64);
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);
BPF_HASH(memptrs, u64, u64);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(combined_allocs, u64, struct combined_alloc_info_t, 10240);

static inline void update_statistics_add(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        cinfo.total_size += sz;
        cinfo.number_of_allocs += 1;

        combined_allocs.update(&stack_id, &cinfo);
}

static inline void update_statistics_del(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        if (sz >= cinfo.total_size)
                cinfo.total_size = 0;
        else
                cinfo.total_size -= sz;

        if (cinfo.number_of_allocs > 0)
                cinfo.number_of_allocs -= 1;

        combined_allocs.update(&stack_id, &cinfo);
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
        SIZE_FILTER
        if (SAMPLE_EVERY_N > 1) {
                u64 ts = bpf_ktime_get_ns();
                if (ts % SAMPLE_EVERY_N != 0)
                        return 0;
        }

        u64 pid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        sizes.update(&pid, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\\n", size);
        return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
        u64 pid = bpf_get_current_pid_tgid();
        u64* size64 = sizes.lookup(&pid);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&pid);

        if (address != 0) {
                info.timestamp_ns = bpf_ktime_get_ns();
                info.stack_id = stack_traces.get_stackid(ctx, STACK_FLAGS);
                allocs.update(&address, &info);
                update_statistics_add(info.stack_id, info.size);
        }

        if (SHOULD_PRINT) {
                bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n",
                                 info.size, address);
        }
        return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);
        update_statistics_del(info->stack_id, info->size);

        if (SHOULD_PRINT) {
                bpf_trace_printk("free entered, address = %lx, size = %lu\\n",
                                 address, info->size);
        }
        return 0;
}

int malloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int malloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int free_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size) {
        return gen_alloc_enter(ctx, nmemb * size);
}

int calloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) {
        gen_free_enter(ctx, ptr);
        return gen_alloc_enter(ctx, size);
}

int realloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int mmap_enter(struct pt_regs *ctx) {
        size_t size = (size_t)PT_REGS_PARM2(ctx);
        return gen_alloc_enter(ctx, size);
}

int mmap_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int munmap_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment,
                         size_t size) {
        u64 memptr64 = (u64)(size_t)memptr;
        u64 pid = bpf_get_current_pid_tgid();

        memptrs.update(&pid, &memptr64);
        return gen_alloc_enter(ctx, size);
}

int posix_memalign_exit(struct pt_regs *ctx) {
        u64 pid = bpf_get_current_pid_tgid();
        u64 *memptr64 = memptrs.lookup(&pid);
        void *addr;

        if (memptr64 == 0)
                return 0;

        memptrs.delete(&pid);

        if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
                return 0;

        u64 addr64 = (u64)(size_t)addr;
        return gen_alloc_exit2(ctx, addr64);
}

int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int aligned_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int valloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int valloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int memalign_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int memalign_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int pvalloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int pvalloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}
"""

bpf_source_kernel_node = """

TRACEPOINT_PROBE(kmem, kmalloc_node) {
        if (WORKAROUND_MISSING_FREE)
            gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc_node) {
        if (WORKAROUND_MISSING_FREE)
            gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}
"""

bpf_source_kernel = """

TRACEPOINT_PROBE(kmem, kmalloc) {
        if (WORKAROUND_MISSING_FREE)
            gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kfree) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc) {
        if (WORKAROUND_MISSING_FREE)
            gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
        gen_alloc_enter((struct pt_regs *)args, PAGE_SIZE << args->order);
        return gen_alloc_exit2((struct pt_regs *)args, args->pfn);
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->pfn);
}
"""

bpf_source_percpu = """

TRACEPOINT_PROBE(percpu, percpu_alloc_percpu) {
        gen_alloc_enter((struct pt_regs *)args, args->size);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(percpu, percpu_free_percpu) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}
"""

if kernel_trace:
        if args.percpu:
                bpf_source += bpf_source_percpu
        else:
                bpf_source += bpf_source_kernel
                if BPF.tracepoint_exists("kmem", "kmalloc_node"):
                        bpf_source += bpf_source_kernel_node

if kernel_trace:
    bpf_source = bpf_source.replace("WORKAROUND_MISSING_FREE", "1"
                                    if args.wa_missing_free else "0")

bpf_source = bpf_source.replace("SHOULD_PRINT", "1" if trace_all else "0")
bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(sample_every_n))
bpf_source = bpf_source.replace("PAGE_SIZE", str(resource.getpagesize()))
