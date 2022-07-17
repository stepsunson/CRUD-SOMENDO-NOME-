#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF, BPFAttachType, BPFProgType
from bcc.libbcc import lib
import ctypes as ct
from unittest import main, skipUnless, TestCase
from utils import kernel_version_ge
import os
import sys
import socket
import struct
from contextlib import contextmanager

@contextmanager
def redirect_stderr(to):
    stderr_fd = sys.stderr.fileno()
    with os.fdopen(os.dup(stderr_fd), 'wb') as copied, os.fdopen(to, 'w') as to:
        sys.stderr.flush()
        os.dup2(to.fileno(), stderr_fd)
        try:
            yield sys.stderr
        finally:
            sys.stderr.flush()
            os.dup2(copied.fileno(), stderr_fd)

class TestClang(TestCase):
    def test_complex(self):
        b = BPF(src_file=b"test_clang_complex.c", debug=0)
        fn = b.load_func(b"handle_packet", BPF.SCHED_CLS)
    def test_printk(self):
        text = b"""
#include <bcc/proto.h>
int handle_packet(void *ctx) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  bpf_trace_printk("ethernet->dst = %llx, ethernet->src = %llx\\n",
                   ethernet->dst, ethernet->src);
  return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func(b"handle_packet", BPF.SCHED_CLS)

    def test_probe_read1(self):
        text = b"""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    pid_t p = prev->pid;
    return (p != -1);
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func(b"count_sched", BPF.KPROBE)

    def test_load_cgroup_sockopt_prog(self):
        text = b"""
int sockopt(struct bpf_sockopt* ctx){

    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn =  b.load_func(b"sockopt", BPFProgType.CGROUP_SOCKOPT, device = None, attach_type = BPFAttachType.CGROUP_SETSOCKOPT)

    def test_probe_read2(self):
        text = b"""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
int count_foo(struct pt_regs *ctx, unsigned long a, unsigned long b) {
    return (a != b);
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func(b"count_foo", BPF.KPROBE)

    def test_probe_read3(self):
        text = b"""
#include <net/tcp.h>
#define _(P) ({typeof(P) val = 0; bpf_probe_read_kernel(&val, sizeof(val), &P); val;})
int count_tcp(struct pt_regs *ctx, struct sk_buff *skb) {
    return _(TCP_SKB_CB(skb)->tcp_gso_size);
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"count_tcp", BPF.KPROBE)

    def test_probe_read4(self):
        text = b"""
#include <net/tcp.h>
#define _(P) ({typeof(P) val = 0; bpf_probe_read_kernel(&val, sizeof(val), &P); val;})
int test(struct pt_regs *ctx, struct sk_buff *skb) {
    return _(TCP_SKB_CB(skb)->tcp_gso_size) + skb->protocol;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"test", BPF.KPROBE)

    def test_probe_read_whitelist1(self):
        text = b"""
#include <net/tcp.h>
int count_tcp(struct pt_regs *ctx, struct sk_buff *skb) {
    // The below define is in net/tcp.h:
    //    #define TCP_SKB_CB(__skb)	((struct tcp_skb_cb *)&((__skb)->cb[0]))
    // Note that it has AddrOf in the macro, which will cause current rewriter
    // failing below statement
    // return TCP_SKB_CB(skb)->tcp_gso_size;
    u16 val = 0;
    bpf_probe_read_kernel(&val, sizeof(val), &(TCP_SKB_CB(skb)->tcp_gso_size));
    return val;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"count_tcp", BPF.KPROBE)

    def test_probe_read_whitelist2(self):
        text = b"""
#include <net/tcp.h>
int count_tcp(struct pt_regs *ctx, struct sk_buff *skb) {
    // The below define is in net/tcp.h:
    //    #define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))
    // Note that it has AddrOf in the macro, which will cause current rewriter
    // failing below statement
    // return TCP_SKB_CB(skb)->tcp_gso_size;
    u16 val = 0;
    bpf_probe_read_kernel(&val, sizeof(val), &(TCP_SKB_CB(skb)->tcp_gso_size));
    return val + skb->protocol;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"count_tcp", BPF.KPROBE)

    def test_probe_read_keys(self):
        text = b"""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
BPF_HASH(start, struct request *);
int do_request(struct pt_regs *ctx, struct request *req) {
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

int do_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp = start.lookup(&req);
    if (tsp != 0) {
        start.delete(&req);
    }
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fns = b.load_funcs(BPF.KPROBE)

    @skipUnless(lib.bpf_module_rw_engine_enabled(), "requires enabled rwengine")
    def test_sscanf(self):
        text = b"""
BPF_HASH(stats, int, struct { u64 a; u64 b; u64 c:36; u64 d:28; struct { u32 a; u32 b; } s; }, 10);
int foo(void *ctx) {
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func(b"foo", BPF.KPROBE)
        t = b.get_table(b"stats")
        s1 = t.key_sprintf(t.Key(2))
        self.assertEqual(s1, b"0x2")
        s2 = t.leaf_sprintf(t.Leaf(2, 3, 4, 1, (5, 6)))
        l = t.leaf_scanf(s2)
        self.assertEqual(l.a, 2)
        self.assertEqual(l.b, 3)
        self.assertEqual(l.c, 4)
        self.assertEqual(l.d, 1)
        self.assertEqual(l.s.a, 5)
        self.assertEqual(l.s.b, 6)

    @skipUnless(lib.bpf_module_rw_engine_enabled(), "requires enabled rwengine")
    def test_sscanf_array(self):
        text = b"""
BPF_HASH(stats, int, struct { u32 a[3]; u32 b; }, 10);
"""
        b = BPF(text=text, debug=0)
        t = b.get_table(b"stat