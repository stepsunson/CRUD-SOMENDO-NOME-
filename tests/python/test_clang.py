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
        t = b.get_table(b"stats")
        s1 = t.key_sprintf(t.Key(2))
        self.assertEqual(s1, b"0x2")
        s2 = t.leaf_sprintf(t.Leaf((ct.c_uint * 3)(1,2,3), 4))
        self.assertEqual(s2, b"{ [ 0x1 0x2 0x3 ] 0x4 }")
        l = t.leaf_scanf(s2)
        self.assertEqual(l.a[0], 1)
        self.assertEqual(l.a[1], 2)
        self.assertEqual(l.a[2], 3)
        self.assertEqual(l.b, 4)

    @skipUnless(lib.bpf_module_rw_engine_enabled(), "requires enabled rwengine")
    def test_sscanf_string(self):
        text = b"""
struct Symbol {
    char name[128];
    char path[128];
};
struct Event {
    uint32_t pid;
    uint32_t tid;
    struct Symbol stack[64];
};
BPF_TABLE("array", int, struct Event, comms, 1);
"""
        b = BPF(text=text)
        t = b.get_table(b"comms")
        s1 = t.leaf_sprintf(t[0])
        fill = b' { "" "" }' * 63
        self.assertEqual(s1, b'{ 0x0 0x0 [ { "" "" }%s ] }' % fill)
        l = t.Leaf(1, 2)
        name = b"libxyz"
        path = b"/usr/lib/libxyz.so"
        l.stack[0].name = name
        l.stack[0].path = path
        s2 = t.leaf_sprintf(l)
        self.assertEqual(s2,
                b'{ 0x1 0x2 [ { "%s" "%s" }%s ] }' % (name, path, fill))
        l = t.leaf_scanf(s2)
        self.assertEqual(l.pid, 1)
        self.assertEqual(l.tid, 2)
        self.assertEqual(l.stack[0].name, name)
        self.assertEqual(l.stack[0].path, path)

    def test_iosnoop(self):
        text = b"""
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

struct key_t {
    struct request *req;
};

BPF_HASH(start, struct key_t, u64, 1024);
int do_request(struct pt_regs *ctx, struct request *req) {
    struct key_t key = {};

    bpf_trace_printk("traced start %d\\n", req->__data_len);

    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func(b"do_request", BPF.KPROBE)

    def test_blk_start_request(self):
        text = b"""
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>
int do_request(struct pt_regs *ctx, int req) {
    bpf_trace_printk("req ptr: 0x%x\\n", req);
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func(b"do_request", BPF.KPROBE)

    def test_bpf_hash(self):
        text = b"""
BPF_HASH(table1);
BPF_HASH(table2, u32);
BPF_HASH(table3, u32, int);
"""
        b = BPF(text=text, debug=0)

    def test_consecutive_probe_read(self):
        text = b"""
#include <linux/fs.h>
#include <linux/mount.h>
BPF_HASH(table1, struct super_block *);
int trace_entry(struct pt_regs *ctx, struct file *file) {
    if (!file) return 0;
    struct vfsmount *mnt = file->f_path.mnt;
    if (mnt) {
        struct super_block *k = mnt->mnt_sb;
        u64 zero = 0;
        table1.update(&k, &zero);
        k = mnt->mnt_sb;
        table1.update(&k, &zero);
    }

    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func(b"trace_entry", BPF.KPROBE)

    def test_nested_probe_read(self):
        text = b"""
#include <linux/fs.h>
int trace_entry(struct pt_regs *ctx, struct file *file) {
    if (!file) return 0;
    const char *name = file->f_path.dentry->d_name.name;
    bpf_trace_printk("%s\\n", name);
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func(b"trace_entry", BPF.KPROBE)

    def test_nested_probe_read_deref(self):
        text = b"""
#include <uapi/linux/ptrace.h>
struct sock {
    u32 *sk_daddr;
};
int test(struct pt_regs *ctx, struct sock *skp) {
    return *(skp->sk_daddr);
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"test", BPF.KPROBE)

    def test_char_array_probe(self):
        BPF(text=b"""#include <linux/blkdev.h>
int kprobe__blk_update_request(struct pt_regs *ctx, struct request *req) {
    bpf_trace_printk("%s\\n", req->rq_disk->disk_name);
    return 0;
}""")

    @skipUnless(kernel_version_ge(5,7), "requires kernel >= 5.7")
    def test_lsm_probe(self):
        # Skip if the kernel is not compiled with CONFIG_BPF_LSM
        if not BPF.support_lsm():
            return
        b = BPF(text=b"""
LSM_PROBE(bpf, int cmd, union bpf_attr *uattr, unsigned int size) {
    return 0;
}""")

    def test_probe_read_helper(self):
        b = BPF(text=b"""
#include <linux/fs.h>
static void print_file_name(struct file *file) {
    if (!file) return;
    const char *name = file->f_path.dentry->d_name.name;
    bpf_trace_printk("%s\\n", name);
}
static void print_file_name2(int unused, struct file *file) {
    print_file_name(file);
}
int trace_entry1(struct pt_regs *ctx, struct file *file) {
    print_file_name(file);
    return 0;
}
int trace_entry2(struct pt_regs *ctx, int unused, struct file *file) {
    print_file_name2(unused, file);
    return 0;
}
""")
        fn = b.load_func(b"trace_entry1", BPF.KPROBE)
        fn = b.load_func(b"trace_entry2", BPF.KPROBE)

    def test_probe_unnamed_union_deref(self):
        text = b"""
#include <linux/mm_types.h>
int trace(struct pt_regs *ctx, struct page *page) {
    void *p = page->mapping;
    return p != NULL;
}
"""
        # depending on llvm, compile may pass/fail, but at least shouldn't crash
        try:
            b = BPF(text=text)
        except:
            pass

    def test_probe_struct_assign(self):
        b = BPF(text = b"""
#include <uapi/linux/ptrace.h>
struct args_t {
    const char *filename;
    int flags;
    int mode;
};
int do_sys_open(struct pt_regs *ctx, const char *filename,
        int flags, int mode) {
    struct args_t args = {};
    args.filename = filename;
    args.flags = flags;
    args.mode = mode;
    bpf_trace_printk("%s\\n", args.filename);
    return 0;
};
""")
        b.attach_kprobe(event=b.get_syscall_fnname(b"open"),
                        fn_name=b"do_sys_open")

    def test_task_switch(self):
        b = BPF(text=b"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct key_t {
  u32 prev_pid;
  u32 curr_pid;
};
BPF_HASH(stats, struct key_t, u64, 1024);
int kprobe__finish_task_switch(struct pt_regs *ctx, struct task_struct *prev) {
  struct key_t key = {};
  u64 zero = 0, *val;
  key.curr_pid = bpf_get_current_pid_tgid();
  key.prev_pid = prev->pid;

  val = stats.lookup_or_try_init(&key, &zero);
  if (val) {
    (*val)++;
  }
  return 0;
}
""")

    def test_probe_simple_assign(self):
        b = BPF(text=b"""
#include <uapi/linux/ptrace.h>
#include <linux/gfp.h>
struct leaf { size_t size; };
BPF_HASH(simple_map, u32, struct leaf);
int kprobe____kmalloc(struct pt_regs *ctx, size_t size) {
    u32 pid = bpf_get_current_pid_tgid();
    struct leaf* leaf = simple_map.lookup(&pid);
    if (leaf)
        leaf->size += size;
    return 0;
}""")

    def test_probe_simple_member_assign(self):
        b = BPF(text=b"""
#include <uapi/linux/ptrace.h>
#include <linux/netdevice.h>
struct leaf { void *ptr; };
int test(struct pt_regs *ctx, struct sk_buff *skb) {
    struct leaf l = {};
    struct leaf *lp = &l;
    lp->ptr = skb;
    return 0;
}""")
        b.load_func(b"test", BPF.KPROBE)

    def test_probe_member_expr_deref(self):
        b = BPF(text=b"""
#include <uapi/linux/ptrace.h>
#include <linux/netdevice.h>
struct leaf { struct sk_buff *ptr; };
int test(struct pt_regs *ctx, struct sk_buff *skb) {
    struct leaf l = {};
    struct leaf *lp = &l;
    lp->ptr = skb;
    return lp->ptr->priority;
}""")
        b.load_func(b"test", BPF.KPROBE)

    def test_probe_member_expr(self):
        b = BPF(text=b"""
#include <uapi/linux/ptrace.h>
#include <linux/netdevice.h>
struct leaf { struct sk_buff *ptr; };
int test(struct pt_regs *ctx, struct sk_buff *skb) {
    struct leaf l = {};
    struct leaf *lp = &l;
    lp->ptr = skb;
    return l.ptr->priority;
}""")
        b.load_func(b"test", BPF.KPROBE)

    def test_unop_probe_read(self):
        text = b"""
#include <linux/blkdev.h>
int trace_entry(struct pt_regs *ctx, struct request *req) {
    if (!(req->bio->bi_flags & 1))
        return 1;
    if (((req->bio->bi_flags)))
        return 1;
    return 0;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"trace_entry", BPF.KPROBE)

    def test_probe_read_nested_deref(self):
        text = b"""
#include <net/inet_sock.h>
int test(struct pt_regs *ctx, struct sock *sk) {
    struct sock *ptr1;
    struct sock **ptr2 = &ptr1;
    *ptr2 = sk;
    return ((struct sock *)(*ptr2))->sk_daddr;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"test", BPF.KPROBE)

    def test_probe_read_nested_deref2(self):
        text = b"""
#include <net/inet_sock.h>
int test(struct pt_regs *ctx, struct sock *sk) {
    struct sock *ptr1;
    struct sock **ptr2 = &ptr1;
    struct sock ***ptr3 = &ptr2;
    *ptr2 = sk;
    *ptr3 = ptr2;
    return ((struct sock *)(**ptr3))->sk_daddr;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"test", BPF.KPROBE)

    def test_probe_read_nested_deref3(self):
        text = b"""
#include <net/inet_sock.h>
int test(struct pt_regs *ctx, struct sock *sk) {
    struct sock **ptr1, **ptr2 = &sk;
    ptr1 = &sk;
    return (*ptr1)->sk_daddr + (*ptr2)->sk_daddr;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"test", BPF.KPROBE)

    def test_probe_read_nested_deref_func1(self):
        text = b"""
#include <net/inet_sock.h>
static struct sock **subtest(struct sock **sk) {
    return sk;
}
int test(struct pt_regs *ctx, struct sock *sk) {
    struct sock **ptr1, **ptr2 = subtest(&sk);
    ptr1 = subtest(&sk);
    return (*ptr1)->sk_daddr + (*ptr2)->sk_daddr;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"test", BPF.KPROBE)

    def test_probe_read_nested_deref_func2(self):
        text = b"""
#include <net/inet_sock.h>
static int subtest(struct sock ***skp) {
    return ((struct sock *)(**skp))->sk_daddr;
}
int test(struct pt_regs *ctx, struct sock *sk) {
    struct sock *ptr1;
    struct sock **ptr2 = &ptr1;
    struct sock ***ptr3 = &ptr2;
    *ptr2 = sk;
    *ptr3 = ptr2;
    return subtest(ptr3);
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"test", BPF.KPROBE)

    def test_probe_read_nested_member1(self):
        text = b"""
#include <net/inet_sock.h>
int test(struct pt_regs *ctx, struct sock *skp) {
    u32 *daddr = &skp->sk_daddr;
    return *daddr;
}
"""
        b = BPF(text=text)
        fn = b.load_func(b"test", BPF.KPROBE)

    def test_probe_read_nested_member2(self):
        text = b"""
#include <uapi/linux/ptrace.h>
struct sock {
    u32 **sk_daddr;
};
int test(struct pt_regs *ctx, struct sock *skp) {
    u32 *daddr = *(skp->sk_daddr);
    return *daddr;
}
"""
        b