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
int count_sche