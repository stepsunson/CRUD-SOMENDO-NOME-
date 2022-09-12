#!/usr/bin/env python3
#
# USAGE: test_usdt2.py
#
# Copyright 2017 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
from unittest import main, TestCase
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile
import ctypes as ct
import inspect
import os
import signal

class TestUDST(TestCase):
    def setUp(self):
        # Application, minimum, to define three trace points
        app_text = b"""
#include <stdlib.h>
#include <unistd.h>
#include "folly/tracing/StaticTracepoint.h"

int main(int argc, char **argv) {
  int t = atoi(argv[1]);
  while (1) {
    FOLLY_SDT(test, probe_point_1, t);
    FOLLY_SDT(test, probe_point_2, t + 1);
    FOLLY_SDT(test, probe_point_3, t + 2);
    sleep(1);
  }
  return 1;
}
"""
        # BPF program
        self.bpf_text = b"""
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(event1);
BPF_PERF_OUTPUT(event2);
BPF_PERF_OUTPUT(event3);
BPF_PERF_OUTPUT(event4);
BPF_PERF_OUTPUT(event5);
BPF_PERF_OUTPUT(event6);

int do_trace1(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int result = 0;
    bpf_usdt_readarg(1, ctx, &result);
    if (FILTER)
      event1.perf_submit(ctx, &result, sizeof(result));
    else
      event4.perf_submit(ctx, &re