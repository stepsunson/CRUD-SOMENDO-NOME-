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
      event4.perf_submit(ctx, &result, sizeof(result));
    return 0;
};
int do_trace2(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int result = 0;
    bpf_usdt_readarg(1, ctx, &result);
    if (FILTER)
      event2.perf_submit(ctx, &result, sizeof(result));
    else
      event5.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
int do_trace3(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int result = 0;
    bpf_usdt_readarg(1, ctx, &result);
    if (FILTER)
      event3.perf_submit(ctx, &result, sizeof(result));
    else
      event6.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
"""

        # Compile and run the application
        self.ftemp = NamedTemporaryFile(delete=False)
        self.ftemp.close()
        comp = Popen(["gcc", "-I", "%s/include" % os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))),
                      "-x", "c++", "-o", self.ftemp.name, "-"],
                     stdin=PIPE)
        comp.stdin.write(app_text)
        comp.stdin.close()
        self.assertEqual(comp.wait(), 0)

        # create 3 applications, 2 applications will have usdt attached and
        # the third one does not, and the third one should not call into
        # bpf program.
        self.app = Popen([self.ftemp.name, "1"])
        self.app2 = Popen([self.ftemp.name, "11"])
        self.app3 = Popen([self.ftemp.name, "21"])

    def test_attach1(self):
        # Enable USDT probe from given PID and verifier generated BPF programs.
        u = USDT(pid=int(self.app.pid))
        u.enable_probe(probe="probe_point_1", fn_name="do_trace1")
        u.enable_probe(probe="probe_point_2", fn_name="do_trace2")
        u2 = USDT(pid=int(self.app2.pid))
        u2.enable_probe(probe="probe_point_2", fn_name="do_trace2")
        u2.enable_probe(probe="probe_point_3", fn_name="do_trace3")
        self.bpf_text = self.bpf_text.replace(b"FILTER", b"pid == %d" % self.app.pid)
        b = BPF(text=self.bpf_text, usdt_contexts=[u, u2])

        # Event states for each event:
        # 0 - probe not 