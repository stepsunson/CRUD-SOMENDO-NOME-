#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This is an example of tracing an event and printing custom fields.
# run in project examples directory with:
# sudo ./trace_fields.py"

import atexit
from bcc import BPF
from bcc.utils import printb
import ctypes as ct

class Data(ct.Structure):
    _fields_ = [("ts", ct.c_ulonglong),
                ("magic", ct.c_ulonglong)]

counter = 0
def cb(cpu, data, size):
    assert size >= ct.sizeof(Data)
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("[%0d] %f: %x" % (cpu, float(event.ts) / 1000000, event.magic))
    global counter
    counter += 1

prog = """
BPF_PERF_OUTPUT(events);
BPF_ARRAY(counters, u64, 10);
int do_sys_clone(void *ctx) {
  struct {
    u64 ts;
    u64 magic;
  } data = {bpf_ktime_get_ns(), 0x12345678};
  int rc;
  if ((rc = events.perf_submit(ctx, &data, sizeof(data))) < 0)
    bpf_trace_printk("perf_output failed: %d\\n", rc);
  int zero = 0;
  u64 *val = counters.lookup(&zero);
  if (val) lock_xad