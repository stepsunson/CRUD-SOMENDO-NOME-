#!/usr/bin/python
#
# An example usage of stack_build_id
# Most of the code here is borrowed from tools/profile.py
#
# Steps for using this code
# 1) Start ping program in one terminal eg invocation: ping google.com -i0.001
# 2) Change the path of libc specified in b.add_module() below
# 3) Invoke the script as 'python stack_buildid_example.py'
# 4) o/p of the tool is as shown below
#  python example/tracing/stack_buildid_example.py
#    sendto
#    -                ping (5232)
#        2
#
# REQUIRES: Linux 4.17+ (BPF_BUILD_ID support)
# Licensed under the Apache License, Version 2.0 (the "License")
# 03-Jan-2019  Vijay Nag

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from sys import stderr
from time import sleep
import argparse
import signal
import os
import subprocess
import errno
import multiprocessing
import ctypes as ct

def Get_libc_path():
  # A small helper function that returns full path
  # of libc in the system
  cmd = 'cat /proc/self/maps | grep libc | awk \'{print $6}\' | uniq'
  output = subprocess.check_output(cmd, shell=True)
  if not isinstance(output, str):
    output = output.decode()
  return output.split('\n')[0]

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE_BUILDID(stack_traces, 128);

int do_perf_event(struct bpf_perf_event_data *