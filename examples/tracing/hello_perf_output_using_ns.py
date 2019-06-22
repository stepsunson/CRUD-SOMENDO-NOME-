#!/usr/bin/python
# Carlos Neira <cneirabustos@gmail.com>
# This is a Hello World example that uses BPF_PERF_OUTPUT.
# in this example bpf_get_ns_current_pid_tgid(), this helper
# works inside pid namespaces.
# bpf_get_current_pid_tgid() only returns the host pid outside any
# namespace and this will not work when the script is run inside a pid namespace.

from bcc import BPF
from bcc.utils import printb
import sys, os
from stat import *

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    struct bpf_pidns_info ns = {};

    if(bpf_get_ns_current_pid_tgid(DEV, INO, &ns, sizeof(struct bpf_pidns_info)))
	return 0;
    data.pid = ns.pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

