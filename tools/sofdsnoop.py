
#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# sofdsnoop traces file descriptors passed via socket
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: sofdsnoop
#
# Copyright (c) 2018 Jiri Olsa.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-Jul-2018   Jiri Olsa   Created this.

from __future__ import print_function
from bcc import ArgString, BPF
import os
import argparse
from datetime import datetime, timedelta

# arguments
examples = """examples:
    ./sofdsnoop           # trace passed file descriptors
    ./sofdsnoop -T        # include timestamps
    ./sofdsnoop -p 181    # only trace PID 181
    ./sofdsnoop -t 123    # only trace TID 123
    ./sofdsnoop -d 10     # trace for 10 seconds only
    ./sofdsnoop -n main   # only print process names containing "main"

"""
parser = argparse.ArgumentParser(
    description="Trace file descriptors passed via socket",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
args = parser.parse_args()
debug = 0

ACTION_SEND=0
ACTION_RECV=1
MAX_FD=10

if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <net/sock.h>

#define MAX_FD 10
#define ACTION_SEND   0
#define ACTION_RECV   1

struct val_t {
    u64  id;
    u64  ts;
    int  action;
    int  sock_fd;
    int  fd_cnt;
    int  fd[MAX_FD];
    char comm[TASK_COMM_LEN];
};

BPF_HASH(detach_ptr, u64, struct cmsghdr *);
BPF_HASH(sock_fd, u64, int);
BPF_PERF_OUTPUT(events);

static void set_fd(int fd)
{
    u64 id = bpf_get_current_pid_tgid();

    sock_fd.update(&id, &fd);
}

static int get_fd(void)
{
    u64 id = bpf_get_current_pid_tgid();
    int *fd;

    fd = sock_fd.lookup(&id);
    return fd ? *fd : -1;
}

static void put_fd(void)
{
    u64 id = bpf_get_current_pid_tgid();

    sock_fd.delete(&id);
}

static int sent_1(struct pt_regs *ctx, struct val_t *val, int num, void *data)
{
    val->fd_cnt = min(num, MAX_FD);

    if (bpf_probe_read_kernel(&val->fd[0], MAX_FD * sizeof(int), data))
        return -1;

    events.perf_submit(ctx, val, sizeof(*val));
    return 0;
}

#define SEND_1                                  \
    if (sent_1(ctx, &val, num, (void *) data))  \
        return 0;                               \
                                                \
    num -= MAX_FD;                              \
    if (num < 0)                                \
        return 0;                               \
                                                \
    data += MAX_FD;

#define SEND_2   SEND_1 SEND_1
#define SEND_4   SEND_2 SEND_2
#define SEND_8   SEND_4 SEND_4
#define SEND_260 SEND_8 SEND_8 SEND_8 SEND_2

static int send(struct pt_regs *ctx, struct cmsghdr *cmsg, int action)
{
    struct val_t val = { 0 };
    int *data, num, fd;
    u64 tsp = bpf_ktime_get_ns();

    data = (void *) ((char *) cmsg + sizeof(struct cmsghdr));
    num  = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);

    val.id      = bpf_get_current_pid_tgid();
    val.action  = action;
    val.sock_fd = get_fd();
    val.ts      = tsp / 1000;