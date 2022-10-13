#!/usr/bin/env python
#
# biolatpcts.py  Monitor IO latency distribution of a block device.
#
#  $ ./biolatpcts.py /dev/nvme0n1
#  nvme0n1    p1    p5   p10   p16   p25   p50   p75   p84   p90   p95   p99  p100
#  read     95us 175us 305us 515us 895us 985us 995us 1.5ms 2.5ms 3.5ms 4.5ms  10ms
#  write     5us   5us   5us  15us  25us 135us 765us 855us 885us 895us 965us 1.5ms
#  discard   5us   5us   5us   5us 135us 145us 165us 205us 385us 875us 1.5ms 2.5ms
#  flush     5us   5us   5us   5us   5us   5us   5us   5us   5us 1.5ms 4.5ms 5.5ms
#
# Copyright (C) 2020 Tejun Heo <tj@kernel.org>
# Copyright (C) 2020 Facebook

from __future__ import print_function
from bcc import BPF
from time import sleep
from threading import Event
import argparse
import json
import sys
import os
import signal

description = """
Monitor IO latency distribution of a block device
"""

epilog = """
When interval is infinite, biolatpcts will print out result once the
initialization is complete to indicate readiness. After initialized,
biolatpcts will output whenever it receives SIGUSR1/2 and before exiting on
SIGINT, SIGTERM or SIGHUP.

SIGUSR1 starts a new period after reporting. SIGUSR2 doesn't and can be used
to monitor progress without affecting accumulation of data points. They can
be used to obtain latency distribution between two arbitrary events and
monitor progress inbetween.
"""

parser = argparse.ArgumentParser(description = description, epilog = epilog,
                                 formatter_class = argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('dev', metavar='DEV', type=str,
                    help='Target block device (/dev/DEVNAME, DEVNAME or MAJ:MIN)')
parser.add_argument('-i', '--interval', type=int, default=3,
                    help='Report interval (0: exit after startup, -1: infinite)')
parser.add_argument('-w', '--which', choices=['from-rq-alloc', 'after-rq-alloc', 'on-device'],
                    default='on-device', help='Which latency to measure')
parser.add_argument('-p', '--pcts', metavar='PCT,...', type=str,
                    default='1,5,10,16,25,50,75,84,90,95,99,100',
                    help='Percentiles to calculate')
parser.add_argument('-j', '--json', action='store_true',
                    help='Output in json')
parser.add_argument('--verbose', '-v', action='count', default = 0)

bpf_source = """
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/time64.h>

BPF_PERCPU_ARRAY(rwdf_100ms, u64, 400);
BPF_PERCPU_ARRAY(rwdf_1ms, u64, 400);
BPF_PERCPU_ARRAY(rwdf_10us, u64, 400);

RAW_TRACEPOINT_PROBE(block_rq_complete)
{
        // TP_PROTO(struct request *rq, blk_status_t error, unsigned int nr_bytes)
        struct request *rq = (void *)ctx->args[0];
        unsigned int cmd_flags;
        u64 dur;
        size_t base, slot;

        if (!rq->__START_TIME_FIELD__)
                return 0;

        if (!rq->__RQ_DISK__ ||
            rq->__RQ_DISK__->major != __MAJOR__ ||
            rq->__RQ_DISK__->first_minor != __MINOR__)
                return 0;

        cmd_flags = rq->cmd_flags;
        switch (cmd_flags & REQ_OP_MASK) {
        case REQ_OP_READ:
                base = 0;
                break;
        case REQ_OP_WRITE:
                base = 100;
                break;
        case REQ_OP_DISCARD:
                base = 200;
                break;
        case REQ_OP_FLUSH:
                base = 300;
                break;
        default:
                return 0;
        }

        dur = bpf_ktime_get_ns() - rq->__START_TIME_FIELD__;

        slot = min_t(size_t, div_u64(dur, 100 * NSEC_PER_MSEC), 99);
        rwdf_100ms.increment(base + slot);
        if (slot)
                return 0;

        slot = min_t(size_t, div_u64(dur, NSEC_PER_MSEC), 99);
        rwdf_1ms.increment(base + slot);
        if (slot)
                return 0;

        slot = min_t(size_t, div_u64(dur, 