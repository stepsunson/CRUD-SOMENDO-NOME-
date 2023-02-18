
#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# ttysnoop   Watch live output from a tty or pts device.
#            For Linux, uses BCC, eBPF. Embedded C.
#
# Due to a limited buffer size (see BUFSIZE), some commands (eg, a vim
# session) are likely to be printed a little messed up.
#
# Copyright (c) 2016 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Idea: from ttywatcher.
#
# 15-Oct-2016   Brendan Gregg   Created this.
# 13-Dec-2022   Rong Tao        Detect whether kfunc is supported.
# 07-Jan-2023   Rong Tao        Support ITER_UBUF(CO-RE way)

from __future__ import print_function
from bcc import BPF
from subprocess import call
import argparse
from sys import argv
import sys
from os import stat

def usage():
    print("USAGE: %s [-Ch] {PTS | /dev/ttydev}  # try -h for help" % argv[0])
    exit()

# arguments
examples = """examples:
    ./ttysnoop /dev/pts/2          # snoop output from /dev/pts/2
    ./ttysnoop 2                   # snoop output from /dev/pts/2 (shortcut)
    ./ttysnoop /dev/console        # snoop output from the system console
    ./ttysnoop /dev/tty0           # snoop output from /dev/tty0
    ./ttysnoop /dev/pts/2 -s 1024  # snoop output from /dev/pts/2 with data size 1024
    ./ttysnoop /dev/pts/2 -c 2     # snoop output from /dev/pts/2 with 2 checks for 256 bytes of data in buffer
                                     (potentially retrieving 512 bytes)
"""
parser = argparse.ArgumentParser(
    description="Snoop output from a pts or tty device, eg, a shell",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("device", default="-1",
    help="path to a tty device (eg, /dev/tty0) or pts number")
parser.add_argument("-s", "--datasize", default="256",
    help="size of the transmitting buffer (default 256)")
parser.add_argument("-c", "--datacount", default="16",
    help="number of times we check for 'data-size' data (default 16)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

if args.device == "-1":
    usage()

path = args.device
if path.find('/') != 0:
    path = "/dev/pts/" + path
try:
    pi = stat(path)
except:
    print("Unable to read device %s. Exiting." % path)
    exit()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/uio.h>

#define BUFSIZE USER_DATASIZE
struct data_t {
    int count;
    char buf[BUFSIZE];
};

BPF_ARRAY(data_map, struct data_t, 1);
PERF_TABLE

static int do_tty_write(void *ctx, const char __user *buf, size_t count)
{
    int zero = 0, i;
    struct data_t *data;

/* We can't read data to map data before v4.11 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    struct data_t _data = {};

    data = &_data;
#else
    data = data_map.lookup(&zero);
    if (!data)
        return 0;