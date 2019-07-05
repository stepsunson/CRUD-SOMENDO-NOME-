#!/usr/bin/python
import argparse
from time import sleep, strftime
from sys import argv
import ctypes as ct
from bcc import BPF, USDT
import inspect
import os

# Parse command line arguments
parser = argparse.ArgumentParser(description="Trace the moving average of the latency of an operation using usdt probes.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, help="The id of the process to trace.")
parser.add_argument("-i", "--interval", type=int, help="The interval in seconds on which to report the latency distribution.")
parser.add_argument("-c", "--count", type=int, default=16, help="The maximum number of samples over which to calculate the moving average.")
parser.add_argument("-f", "--filterstr", type=str, default="", help="The prefix filter for the operation input. If specified, only operations for which the input string starts with the filterstr are traced.")
parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="If true, will output generated bpf program and verbose logging information.")
parser.add_argument("-s", "--sdt", dest="sdt", action="store_true", help="If true, will use the probes, created by systemtap's dtrace.")

parser.set_defaults(verbose=False)
args = parser.parse_args()
this_pid = int(args.pid)
this_interval = int(args.interval)
this_maxsamplesize = int(args.count)
this_filter = str(args.filterstr)

if this_interval < 1:
    print("Invalid value for interval, using 1.")
    this_interval = 1

if this_maxsamplesize < 1:
    print("Invalid value for this_maxsamplesize, using 1.")
    this_maxsamplesize = 1

debugLevel=0
if args.verbose:
    debugLevel=4

# BPF program
bpf_text_shared = "%s/bpf_text_shared.c" % os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
bpf_text = open(bpf_text_shared, 'r').read()
bpf_text += """

const u32 max_sample_size = MAX_SAMPLE_SIZE;

struct hash_key_t
{
    char input[64]; // The operation id is used as key
};

struct hash_leaf_t
{
    u32 sample_size;    // Number of operation samples taken
    u64 total;          // Cumulative duration of the operations
    u64 average;        // Moving average duration of the operations
};

/**
 * @brief Contains the averages for the operation latencies by operation input.
 */
BPF_HASH(lat_hash, struct hash_key_t, struct hash_leaf_t, 512);

/**
 * @brief Reads the operation response arguments, calculates the latency, and stores it in the histogram.
 * @param ctx The BPF con