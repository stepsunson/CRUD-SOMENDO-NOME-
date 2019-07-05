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
parser.add_argument("-i", "