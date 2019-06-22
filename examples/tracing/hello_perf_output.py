#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>

// define