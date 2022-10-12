
#!/usr/bin/env python
#
# bashreadline  Print entered bash commands from all running shells.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: bashreadline [-s SHARED]
# This works by tracing the readline() function using a uretprobe (uprobes).
# When you failed to run the script directly with error:
# `Exception: could not determine address of symbol b'readline'`,
# you may need specify the location of libreadline.so library
# with `-s` option.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Jan-2016    Brendan Gregg   Created this.
# 12-Feb-2016    Allan McAleavy migrated to BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
from time import strftime
import argparse

parser = argparse.ArgumentParser(
        description="Print entered bash commands from all running shells",
        formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-s", "--shared", nargs="?",
        const="/lib/libreadline.so", type=str,
        help="specify the location of libreadline.so library.\
              Default is /lib/libreadline.so")
args = parser.parse_args()