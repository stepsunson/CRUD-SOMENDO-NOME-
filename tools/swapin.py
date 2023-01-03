#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# swapin        Count swapins by process.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# TODO: add -s for total swapin time column (sum)
#
# Copyright (c) 2019 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License").
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-13: 9780136554820
# When copying or porting, include this comment.
#
# 03-Jul-2019   Brendan Gregg   Ported from bpftrace to BCC.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
parser = argparse.ArgumentParser(
    description="Count swapin events by process.")
parser.add_argument("-T", "--notime", action="store_true",
    help="do not show the timestamp (HH:MM:SS)")
p