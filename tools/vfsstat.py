#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# vfsstat   Count some VFS calls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of counting multiple events as a stat tool.
#
# USAGE: vfsstat [-h] [-p PID] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Aug-2015   Brendan Gregg   Created this.
# 12-Oct-2022   Rocky Xing      Added PID filter support.

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strf