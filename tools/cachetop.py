
#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# cachetop      Count cache kernel function calls per processes
#               For Linux, uses BCC, eBPF.
#
# USAGE: cachetop
# Taken from cachestat by Brendan Gregg
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jul-2016   Emmanuel Bretelle first version
# 17-Mar-2022   Rocky Xing        Added PID filter support.

from __future__ import absolute_import
from __future__ import division
# Do not import unicode_literals until #623 is fixed
# from __future__ import unicode_literals
from __future__ import print_function

from bcc import BPF
from collections import defaultdict
from time import strftime

import argparse
import curses
import pwd
import re
import signal
from time import sleep

FIELDS = (
    "PID",
    "UID",
    "CMD",
    "HITS",
    "MISSES",
    "DIRTIES",
    "READ_HIT%",
    "WRITE_HIT%"