#!/usr/bin/env python
#
# klockstat traces lock events and display locks statistics.
#
# USAGE: klockstat
#

from __future__ import print_function
from bcc import BPF, USDT
import argparse
import subprocess
import ctypes as ct
from time import sleep, strftime
from datetime import datetime, timedelta
import errno
from sys import stderr

examples = """
    klockstat                           # trace system wide
    klockstat -d 5                      # trace for 5 seconds only
    klockstat -i 5                      # display stats every 5 seconds
    klockstat -p 123                    # trace locks for PID 123
    klockstat -t 321                    # trace locks for PID 321
    klockstat -c pipe_                  # display stats only for lock callers with 'pipe_' substring
    klockstat -S acq_count              # sort lock acquired results on acquired count
    klockstat -S hld_total              # sort lock held results on total held time
    klockstat -S acq_count,hld_total    # combination of above
    klockstat -n 3 