#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ustat  Activity stats from high-level languages, including exceptions,
#        method calls, class loads, garbage collections, and more.
#        For Linux, uses BCC, eBPF.
#
# USAGE: ustat [-l {java,node,perl,php,python,ruby,tcl}] [-C]
#        [-S {cload,excp,gc,method,objnew,thread}] [-r MAXROWS] [-d]
#        [interval [count]]
#
# This uses in-kernel eBPF maps to store per process summaries for efficiency.
# Newly-created processes might only be traced at the next interval, if the
# relevant USDT probe requires enabling through a semaphore.
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 26-Oct-2016   Sasha Goldshtein    Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, USDTException
import os
import sys
from subprocess import call
from time import sleep, strftime

class Category(object):
    THREAD = "THREAD"
    METHOD = "METHOD"
    OBJNEW = "OBJNEW"
    CLOAD = "CLOAD"
    EXCP = "EXCP"
    GC = "GC"

class Probe(object):
    def __init__(self, language, procnames, events):
        """
        Initialize a new probe object with a specific language, set of process
        names to monitor for that language, and a dictionary of events and
        categories. The dictionary is a mapping of USDT probe names (such as
        'gc__start') to event categories supported by this tool -- from the
        Category class.
        """
        self.language = language
        self.procnames = procnames
        self.events = events

    def _find_targets(self):
        """Find pids where the comm is one of the specified list"""
        self.targets = {}
        all_pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]
        for pid in all_pids:
            try:
                comm = open('/proc/%d/comm' % pid).read().strip()
                if comm in self.procnames:
                    cmdline = open('/proc/%d/cmdline' % pid).rea