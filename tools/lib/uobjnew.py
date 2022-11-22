#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# uobjnew  Summarize object allocations in high-level languages.
#          For Linux, uses BCC, eBPF.
#
# USAGE: uobjnew [-h] [-T TOP] [-v] {c,java,ruby,tcl} pid [interval]
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, utils
from time import sleep
import os

# C needs to be the last language.
languages = ["c", "java", "ruby", "tcl"]

examples = """examples:
    ./uobjnew -l java 145         # summarize Java allocations in process 145
    ./uobjnew 