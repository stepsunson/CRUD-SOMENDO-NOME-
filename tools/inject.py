#!/usr/bin/env python
#
# This script generates a BPF program with structure inspired by trace.py. The
# generated program operates on PID-indexed stacks. Generally speaking,
# bookkeeping is done at every intermediate function kprobe/kretprobe to enforce
# the goal of "fail iff this call chain and these predicates".
#
# Top level functions(the ones at the end of the call chain) are responsible for
# creating the pid_struct and deleting it from the map in kprobe and kretprobe
# respectively.
#
# Intermediate functions(between should_fail_whatever and the top level
# functions) are responsible for updating the stack to indicate "I have been
# called and one of my predicate(s) passed" in their entry probes. In their exit
# probes, they do the opposite, popping their stack to maintain correctness.
# This implementation aims to ensure correctness in edge cases like recursive
# calls, so there's some additional information stored in pid_struct for that.
#
# At the bottom level function(should_fail_whatever), we do a simple check to
# ensure all necessary calls/predicates have passed before error injection.
#
# Note: presently there are a few hacks to get around various rewriter/verifier
# issues.
#
# Note: this tool requires:
# - CONFIG_BPF_KPROBE_OVERRIDE
#
# USAGE: inject [-h] [-I header] [-P probability] [-v] mode spec
#
# Copyright (c) 2018 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Mar-2018   Howard McLauchlan   Created this.

import argparse
import re
from bcc import BPF


class Probe:
    errno_mapping = {
        "kmalloc": "-ENOMEM",
        "bio": "-EIO",
        "alloc_page" : "true",
    }

    @classmethod
    def configure(cls, mode, probability, count):
        cls.mode = mode
        cls.probability = probability
        cls.count = count

    def __init__(self, func, preds, length, entry):
        # length of call chain
        self.length = length
        self.func = func
        self.preds = preds
        self.is_entry = entry

    def _bail(self, err):
        raise ValueError("error in probe '%s': %s" %
                (self.spec, err))

    def _get_err(self):
        return Probe.errno_mapping[Probe.mode]

    def _get_if_top(self):
        # ordering guarantees that if this function is top, the last tup is top
        chk = self.preds[0][1] == 0
        if not chk:
            return ""

        if Probe.probability == 1:
            early_pred = "false"
        else:
            early_pred = "bpf_get_prandom_u32() > %s" % str(int((1<<32)*Probe.probability))
        # init the map
        # don't do an early exit here so the singular case works automatically
        # have an early exit for probability option
        enter = """
        /*
         * Early exit for probability case
         */
        if (%s)
               return 0;
        /*
         * Top level function init map
         */
        struct pid_struct p_struct = {0, 0};
        m.insert(&pid, &p_struct);
        """ % early_pred

        # kill the entry
        exit = """
        /*
         * Top level function clean up map
         */
        m.delete(&pid);
        """

        return enter if self.is_entry else exit

    def _get_heading(self):

        # we need to insert identifier and ctx into self.func
        # gonna make a lot of formatting assumptions to ma