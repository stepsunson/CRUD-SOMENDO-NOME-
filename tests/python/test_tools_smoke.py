#!/usr/bin/env python3
# Copyright (c) Sasha Goldshtein, 2017
# Licensed under the Apache License, Version 2.0 (the "License")

import distutils.version
import subprocess
import os
import re
from unittest import main, skipUnless, TestCase
from utils import mayFail, kernel_version_ge

TOOLS_DIR = "/bcc/tools/"

def _helpful_rc_msg(rc, allow_early, kill):
    s = "rc was %d\n" % rc
    if rc == 0:
        s += "\tMeaning: command returned successfully before test timeout\n"
    elif rc == 124:
        s += "\tMeaning: command was killed by INT signal\n"
    elif rc == 137:
        s += "\tMeaning: command was killed by KILL signal\n"

    s += "Command was expected to do one of:\n"
    s += "\tBe killed by SIGINT\n"
    if kill:
        s += "\tBe killed by SIGKILL\n"
    if allow_early:
        s += "\tSuccessfully return before being killed\n"

    return s

@skipUnless(kernel_version_ge(4,1), "requires kernel >= 4.1")
class SmokeTests(TestCase):
    # Use this for commands that have a built-in timeout, so they only need
    # to be killed in case of a hard hang.
    def run_with_duration(self, command, timeout=10):
        full_command = TOOLS_DIR + command
        self.assertEqual(0,     # clean exit
                subprocess.call("timeout -s KILL %ds %s > /dev/null" %
                                (timeout, full_command), shell=True))

    # Use this for commands that don't have a built-in timeout, so we have
    # to Ctrl-C out of them by sending SIGINT. If that still doesn't stop
    # them, send a kill signal 5 seconds later.
    def run_with_int