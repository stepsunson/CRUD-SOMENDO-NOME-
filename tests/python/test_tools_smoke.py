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
    def run_with_int(self, command, timeout=5, kill_timeout=5,
                     allow_early=False, kill=False):
        full_command = TOOLS_DIR + command
        signal = "KILL" if kill else "INT"
        rc = subprocess.call("timeout -s %s -k %ds %ds %s > /dev/null" %
                (signal, kill_timeout, timeout, full_command), shell=True)
        # timeout returns 124 if the program did not terminate prematurely,
        # and returns 137 if we used KILL instead of INT. So there are three
        # sensible scenarios:
        #   1. The script is allowed to return early, and it did, with a
        #      success return code.
        #   2. The script timed out and was killed by the SIGINT signal.
        #   3. The script timed out and was killed by the SIGKILL signal, and
        #      this was what we asked for using kill=True.
        self.assertTrue((rc == 0 and allow_early) or rc == 124
                        or (rc == 137 and kill), _helpful_rc_msg(rc,
                        allow_early, kill))

    def kmod_loaded(self, mod):
        with open("/proc/modules", "r") as mods:
            reg = re.compile("^%s\s" % mod)
            for line in mods:
                if reg.match(line):
                    return 1
                return 0

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_argdist(self):
        self.run_with_duration("argdist.py -v -C 'p::do_sys_open()' -n 1 -i 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_bashreadline(self):
        self.run_with_int("bashreadline.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_bindsnoop(self):
        self.run_with_int("bindsnoop.py")

    def test_biolatency(self):
        self.run_with_duration("biolatency.py 1 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_biosnoop(self):
        self.run_with_int("biosnoop.py")

    def test_biotop(self):
        self.run_with_duration("biotop.py 1 1")

    def test_bitesize(self):
        self.run_with_int("biotop.py")

    def test_bpflist(self):
        self.run_with_duration("bpflist.py")

    def test_btrfsdist(self):
        # Will attempt to do anything meaningful only when btrfs is installed.
        self.run_with_duration("btrfsdist.py 1 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_btrfsslower(self):
        # Will attempt to do anything meaningful only when btrfs is installed.
        self.run_with_int("btrfsslower.py", allow_early=True)

    def test_cachestat(self):
        self.run_with_duration("cachestat.py 1 1")

    def test_cachetop(self):
        # TODO cachetop doesn't like to run without a terminal, disabled
        # for now.
        # self.run_with_int("cachetop.py 1")
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_capable(self):
        self.run_with_int("capable.py")

    def test_cpudist(self):
        self.run_with_duration("cpudist.py 1 1")

    @skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_cpuunclaimed(self):
        self.run_with_duration("cpuunclaimed.py 1 1")

    @skipUnless(kernel_version_ge(4,17), "requires kernel >= 4.17")
    def test_compactsnoop(self):
        self.run_with_int("compactsnoop.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_dbslower(self):
        # Deliberately left empty -- dbslower requires an instance of either
        # MySQL or PostgreSQL to be running, or it fails to attach.
        pass

    @skipUnless(kernel_version_ge(4,3), "requires kernel >= 4.3")
    def test_dbstat(self):
        # Deliberately left empty -- dbstat requires an instance of either
        # MySQL or PostgreSQL to be running, or it fails to attach.
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_dcsnoop(self):
        self.run_with_int("dcsnoop.py")

    def test_dcstat(self):
        self.run_with_duration("dcstat.py 1 1")

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    def test_deadlock(self):