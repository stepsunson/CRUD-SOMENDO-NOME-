
#!/usr/bin/env python3
#
# USAGE: test_usdt.py
#
# Copyright 2018 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from unittest import main, skipUnless, TestCase
from subprocess import Popen, PIPE
from utils import kernel_version_ge
import os

class TestFreeLLVMMemory(TestCase):
    def getRssFile(self):
        with Popen(["cat", "/proc/" + str(os.getpid()) + "/status"],
                  stdout=PIPE) as p:
            rss = None
            unit = None
            for line in p.stdout.readlines():
                if (line.find(b'RssFile') >= 0):
                    rss  = line.split(b' ')[-2]
                    unit = line.split(b' ')[-1].rstrip()
                    break

            return [rss, unit]

    @skipUnless(kernel_version_ge(4,5), "requires kernel >= 4.5")
    def testFreeLLVMMemory(self):
        text = b"int test() { return 0; }"
        b = BPF(text=text)

        # get the RssFile before freeing bcc memory
        [rss1, unit1] = self.getRssFile()
        self.assertTrue(rss1 != None)

        # free the bcc memory
        self.assertTrue(b.free_bcc_memory() == 0)

        # get the RssFile after freeing bcc memory
        [rss2, unit2] = self.getRssFile()
        self.assertTrue(rss2 != None)

        self.assertTrue(unit1 == unit2)

        print("Before freeing llvm memory: RssFile: ", rss1, unit1)
        print("After  freeing llvm memory: RssFile: ", rss2, unit2)
        self.assertTrue(rss1 > rss2)

if __name__ == "__main__":
    main()