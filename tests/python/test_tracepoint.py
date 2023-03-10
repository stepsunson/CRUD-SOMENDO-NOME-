
#!/usr/bin/env python3
# Copyright (c) Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import unittest
from time import sleep
from utils import kernel_version_ge
import os
import subprocess

@unittest.skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
class TestTracepoint(unittest.TestCase):
    def test_tracepoint(self):
        text = b"""
        BPF_HASH(switches, u32, u64);
        TRACEPOINT_PROBE(sched, sched_switch) {
            u64 val = 0;
            u32 pid = args->next_pid;
            u64 *existing = switches.lookup_or_init(&pid, &val);
            (*existing)++;
            return 0;
        }
        """
        b = bcc.BPF(text=text)
        sleep(1)
        total_switches = 0
        for k, v in b[b"switches"].items():
            total_switches += v.value
        self.assertNotEqual(0, total_switches)

@unittest.skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
class TestTracepointDataLoc(unittest.TestCase):
    def test_tracepoint_data_loc(self):
        text = b"""
        struct value_t {
            char filename[64];
        };
        BPF_HASH(execs, u32, struct value_t);
        TRACEPOINT_PROBE(sched, sched_process_exec) {
            struct value_t val = {0};
            char fn[64];
            u32 pid = args->pid;
            struct value_t *existing = execs.lookup_or_init(&pid, &val);
            TP_DATA_LOC_READ_CONST(fn, filename, 64);
            __builtin_memcpy(existing->filename, fn, 64);
            return 0;
        }
        """
        b = bcc.BPF(text=text)
        subprocess.check_output(["/bin/ls"])
        sleep(1)
        self.assertTrue("/bin/ls" in [v.filename.decode()
                                      for v in b[b"execs"].values()])

if __name__ == "__main__":
    unittest.main()