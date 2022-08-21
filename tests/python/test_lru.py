#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import os
import unittest
from bcc import BPF
import multiprocessing

class TestLru(unittest.TestCase):
    def test_lru_hash(self):
        b = BPF(text=b"""BPF_TABLE("lru_hash", int, u64, lru, 1024);""")
        t = b[b"lru"]
        for i in range(1, 1032):
            t[ct.c_int(i)] = ct.c_ulonglong(i)
        for i, v in t.items():
            s