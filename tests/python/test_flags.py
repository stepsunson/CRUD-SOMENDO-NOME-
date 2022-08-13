#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import unittest
from bcc import BPF

class TestLru(unittest.TestCase):
    def test_lru_map_flags(self):
        test_prog1 = b"""
        BPF_F_TABLE("lru_hash", int, u64, lru, 1024, BPF_F_NO_COMMON_LRU);
        """
        b