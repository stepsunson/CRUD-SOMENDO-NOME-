#!/usr/bin/env python3
# Copyright (c) 2016 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import unittest
from bcc import BPF

class TestSharedTable(unittest.TestCase):
    def test_close_extern(self):
        b1 = BPF(text=b"""BPF_TABLE_PUBLIC("array", int, int, table1, 10);""")

        with BP