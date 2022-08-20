#!/usr/bin/env python3
# Copyright (c) 2017 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import os
from unittest import main, skipUnless, TestCase
from utils import kernel_version_ge
from bcc import BPF
from netaddr import IPAddress

class KeyV4(ct.Structure):
    _fields_ = [("prefixlen", ct.c_uint),
                ("data", ct.c_ubyte * 4)]

class KeyV6(ct.Structure):
    _fields_ = [("prefixlen", ct.c_uint),
                ("data", ct.c_ushort * 8)]

@skipUnless(kernel_version_ge(4, 11), "requires kernel >= 4.11")
class TestLpmTrie(TestCase):
    def t