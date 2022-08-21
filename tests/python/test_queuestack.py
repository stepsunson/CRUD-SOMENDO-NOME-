#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import os
import ctypes as ct

from bcc import BPF

from unittest import main, TestCase, skipUnless
from utils import kernel_version_ge

@skipUnless(kernel_version_ge(4,20), "requires kernel >= 4.20")
class TestQueueStack(TestCase):
