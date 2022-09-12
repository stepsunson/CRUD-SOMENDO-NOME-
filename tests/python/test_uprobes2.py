#!/usr/bin/env python3
#
# USAGE: test_uprobe2.py
#
# Copyright 2020 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from unittest import main, TestCase
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile


class TestUprobes(TestCase):
    def setUp(self):
        lib_text = b"""
__attribute__((__visibility__("default"))) void fun()
{
}
"""
        self.bpf_text = b"""
int trace_fun_call(void *ctx) {{
    return 1;
}}
"""
        # Compile and run the application
        self.fte