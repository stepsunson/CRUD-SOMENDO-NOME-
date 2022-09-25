#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from netaddr import IPAddress
from bcc import BPF
from pyroute2 import IPRoute, protocols
from socket import socket, AF_INET, SOCK_DGRAM
from subprocess import call
import sys
from time import sleep
from unittest import main, TestCase

arg1 = sys.argv.pop(1).encode()
arg2 = "".encode()
if len(sys.argv) > 1:
  arg2 = sys.argv.pop(1)

class TestBPFFilter(TestCase):
    def setUp(self):
        b = BPF(arg1, arg2, debug=0)
        fn = b.load_func(b"on_packet", BPF.SCHED_ACT)
        ip = IPRoute()
        ifindex = ip.link_lookup(ifname=b"eth0")[0]
        # set up a network to change the flow:
        #             outside      |       inside
        # 172.16.1.1 - 1