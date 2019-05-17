#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from sys import argv
from bcc import BPF
from builtins import input
from ctypes import c_int, c_uint
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
from netaddr import EUI, IPAddress
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from socket import htons, AF_INET
from threading import Thread
from subprocess import call

host_id = int(argv[1])

b = BPF(src_file="tunnel.c")
ingress_fn = b.load_func("handle_ingress", BPF.SCHED_CLS)
egress_fn = b.load_func("handle_egress", BPF.SCHED_CLS)
mac2host = b.get_table("mac2host")
vni2if = b.get_table("vni2if")
conf = b.get_table("conf")

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

ifc = ipdb.interfaces.eth0
mcast = IPAddress("239.1.1.1")

# ifcs to cleanup at the end
ifc_gc = []

def run():
    ipdb.routes.add({"dst": "224.0.0.0/4", "oif": ifc.index}).commit()
   