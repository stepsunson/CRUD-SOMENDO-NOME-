#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from ctypes import c_uint, c_int, c_ulonglong, Structure
import json
from netaddr import IPAddress
from os import rename
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
import sys
from time import sleep

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

b = BPF(src_file="monitor.c", debug=0)
ingress_fn = b.load_func("handle_ingress", BPF.SCHED_CLS)
egress_fn = b.load_func("handle_egress", BPF.SCHED_CLS)
outer_fn = b.load_func("handle_outer", BPF.SCHED_CLS)
inner_fn = b.load_func("handle_inner", BPF.SCHED_CLS)
stats = b.get_table("stats")
# using jump table for inner and outer packet split
parser = b.get_table("parser")
parser[c_int(1)] = c_int(outer_fn.fd)
parser[c_int(2)] = c_int(inner_fn.fd)

ifc = ipdb.interfaces.eth0

ipr.tc("add", "ingress", ifc.index, "ffff:")
ipr.tc("add-filter", "bpf", ifc.index, ":1", fd=ingress_fn.fd,
       name=ingress_fn.name, parent="ffff:", action="ok", classid=1)
ipr.tc("add", "sfq", ifc.index, "1:")
ipr.tc("add-filter", "bpf", ifc.index, ":1", fd=egress_fn.fd,
       name=egress_fn.name, parent="1:", action="ok", classid=1)

def stats2json(k, v):
    return {
        "vni": int(k.vni),
        "outer_sip": str(IPAddress(k.outer_sip)),
        "outer_dip": str(IPAddress(k.outer_dip)),
        "inner_sip": str(IPAddress(k.inner_sip)),
        "inner_dip": str(IPAddress(k.inner_dip)),
        "tx_pkts": v.tx_pkts, "tx_bytes": v.tx_bytes,
        "rx_pkts": v.rx_pkts, "rx_bytes": v.rx_bytes,
    }

def delta_stats(v, oldv):
    return stats.Leaf(v.tx_pkts - oldv.tx_pkts, v.rx_pkts - oldv.rx_pkts,
                      v.tx_bytes - oldv.tx_bytes, v.rx_bytes - oldv.rx_bytes)
def key2str(k):
    return "%s,%s,%d,%s,%s" % (IPAddress(k.outer_sip), IPAddress(k.outer_dip), k.vni,
                               IPAddress(k.inner_sip), IPAddress(k.inner_dip))

prev = {}

while True:
    result_total = []
    result_delt