#!/usr/bin/env python
#
# tcpv4tracer   Trace TCP connections.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4tracer [-h] [-v] [-p PID] [-N NETNS] [-4 | -6]
#
# You should generally try to avoid writing long scripts that measure multiple
# functions and walk multiple kernel structures, as they will be a burden to
# maintain as the kernel changes.
# The following code should be replaced, and simplified, when static TCP probes
# exist.
#
# Copyright 2017-2020 Kinvolk GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License")
from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers

import argparse as ap
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

parser = ap.ArgumentParser(description="Trace TCP connections",
                           formatter_class=ap.RawDescriptionHelpFormatter)
parser.add_argument("-t", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-p", "--pid", default=0, type=int,
                    help="trace this PID only")
parser.add_argument("-N", "--netns", default=0, type=int,
                    help="trace this Network Namespace only")
parser.add_argument("--cgroupmap",
                    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
                    help="trace mount namespaces in this BPF map only")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
                    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
                   help="trace IPv6 family only")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="include Network Namespace in the o