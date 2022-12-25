
#!/usr/bin/env python
#
# solisten      Trace TCP listen events
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: solisten.py [-h] [-p PID] [--show-netns]
#
# This is provided as a basic example of TCP connection & socket tracing.
# It could be useful in scenarios where load balancers needs to be updated
# dynamically as application is fully initialized.
#
# All IPv4 and IPv6 listen attempts are traced, even if they ultimately fail
# or the the listening program is not willing to accept().
#
# Copyright (c) 2016 Jean-Tiare Le Bigot.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 04-Mar-2016	Jean-Tiare Le Bigot	Created this.

import os
from socket import inet_ntop, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM
from struct import pack
import argparse
from bcc import BPF
from bcc.utils import printb

# Arguments
examples = """Examples:
    ./solisten.py              # Stream socket listen
    ./solisten.py -p 1234      # Stream socket listen for specified PID only
    ./solisten.py --netns 4242 # " for the specified network namespace ID only
    ./solisten.py --show-netns # Show network ns ID (useful for containers)
"""

parser = argparse.ArgumentParser(
    description="Stream sockets listen",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--show-netns", action="store_true",
    help="show network namespace")
parser.add_argument("-p", "--pid", default=0, type=int,
    help="trace this PID only")
parser.add_argument("-n", "--netns", default=0, type=int,
    help="trace this Network Namespace only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)


# BPF Program
bpf_text = """
#include <net/net_namespace.h>
#include <bcc/proto.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/inet_sock.h>
#pragma clang diagnostic pop

// Common structure for UDP/TCP IPv4/IPv6