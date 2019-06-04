#!/usr/bin/python
# author: https://github.com/agentzex
# Licensed under the Apache License, Version 2.0 (the "License")

# tcp_mon_block.py - uses netlink TC, kernel tracepoints and kprobes to monitor outgoing connections from given PIDs
# and block connections to all addresses initiated from them (acting like an in-process firewall), unless they are listed in allow_list

# outputs blocked connections attempts from monitored processes
# Usage:
#   python3 tcp_mon_block.py -i network_interface_name
#   python3 tcp_mon_block.py -v -i network_interface_name (-v --verbose - will output all connections attempts, including allowed ones)
#


from bcc import BPF
import pyroute2
import socket
import struct
import json
import argparse
from urllib.parse import urlparse


# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


verbose_states = {
    1: "Connection not allowed detected - forwarding to block",
    2: "Connection allowed",
    3: "Connection destroyed",
}


def get_verbose_message(state):
    if state not in verbose_states:
        return ""

    return verbose_states[state]


def parse_tcp_flags(flags):
    found_flags = ""
    if flags & FIN:
        found_flags += "FIN; "
    if flags & SYN:
        found_flags += "SYN; "
    if flags & RST:
        found_flags += "RST; "
    if flags & PSH:
        found_flags += "PSH; "
    if flags & ACK:
        found_flags += "ACK; "
    if flags & URG:
        found_flags += "URG; "
    if flags & ECE:
        found_flags += "ECE; "
    if flags & CWR:
        found_flags += "CWR;"

    return found_flags


def ip_to_network_address(ip):
    return struct.unpack("I", socket.inet_aton(ip))[0]


def network_address_to_ip(ip):
    return socket.inet_ntop(socket.AF_INET, struct.pack("I", ip))


def parse_address(url_or_ip):
    is_ipv4 = True
    domain = ""

    #first check if valid ipv4
    try:
        socket.inet_aton(url_or_ip)
    except socket.error:
        is_ipv4 = False

    if is_ipv4:
        return [url_or_ip]

    # if not check if valid URL, parse and get its domain, resolve it to IPv4 and return it
    try:
        domain = urlparse(url_or_ip).netloc
    except:
        print(f"[-] {url_or_ip} is invalid IPv4 or URL")
        return False

    # should get a list of IPv4 addresses resolved from the domain
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(domain)
    except:
        print(f"[-] Failed to resolve {url_or_ip} to Ipv4")
        return False

    return i