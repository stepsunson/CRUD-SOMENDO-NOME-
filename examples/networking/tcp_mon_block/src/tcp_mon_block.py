#!/usr/bin/python
# author: https://github.com/agentzex
# Licensed under the Apache License, Version 2.0 (the "License")

# tcp_mon_block.py - uses netlink TC, kernel tracepoints and kprobes to monitor outgoing connections from given PIDs
# and block connections to all addresses initiated from them (acting like an in-process firewall), unless they are listed in allow_list

# outputs blocked connections attempts from monitored processes
# Usage:
#   python3 tcp_mon_block.py -i network_interface_name
#   python3 tcp_mon_block