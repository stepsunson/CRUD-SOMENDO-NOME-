#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# zfsslower  Trace slow ZFS operations.
#            For Linux, uses BCC, eBPF.
#
# USAGE: zfsslower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common ZFS file operations: reads, writes, opens, and
# syncs. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these ZFS operations,
# including reads and writes from the file system cache. Suc