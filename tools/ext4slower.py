#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# ext4slower  Trace slow ext4 operations.
#             For Linux, uses BCC, eBPF.
#
# USAGE: ext4slower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common ext4 file operations: reads, writes, opens, and
# syncs. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these ext4 operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very freque