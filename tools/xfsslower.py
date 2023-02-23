#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# xfsslower  Trace slow XFS operations.
#            For Linux, uses BCC, eBPF.
#
# USAGE: xfsslower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common XFS file operations: reads, writes, opens, and
# syncs. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these XFS operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# By default, a minimum millisecond threshold of 10 is us