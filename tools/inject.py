#!/usr/bin/env python
#
# This script generates a BPF program with structure inspired by trace.py. The
# generated program operates on PID-indexed stacks. Generally speaking,
# bookkeeping is done at every intermediate function kprobe/kretprobe to enforce
# the goal of "fail iff this call chain and these predicates".
#
# Top level functions(the ones at the end of the call chain) are responsible for
# creating the pid_struct and deleting it from the map in kprobe and kretprobe
# respectively.
#
# Intermediate functions(between should_fail_whatever and the top level
# functions) are responsible for updating the stack to indicate "I have been
# called and one of my predicate(s) passed" in their entry probes. In their exit
# probes, they do the opposite, popping their stack to maintain correctness.
# This implementation aims to ensure correctness in edge cases like recursive
# calls, so there's some additional information stored in pid_struct for that.
#
# At the bottom level function(should_fail_whatever), we do a simple check to
# ensure all necessary calls/predicates have passed before error injection.
#
# Note: presently there are a few hacks to get 