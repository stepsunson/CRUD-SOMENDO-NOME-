
#!/usr/bin/env python
#
# trace         Trace a function and print a trace message based on its
#               parameters, with an optional filter.
#
# usage: trace [-h] [-p PID] [-L TID] [-v] [-Z STRING_SIZE] [-S] [-c cgroup_path]
#              [-M MAX_EVENTS] [-s SYMBOLFILES] [-T] [-t] [-K] [-U] [-a] [-I header]
#              [-A]
#              probe [probe ...]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from __future__ import print_function
from bcc import BPF, USDT, StrcmpRewrite
from functools import partial
from time import strftime
import time
import argparse
import re
import ctypes as ct
import os
import traceback
import sys

class Probe(object):
        probe_count = 0
        streq_index = 0
        max_events = None
        event_count = 0
        first_ts = 0
        first_ts_real = None
        print_time = False
        print_unix_timestamp = False
        use_localtime = True
        time_field = False
        print_cpu = False
        print_address = False
        tgid = -1
        pid = -1
        uid = -1
        page_cnt = None
        build_id_enabled = False
        aggregate = False
        symcount = {}

        @classmethod
        def configure(cls, args):
                cls.max_events = args.max_events
                cls.print_time = args.timestamp or args.time
                cls.print_unix_timestamp = args.unix_timestamp
                cls.use_localtime = not args.timestamp
                cls.time_field = cls.print_time and (not cls.use_localtime)
                cls.print_cpu = args.print_cpu
                cls.print_address = args.address
                cls.first_ts = BPF.monotonic_time()
                cls.first_ts_real = time.time()
                cls.tgid = args.tgid or -1
                cls.pid = args.pid or -1
                cls.uid = args.uid or -1
                cls.page_cnt = args.buffer_pages
                cls.bin_cmp = args.bin_cmp
                cls.build_id_enabled = args.sym_file_list is not None
                cls.aggregate = args.aggregate
                if cls.aggregate and cls.max_events is None:
                        raise ValueError("-M/--max-events should be specified"
                                         " with -A/--aggregate")

        def __init__(self, probe, string_size, kernel_stack, user_stack,
                     cgroup_map_name, name, msg_filter):
                self.usdt = None
                self.streq_functions = ""
                self.raw_probe = probe
                self.string_size = string_size
                self.kernel_stack = kernel_stack
                self.user_stack = user_stack
                self.probe_user_list = set()
                Probe.probe_count += 1
                self._parse_probe()
                self.probe_num = Probe.probe_count
                self.probe_name = "probe_%s_%d" % \
                                (self._display_function(), self.probe_num)
                self.probe_name = re.sub(r'[^A-Za-z0-9_]', '_',
                                         self.probe_name)
                self.cgroup_map_name = cgroup_map_name
                if name is None:
                    # An empty bytestring is always contained in the command
                    # name so this will always succeed.
                    self.name = b''
                else:
                    self.name = name.encode('ascii')
                self.msg_filter = msg_filter
                # compiler can generate proper codes for function
                # signatures with "syscall__" prefix
                if self.is_syscall_kprobe:
                        self.probe_name = "syscall__" + self.probe_name[6:]

        def __str__(self):
                return "%s:%s:%s FLT=%s ACT=%s/%s" % (self.probe_type,
                        self.library, self._display_function(), self.filter,
                        self.types, self.values)

        def is_default_action(self):
                return self.python_format == ""

        def _bail(self, error):
                raise ValueError("error in probe '%s': %s" %
                                 (self.raw_probe, error))

        def _parse_probe(self):
                text = self.raw_probe

                # There might be a function signature preceding the actual
                # filter/print part, or not. Find the probe specifier first --
                # it ends with either a space or an open paren ( for the
                # function signature part.
                #                                          opt. signature
                #                               probespec       |      rest
                #                               ---------  ----------   --
                (spec, sig, rest) = re.match(r'([^ \t\(]+)(\([^\(]*\))?(.*)',
                                             text).groups()

                self._parse_spec(spec)
                # Remove the parens
                self.signature = sig[1:-1] if sig else None
                if self.signature and self.probe_type in ['u', 't']:
                        self._bail("USDT and tracepoint probes can't have " +
                                   "a function signature; use arg1, arg2, " +
                                   "... instead")

                text = rest.lstrip()
                # If we now have a (, wait for the balanced closing ) and that
                # will be the predicate
                self.filter = None
                if len(text) > 0 and text[0] == "(":
                        balance = 1
                        for i in range(1, len(text)):
                                if text[i] == "(":
                                        balance += 1
                                if text[i] == ")":
                                        balance -= 1
                                if balance == 0:
                                        self._parse_filter(text[:i + 1])
                                        text = text[i + 1:]
                                        break
                        if self.filter is None:
                                self._bail("unmatched end of predicate")

                if self.filter is None:
                        self.filter = "1"

                # The remainder of the text is the printf action
                self._parse_action(text.lstrip())
