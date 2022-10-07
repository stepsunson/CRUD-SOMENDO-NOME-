
#!/usr/bin/env python
#
# argdist   Trace a function and display a distribution of its
#           parameter values as a histogram or frequency count.
#
# USAGE: argdist [-h] [-p PID] [-z STRING_SIZE] [-i INTERVAL] [-n COUNT] [-v]
#                [-c] [-T TOP] [-C specifier] [-H specifier] [-I header]
#                [-t TID]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF, USDT, StrcmpRewrite
from time import sleep, strftime
import argparse
import re
import traceback
import os
import sys

class Probe(object):
        next_probe_index = 0
        streq_index = 0
        aliases = {"$PID": "(bpf_get_current_pid_tgid() >> 32)"}

        def _substitute_aliases(self, expr):
                if expr is None:
                        return expr
                for alias, subst in Probe.aliases.items():
                        expr = expr.replace(alias, subst)
                return expr

        def _parse_signature(self):
                params = map(str.strip, self.signature.split(','))
                self.param_types = {}
                for param in params:
                        # If the type is a pointer, the * can be next to the
                        # param name. Other complex types like arrays are not
                        # supported right now.
                        index = param.rfind('*')
                        index = index if index != -1 else param.rfind(' ')
                        param_type = param[0:index + 1].strip()
                        param_name = param[index + 1:].strip()
                        self.param_types[param_name] = param_type
                        # Maintain list of user params. Then later decide to
                        # switch to bpf_probe_read_kernel or bpf_probe_read_user.
                        if "__user" in param_type.split():