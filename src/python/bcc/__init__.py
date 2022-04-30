# Copyright 2015 PLUMgrid
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
import atexit
import ctypes as ct
import fcntl
import json
import os
import re
import errno
import sys
import platform

from .libbcc import lib, bcc_symbol, bcc_symbol_option, bcc_stacktrace_build_id, _SYM_CB_TYPE
from .table import Table, PerfEventArray, RingBuf, BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK
from .perf import Perf
from .utils import get_online_cpus, printb, _assert_is_bytes, ArgString, StrcmpRewrite
from .version import __version__
from .disassembler import disassemble_prog, decode_map
from .usdt import USDT, USDTException

try:
    basestring
except NameError:  # Python 3
    basestring = str

_default_probe_limit = 1000
_num_open_probes = 0

# for tests
def _get_num_open_probes():
    global _num_open_probes
    return _num_open_probes

DEBUGFS = "/sys/kernel/debug"
TRACEFS = os.path.join(DEBUGFS, "tracing")
if not os.path.exists(TRACEFS):
    TRACEFS = "/sys/kernel/tracing"

# Debug flags

# Debug output compiled LLVM IR.
DEBUG_LLVM_IR = 0x1
# Debug output loaded BPF bytecode and register state on branches.
DEBUG_BPF = 0x2
# Debug ou