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
try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping
from time import strftime
import ctypes as ct
from functools import reduce
import os
import errno
import re
import sys

from .libbcc import lib, _RAW_CB_TYPE, _LOST_CB_TYPE, _RINGBUF_CB_TYPE, bcc_perf_buffer_opts
from .utils import get_online_cpus
from .utils import get_possible_cpus

BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_PROG_ARRAY = 3
BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
BPF_MAP_TYPE_PERCPU_HASH = 5
BPF_MAP_TYPE_PERCPU_ARRAY = 6
BPF_MAP_TYPE_STACK_TRACE = 7
BPF_MAP_TYPE_CGROUP_ARRAY = 8
BPF_MAP_TYPE_LRU_HASH = 9
BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
BPF_MAP_TYPE_LPM_TRIE = 11
BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
BPF_MAP_TYPE_HASH_OF_MAPS = 13
BPF_MAP_TYPE_DEVMAP = 14
BPF_MAP_TYPE_SOCKMAP = 15
BPF_MAP_TYPE_CPUMAP = 16
BPF_MAP_TYPE_XSKMAP = 17
BPF_MAP_TYPE_SOCKHASH = 18
BPF_MAP_TYPE_CGROUP_STORAGE = 19
BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20
BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21
BPF_MAP_TYPE_QUEUE = 22
BPF_MAP_TYPE_STACK = 23
BPF_MAP_TYPE_SK_STORAGE = 24
BPF_MAP_TYPE_DEVMAP_HASH = 25
BPF_MAP_TYPE_STRUCT_OPS = 26
BPF_MAP_TYPE_RINGBUF = 27
BPF_MAP_TYPE_INODE_STORAGE = 28
BPF_MAP_TYPE_TASK_STORAGE = 29

map_type_name = {
    BPF_MAP_TYPE_HASH: "HASH",
    BPF_MAP_TYPE_ARRAY: "ARRAY",
    BPF_MAP_TYPE_PROG_ARRAY: "PROG_ARRAY",
    BPF_MAP_TYPE_PERF_EVENT_ARRAY: "PERF_EVENT_ARRAY",
    BPF_MAP_TYPE_PERCPU_HASH: "PERCPU_HASH",
    BPF_MAP_TYPE_PERCPU_ARRAY: "PERCPU_ARRAY",
    BPF_MAP_TYPE_STACK_TRACE: "STACK_TRACE",
    BPF_MAP_TYPE_CGROUP_A