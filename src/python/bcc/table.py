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
    BPF_MAP_TYPE_CGROUP_ARRAY: "CGROUP_ARRAY",
    BPF_MAP_TYPE_LRU_HASH: "LRU_HASH",
    BPF_MAP_TYPE_LRU_PERCPU_HASH: "LRU_PERCPU_HASH",
    BPF_MAP_TYPE_LPM_TRIE: "LPM_TRIE",
    BPF_MAP_TYPE_ARRAY_OF_MAPS: "ARRAY_OF_MAPS",
    BPF_MAP_TYPE_HASH_OF_MAPS: "HASH_OF_MAPS",
    BPF_MAP_TYPE_DEVMAP: "DEVMAP",
    BPF_MAP_TYPE_SOCKMAP: "SOCKMAP",
    BPF_MAP_TYPE_CPUMAP: "CPUMAP",
    BPF_MAP_TYPE_XSKMAP: "XSKMAP",
    BPF_MAP_TYPE_SOCKHASH: "SOCKHASH",
    BPF_MAP_TYPE_CGROUP_STORAGE: "CGROUP_STORAGE",
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: "REUSEPORT_SOCKARRAY",
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: "PERCPU_CGROUP_STORAGE",
    BPF_MAP_TYPE_QUEUE: "QUEUE",
    BPF_MAP_TYPE_STACK: "STACK",
    BPF_MAP_TYPE_SK_STORAGE: "SK_STORAGE",
    BPF_MAP_TYPE_DEVMAP_HASH: "DEVMAP_HASH",
    BPF_MAP_TYPE_STRUCT_OPS: "STRUCT_OPS",
    BPF_MAP_TYPE_RINGBUF: "RINGBUF",
    BPF_MAP_TYPE_INODE_STORAGE: "INODE_STORAGE",
    BPF_MAP_TYPE_TASK_STORAGE: "TASK_STORAGE",
}

stars_max = 40
log2_index_max = 65
linear_index_max = 1025

# helper functions, consider moving these to a utils module
def _stars(val, val_max, width):
    i = 0
    text = ""
    while (1):
        if (i > (width * val / val_max) - 1) or (i > width - 1):
            break
        text += "*"
        i += 1
    if val > val_max:
        text = text[:-1] + "+"
    return text

def _print_json_hist(vals, val_type, section_bucket=None):
    hist_list = []
    max_nonzero_idx = 0
    for i in range(len(vals)):
        if vals[i] != 0:
            max_nonzero_idx = i
    index = 1
    prev = 0
    for i in range(len(vals)):
        if i != 0 and i <= max_nonzero_idx:
            index = index * 2

            list_obj = {}
            list_obj['interval-start'] = prev
            list_obj['interval-end'] = int(index) - 1
            list_obj['count'] = int(vals[i])

            hist_list.append(list_obj)

            prev = index
    histogram = {"ts": strftime("%Y-%m-%d %H:%M:%S"), "val_type": val_type, "data": hist_list}
    if section_bucket:
        histogram[section_bucket[0]] = section_bucket[1]
    print(histogram)

def _print_log2_hist(vals, val_type, strip_leading_zero):
    global stars