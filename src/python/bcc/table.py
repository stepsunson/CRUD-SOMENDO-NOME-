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
    global stars_max
    log2_dist_max = 64
    idx_max = -1
    val_max = 0

    for i, v in enumerate(vals):
        if v > 0: idx_max = i
        if v > val_max: val_max = v

    if idx_max <= 32:
        header = "     %-19s : count     distribution"
        body = "%10d -> %-10d : %-8d |%-*s|"
        stars = stars_max
    else:
        header = "               %-29s : count     distribution"
        body = "%20d -> %-20d : %-8d |%-*s|"
        stars = int(stars_max / 2)

    if idx_max > 0:
        print(header % val_type)

    for i in range(1, idx_max + 1):
        low = (1 << i) >> 1
        high = (1 << i) - 1
        if (low == high):
            low -= 1
        val = vals[i]

        if strip_leading_zero:
            if val:
                print(body % (low, high, val, stars,
                              _stars(val, val_max, stars)))
                strip_leading_zero = False
        else:
            print(body % (low, high, val, stars,
                          _stars(val, val_max, stars)))

def _print_linear_hist(vals, val_type, strip_leading_zero):
    global stars_max
    log2_dist_max = 64
    idx_max = -1
    val_max = 0

    for i, v in enumerate(vals):
        if v > 0: idx_max = i
        if v > val_max: val_max = v

    header = "     %-13s : count     distribution"
    body = "        %-10d : %-8d |%-*s|"
    stars = stars_max

    if idx_max >= 0:
        print(header % val_type)
    for i in range(0, idx_max + 1):
        val = vals[i]

        if strip_leading_zero:
            if val:
                print(body % (i, val, stars,
                              _stars(val, val_max, stars)))
                strip_leading_zero = False
        else:
                print(body % (i, val, stars,
                              _stars(val, val_max, stars)))


def get_table_type_name(ttype):
    try:
        return map_type_name[ttype]
    except KeyError:
        return "<unknown>"


def _get_event_class(event_map):
    ct_mapping = {
        'char'              : ct.c_char,
        's8'                : ct.c_char,
        'unsigned char'     : ct.c_ubyte,
        'u8'                : ct.c_ubyte,
        'u8 *'              : ct.c_char_p,
        'char *'            : ct.c_char_p,
        'short'             : ct.c_short,
        's16'               : ct.c_short,
        'unsigned short'    : ct.c_ushort,
        'u16'               : ct.c_ushort,
        'int'               : ct.c_int,
        's32'               : ct.c_int,
        'enum'              : ct.c_int,
        'unsigned int'      : ct.c_uint,
        'u32'               : ct.c_uint,
        'long'              : ct.c_long,
        'unsigned long'     : ct.c_ulong,
        'long long'         : ct.c_longlong,
        's64'               : ct.c_longlong,
        'unsigned long long': ct.c_ulonglong,
        'u64'               : ct.c_ulonglong,
        '__int128'          : (ct.c_longlong * 2),
        'unsigned __int128' : (ct.c_ulonglong * 2),
        'void *'            : ct.c_void_p,
    }

    # handle array types e.g. "int [16]", "char[16]" or "unsigned char[16]"
    array_type = re.compile(r"(\S+(?: \S+)*) ?\[([0-9]+)\]$")

    fields = []
    num_fields = lib.bpf_perf_event_fields(event_map.bpf.module, event_map._name)
    i = 0
    while i < num_fields:
        field = lib.bpf_perf_event_field(event_map.bpf.module, event_map._name, i).decode()
        m = re.match(r"(.*)#(.*)", field)
        field_name = m.group(1)
        field_type = m.group(2)

        if re.match(r"enum .*", field_type):
            field_type = "enum"

        m = array_type.match(field_type)
        try:
            if m:
                fields.append((field_name, ct_mapping[m.group(1)] * int(m.group(2))))
            else:
                fields.append((field_name, ct_mapping[field_type]))
        except KeyError:
            # Using print+sys.exit instead of raising exceptions,
            # because exceptions are caught by the caller.
            print("Type: '%s' not recognized. Please define the data with ctypes manually."
                  % field_type, file=sys.stderr)
            sys.exit(1)
        i += 1
    return type('', (ct.Structure,), {'_fields_': fields})


def Table(bpf, map_id, map_fd, keytype, leaftype, name, **kwargs):
    """Table(bpf, map_id, map_fd, keytype, leaftype, **kwargs)

    Create a python object out of a reference to a bpf table handle"""

    ttype = lib.bpf_table_type_id(bpf.module, map_id)
    t = None
    if ttype == BPF_MAP_TYPE_HASH:
        t = HashTable(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_ARRAY:
        t = Array(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_PROG_ARRAY:
        t = ProgArray(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        t = PerfEventArray(bpf, map_id, map_fd, keytype, leaftype, name)
    elif ttype == BPF_MAP_TYPE_PERCPU_HASH:
        t = PerCpuHash(bpf, map_id, map_fd, keytype, leaftype, **kwargs)
    elif ttype == BPF_MAP_TYPE_PERCPU_ARRAY:
        t = PerCpuArray(bpf, map_id, map_fd, keytype, leaftype, **kwargs)
    elif ttype == BPF_MAP_TYPE_LPM_TRIE:
        t = LpmTrie(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_STACK_TRACE:
        t = StackTrace(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_LRU_HASH:
        t = LruHash(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_LRU_PERCPU_HASH:
        t = LruPerCpuHash(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_CGROUP_ARRAY:
        t = CgroupArray(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_DEVMAP:
        t = DevMap(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_CPUMAP:
        t = CpuMap(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_XSKMAP:
        t = XskMap(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_ARRAY_OF_MAPS:
        t = MapInMapArray(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_HASH_OF_MAPS:
        t = MapInMapHash(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_QUEUE or ttype == BPF_MAP_TYPE_STACK:
        t = QueueStack(bpf, map_id, map_fd, leaftype)
    elif ttype == BPF_MAP_TYPE_RINGBUF:
        t = RingBuf(bpf, map_id, map_fd, keytype, leaftype, name)
    if t == None:
        raise Exception("Unknown table type %d" % ttype)
    return t


class TableBase(MutableMapping):

    def __init__(self, bpf, map_id, map_fd, keytype, leaftype, name=None):
        self.bpf = bpf
        self.map_id = map_id
        self.map_fd = map_fd
        self.Key = keytype
        self.Leaf = leaftype
        self.ttype = lib.bpf_table_type_id(self.bpf.module, self.map_id)
        self.flags = lib.bpf_table_flags_id(self.bpf.module, self.map_id)
        self._cbs = {}
        self._name = name
        self.max_entries = int(lib.bpf_table_max_entries_id(self.bpf.module,
                self.map_id))

    def get_fd(self):
        return self.map_fd

    def key_sprintf(self, key):
        buf = ct.create_string_buffer(ct.sizeof(self.Key) * 8)
        res = lib.bpf_table_key_snprintf(self.bpf.module, self.map_id, buf,
                                         len(buf), ct.byref(key))
        if res < 0:
            raise Exception("Could not printf key")
        return buf.value

    def leaf_sprintf(self, leaf):
        buf = ct.create_string_buffer(ct.sizeof(self.Leaf) * 8)
        res = lib.bpf_table_leaf_snprintf(self.bpf.module, self.map_id, buf,
                                          len(buf), ct.byref(leaf))
        if res < 0:
            raise Exception("Could not printf leaf")
        return buf.value

    def key_scanf(self, key_str):
        key = self.Key()
        res = lib.bpf_table_key_sscanf(self.bpf.module, self.map_id, key_str,
                                       ct.byref(key))
        if res < 0:
            raise Exception("Could not scanf key")
        return key

    def leaf_scanf(self, leaf_str):
        leaf = self.Leaf()
        res = lib.bpf_table_leaf_sscanf(self.bpf.module, self.map_id, leaf_str,
                                        ct.byref(leaf))
        if res < 0:
            raise Exception("Could not scanf leaf")
        return leaf

    def __getitem__(self, key):
        leaf = self.Leaf()
        res = lib.bpf_lookup_elem(self.map_fd, ct.byref(key), ct.byref(leaf))
        if res < 0:
            raise KeyError
        return leaf

    def __setitem__(self, key, leaf):
        res = lib.bpf_update_elem(self.map_fd, ct.byref(key), ct.byref(leaf), 0)
        if res < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Could not update table: %s" % errstr)

    def __delitem__(self, key):
        res = lib.bpf_delete_elem(self.map_fd, ct.byref(key))
        if res < 0:
            raise KeyError

    # override the MutableMapping's implementation of these since they
    # don't handle KeyError nicely
    def itervalues(self):
        for key in self:
            # a map entry may be deleted in between discovering the key and
            # fetching the value, suppress such errors
            try:
                yield self[key]
            except KeyError:
                pass

    def iteritems(self):
        for key in self:
            try:
                yield (key, self[key])
            except KeyError:
                pass

    def items(self):
        return [item for item in self.iteritems()]

    def values(self):
        return [value for value in self.itervalues()]

    def clear(self):
        # default clear uses popitem, which can race with the bpf prog
        for k in self.keys():
            self.__delitem__(k)

    def _alloc_keys_values(self, alloc_k=False, alloc_v=False, count=None):
        """Allocate keys and/or values arrays. Useful for in items_*_batch.

        Args:
            alloc_k (bool): True to allocate keys array, False otherwise.
            Default is False.
            alloc_v (bool): True to allocate values array, False otherwise.
            Default is False.
            count (int): number of elements in the array(s) to allocate. If
            count is None then it allocates the maximum number of elements i.e
            self.max_entries.

        Returns:
            tuple: (count, keys, values). Where count is ct.c_uint32,
            and keys and values an instance of ct.Array
        Raises:
            ValueError: If count is less than 1 or greater than
            self.max_entries.
        """
        keys = values = None
        if not alloc_k and not alloc_v:
            return (ct.c_uint32(0), None, None)

        if not count:  # means alloc maximum size
            count = self.max_entries
        elif count < 1 or count > self.max_entries:
            raise ValueError("Wrong count")

        if alloc_k:
            keys = (self.Key * count)()
        if alloc_v:
            values = (self.Leaf * count)()

        return (ct.c_uint32(count), keys, values)

    def _sanity_check_keys_values(self, keys=None, values=None):
        """Check if the given keys or values have the right type and size.

        Args:
            keys (ct.Array): keys array to check
            values (ct.Array): values array to check
        Returns:
            ct.c_uint32 : the size of the array(s)
        Raises:
            ValueError: If length of arrays is less than 1 or greater than
            self.max_entries, or when both arrays length are different.
            TypeError: If the keys and values are not an instance of ct.Array
        """
        arr_len = 0
        for elem in [keys, values]:
            if elem:
                if not isinstance(elem, ct.Array):
                    raise TypeError

                arr_len = len(elem)
                if arr_len < 1 or arr_len > self.max_entries:
                    raise ValueError("Array's length is wrong")

        if keys and values:
            # check both length are equal
            if len(keys) != len(values):
                raise ValueError("keys array length != values array length")

        return ct.c_uint32(arr_len)

    def items_lookup_batch(self):
        """Look up all the key-value pairs in the map.

        Args:
            None
        Yields:
            tuple: The tuple of (key,value) for every entries that have
            been looked up.
        Notes: lookup batch on a keys subset is not supported by the kernel.
        """
        for k, v in self._items_lookup_and_optionally_delete_batch(delete=False):
            yield(k, v)
        return

    def items_delete_batch(self, ct_keys=None):
        """Delete the key-value pairs related to the keys given as parameters.
        Note that if no key are given, it is faster to call
        lib.bpf_lookup_and_delete_batch than create keys array and then call
        lib.bpf_delete_batch on these keys.

        Args:
            ct_keys (ct.Array): keys array to delete. If an array of keys is
            given then it deletes all the related keys-values.
            If keys is None (default) then it deletes all entries.
        Yields:
            tuple: The tuple of (key,value) for every entries that have
            been deleted.
        Raises:
            Exception: If bpf syscall return value indicates an error.
        """
        if ct_keys is not None:
            ct_cnt = self._sanity_check_keys_values(keys=ct_keys)
            res = lib.bpf_delete_batch(self.map_fd,
                                       ct.byref(ct_keys),
                                       ct.byref(ct_cnt)
                                       )
            if (res != 0):
                raise Exception("BPF_MAP_DELETE_BATCH has failed: %s"
                                % os.strerror(ct.get_errno()))

        else:
            for _ in self.items_lookup_and_delete_batch():
                return

    def items_update_batch(self, ct_keys, ct_values):
        """Update all the key-value pairs in the map provided.
        The arrays must be the same length, between 1 and the maximum number
        of entries.

        Args:
            ct_keys (ct.Array): keys array to update
            ct_values (ct.Array): values array to update
        Raises:
            Exception: If bpf syscall return value indicates an error.
        """
        ct_cnt = self._sanity_check_keys_values(keys=ct_keys, values=ct_values)
        res = lib.bpf_update_batch(self.map_fd,
                                   ct.byref(ct_keys),
                                   ct.byref(ct_values),
                                   ct.byref(ct_cnt)
                                   )
        if (res != 0):
         