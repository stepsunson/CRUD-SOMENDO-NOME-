--[[
Copyright 2016 GitHub, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]
local ffi = require("ffi")
local libbcc = require("bcc.libbcc")
local Posix = require("bcc.vendor.posix")

local BaseTable = class("BaseTable")

BaseTable.static.BPF_MAP_TYPE_HASH = 1
BaseTable.static.BPF_MAP_TYPE_ARRAY = 2
BaseTable.static.BPF_MAP_TYPE_PROG_ARRAY = 3
BaseTable.static.BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
BaseTable.static.BPF_MAP_TYPE_PERCPU_HASH = 5
BaseTable.static.BPF_MAP_TYPE_PERCPU_ARRAY = 6
BaseTable.static.BPF_MAP_TYPE_STACK_TRACE = 7
BaseTable.static.BPF_MAP_TYPE_CGROUP_ARRAY = 8
BaseTable.static.BPF_MAP_TYPE_LRU_HASH = 9
BaseTable.static.BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
BaseTable.static.BPF_MAP_TYPE_LPM_TRIE = 11

function BaseTable:initialize(t_type, bpf, map_id, map_fd, key_type, leaf_type)
  assert(t_type == libbcc.bpf_table_type_id(bpf.module, map_id))

  self.t_type = t_type
  self.bpf = bpf
  self.map_id = map_id
  self.map_fd = map_fd
  self.c_key = ffi.typeof(key_type.."[1]")
  self.c_leaf = ffi.typeof(leaf_type.."[1]")
end

function BaseTable:key_sprintf(key)
  local pkey = self.c_key(key)
  local buf_len = ffi.sizeof(self.c_key) * 8
  local pbuf = ffi.new("char[?]", buf_len)

  local res = libbcc.bpf_table_key_snprintf(
    self.bpf.module, self.map_id, pbuf, buf_len, pkey)
  assert(res == 0, "could not print key")

  return ffi.string(pbuf)
end

function BaseTable:leaf_sprintf(leaf)
  local pleaf = self.c_leaf(leaf)
  local buf_len = ffi.sizeof(self.c_leaf) * 8
  local pbuf = ffi.new("char[?]", buf_len)

  local res = libbcc.bpf_table_leaf_snprintf(
    self.bpf.module, self.map_id, pbuf, buf_len, pleaf)
  assert(res == 0, "could not print leaf")

  return ffi.string(pbuf)
end

function BaseTable:key_scanf(key_str)
  local pkey = self.c_key()
  local res = libbcc.bpf_table_key_sscanf(
    self.bpf.module, self.map_id, key_str, pkey)
  assert(res == 0, "could not scanf key")
  return pkey[0]
end

function BaseTable:leaf_scanf(leaf_str)
  local pleaf = self.c_leaf()
  local res = libbcc.bpf_table_leaf_sscanf(
    self.bpf.module, self.map_id, leaf_str, pleaf)
  assert(res == 0, "could not scanf leaf")
  return pleaf[0]
end

function BaseTable:get(key)
  local pkey = self.c_key(key)
  local pvalue = self.c_leaf()

  if libbcc.bpf_lookup_elem(self.map_fd, pkey, pvalue) < 0 then
    return nil
  end

  return pvalue[0]
end

function BaseTable:set(key, value)
  local pkey = self.c_key(key)
  local pvalue = self.c_leaf(value)
  assert(libbcc.bpf_update_elem(self.map_fd, pkey, pvalue, 0) == 0, "could not update table")
end

function BaseTable:_empty_key()
  local pkey = self.c_key()
  local pvalue = self.c_leaf()

  for _, v in ipairs({0x0, 0x55, 0xff}) do
    ffi.fill(pkey, ffi.sizeof(pkey[0]), v)
    if libbcc.bpf_lookup_elem(self.map_fd, pkey, pvalue) < 0 then
      return pkey
    end
  end

  error("failed to find an empty key for table iteration")
end

function BaseTable:keys()
  local pkey = self:_empty_key()

  return function()
    local pkey_next = self.c_key()

    if libbcc.bpf_get_next_key(self.map_fd, pkey, pkey_next) < 0 then
      return nil
    end

    pkey = pkey_next
    return pkey[0]
  end
end

function BaseTable:items()
  local pkey = self:_empty_key()

  return function()
    local pkey_next = self.c_key()
    local pvalue = self.c_leaf()

    if libbcc.bpf_get_next_key(self.map_fd, pkey, pkey_next) < 0 then
      return nil
    end

    pkey = pkey_next
    assert(libbcc.bpf_lookup_elem(self.map_fd, pkey, pvalue) == 0)
    return pkey[0], pvalue[0]
  end
end



local HashTable = class("HashTable", BaseTable)

function HashTable:initialize(bpf, map_id, map_fd, key_type, leaf_type)
  BaseTable.initialize(self, BaseTable.BPF_MAP_TYPE_HASH, bpf, map_id, map_fd, key_type, leaf_type)
end

function HashTable:delete(key)
  local pkey = self.c_key(key)
  return libbcc.bpf_delete_elem(self.map_fd, pkey) == 0
end

function HashTable:size()
  local n = 0
  self:each(function() n = n + 1 end)
  return n
end



local BaseArray = class("BaseArray", BaseTable)

function BaseArray:initialize(t_type, bpf, map_id, map_fd, key_type, leaf_type)
  BaseTable.initialize(self, t_type, bpf, map_id, map_fd, key_type, leaf_type)
  self.max_entries = tonumber(libbcc.bpf_table_max_entries_id(self.bpf.module, self.map_id))
end

function BaseArray:_normalize_key(key)
  assert(type(key) == "number", "invalid key (expected a number")
  if key < 0 then
    key = self.max_entries + key
  end
  assert(key < self.max_entries, string.format("out of range (%d >= %d)", key, self.max_entries))
  return key
end

function BaseArray:get(key)
  return BaseTable.get(self, self:_normalize_key(key))
end

function BaseArray:set(key, value)
  return BaseTable.set(self, self:_normalize_key(key), value)
end

function BaseArray:delete(key)
  assert(nil, "unsupported")
end

function BaseArray:items(with_index)
  local pkey = self.c_key()
  local max = self.max_entries
  local n = 0

  -- TODO
  return function()
    local pvalue = self.c_leaf()

    if n == max then
      return nil
    end

    pkey[0] = n
    n = n + 1

    if libbcc.bpf_lookup_elem(self.map_fd, pkey, pvalue) ~= 0 then
      return nil
    end

    if with_index then
      return n, pvalue[0] -- return 1-based index
    else
      return pvalue[0]
    end
  end
end



local Array = class("Array", BaseArray)

function Array:initialize(bpf, map_id, map_fd, key_type, leaf_type)
  BaseArray.initialize(self, BaseTable.BPF_MAP_TYPE_ARRAY, bpf, map_id, map_fd, key_type, leaf_type)
end



local PerfEventArray = class("PerfEventArray", BaseArray)

function PerfEventArray:initialize(bpf, map_id, map_fd, key_type, leaf_type)
  BaseArray.initialize(self, BaseTable.BPF_MAP_TYPE_PERF_EVENT_ARRAY, bpf, map_id, map_fd, key_type, leaf_type)
  self._callbacks = {}
end

local function _perf_id(id, cpu)
  return string.format("bcc:perf_event_array:%d:%d", tonumber(id), cpu or 0)
end

function PerfEventArray:_open_perf_buffer(cpu, callback, ctype, page_cnt, lost_cb)
  local _cb = ffi.cast("perf_reader_raw_cb",
    function (cookie, data, size)
      callback(cpu, ctype(data)[0])
    end)

  local _lost_cb = nil
  if lost_cb then
    _lost_cb = ffi.cast("perf_reader_lost_cb",
      function (cookie, lost)
        lost_cb(cookie, lost)
      end)
  end

  -- default to 8 pages per buffer
  local reader = libbcc.bpf_open_perf_buffer(_cb, _lost_cb, nil, -1, cpu, page_cnt or 8)
  assert(reader, "failed to open perf buffer")

  local fd = libbcc.perf_reader_fd(reader)
  self:set(cpu, fd)
  self.bpf:perf_buffer_store(_perf_id(self.map_id, cpu), reader)
  self._callbacks[cpu] = _cb
end

function PerfEventArray:op