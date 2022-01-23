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
  local pkey = self.c_key(ke