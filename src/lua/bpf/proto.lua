--[[
Copyright 2016 Marek Vavrusa <mvavrusa@cloudflare.com>

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
local ffi = require('ffi')
local BPF = ffi.typeof('struct bpf')

ffi.cdef [[
struct sk_buff {
	uint32_t len;
	uint32_t pkt_type;
	uint32_t mark;
	uint32_t queue_mapping;
	uint32_t protocol;
	uint32_t vlan_present;
	uint32_t vlan_tci;
	uint32_t vlan_proto;
	uint32_t priority;
	uint32_t ingress_ifindex;
	uint32_t ifindex;
	uint32_t tc_index;
	uint32_t c