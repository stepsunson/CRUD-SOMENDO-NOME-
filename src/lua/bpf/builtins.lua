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
local bit = require('bit')
local cdef = require('bpf.cdef')

local BPF, HELPER = ffi.typeof('struct bpf'), ffi.typeof('struct bpf_func_id')
local const_width = {
	[1] = BPF.B, [2] = BPF.H, [4] = BPF.W, [8] = BPF.DW,
}
local const_width_type = {
	[1] = ffi.typeof('uint8_t'), [2] = ffi.typeof('uint16_t'), [4] = ffi.typeof('uint32_t'), [8] = ffi.typeof('uint64_t'),
}

-- Built-ins that will be translated into BPF instructions
-- i.e. bit.bor(0xf0, 0x0f) becomes {'alu64, or, k', reg(0xf0), reg(0x0f), 0, 0}
local builtins = {
	[bit.lshift]  = 'LSH',
	[bit.rshift]  = 'RSH',
	[bit.band]    = 'AND',
	[bit.bnot]    = 