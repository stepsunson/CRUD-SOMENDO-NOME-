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
	[bit.bnot]    = 'NEG',
	[bit.bor]     = 'OR',
	[bit.bxor]    = 'XOR',
	[bit.arshift] = 'ARSH',
	-- Extensions and intrinsics
}

local function width_type(w)
	-- Note: ffi.typeof doesn't accept '?' as template
	return const_width_type[w] or ffi.typeof(string.format('uint8_t [%d]', w))
end
builtins.width_type = width_type

-- Return struct member size/type (requires LuaJIT 2.1+)
-- I am ashamed that there's no easier way around it.
local function sizeofattr(ct, name)
	if not ffi.typeinfo then error('LuaJIT 2.1+ is required for ffi.typeinfo') end
	local cinfo = ffi.typeinfo(ct)
	while true do
		cinfo = ffi.typeinfo(cinfo.sib)
		if not cinfo then return end
		if cinfo.name == name then break end
	end
	local size = math.max(1, ffi.typeinfo(cinfo.sib or ct).size - cinfo.size)
	-- Guess type name
	return size, builtins.width_type(size)
end
builtins.sizeofattr = sizeofattr

-- Byte-order conversions for little endian
local function ntoh(x, w)
	if w then x = ffi.cast(const_width_type[w/8], x) end
	return bit.bswap(x)
end
local function hton(x, w) return ntoh(x, w) end
builtins.ntoh = ntoh
builtins.hton = hton
builtins[ntoh] = function (e, dst, a, w)
	-- This is trickery, but TO_LE means cpu_to_le(),
	-- and we want exactly the opposite as network is always 'be'
	w = w or ffi.sizeof(e.V[a].type)*8
	if w == 8 then return end -- NOOP
	assert(w <= 64, 'NYI: hton(a[, width]) - operand larger than register width')
	-- Allocate registers and execute
	e.vcopy(dst, a)
	e.emit(BPF.ALU + BPF.END + BPF.TO_BE, e.vreg(dst), 0, 0, w)
end
builtins[hton] = function (e, dst, a, w)
	w = w or ffi.sizeof(e.V[a].type)*8
	if w == 8 then return end -- NOOP
	assert(w <= 64, 'NYI: hton(a[, width]) - operand larger than register width')
	-- Allocate registers and execute
	e.vcopy(dst, a)
	e.emit(BPF.ALU + BPF.END + BPF.TO_LE, e.vreg(dst), 0, 0, w)
end
-- Byte-order conversions for big endian are no-ops
if ffi.abi('be') then
	ntoh = function (x, w)
		return w and ffi.cast(const_width_type[w/8], x) or x
	end
	hton = ntoh
	builtins[ntoh] = function(_, _, _) return end
	builtins[hton] = functi