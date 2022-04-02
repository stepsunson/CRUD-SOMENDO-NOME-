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
	builtins[hton] = function(_, _, _) return end
end
-- Other built-ins
local function xadd() error('NYI') end
builtins.xadd = xadd
builtins[xadd] = function (e, ret, a, b, off)
	local vinfo = e.V[a].const
	assert(vinfo and vinfo.__dissector, 'xadd(a, b[, offset]) called on non-pointer')
	local w = ffi.sizeof(vinfo.__dissector)
	-- Calculate structure attribute offsets
	if e.V[off] and type(e.V[off].const) == 'string' then
		local ct, field = vinfo.__dissector, e.V[off].const
		off = ffi.offsetof(ct, field)
		assert(off, 'xadd(a, b, offset) - offset is not valid in given structure')
		w = sizeofattr(ct, field)
	end
	assert(w == 4 or w == 8, 'NYI: xadd() - 1 and 2 byte atomic increments are not supported')
	-- Allocate registers and execute
	local src_reg = e.vreg(b)
	local dst_reg = e.vreg(a)
	-- Set variable for return value and call
	e.vset(ret)
	e.vreg(ret, 0, true, ffi.typeof('int32_t'))
	-- Optimize the NULL check away if provably not NULL
	if not e.V[a].source or e.V[a].source:find('_or_null', 1, true) then
		e.emit(BPF.JMP + BPF.JEQ + BPF.K, dst_reg, 0, 1, 0) -- if (dst != NULL)
	end
	e.emit(BPF.XADD + BPF.STX + const_width[w], dst_reg, src_reg, off or 0, 0)
end

local function probe_read() error('NYI') end
builtins.probe_read = probe_read
builtins[probe_read] = function (e, ret, dst, src, vtype, ofs)
	e.reg_alloc(e.tmpvar, 1)
	-- Load stack pointer to dst, since only load to stack memory is supported
	-- we have to use allocated stack memory or create a new allocation and convert
	-- to pointer type
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 10, 0, 0)
	if not e.V[dst].const or not e.V[dst].const.__base > 0 then
		builtins[ffi.new](e, dst, vtype) -- Allocate stack memory
	end
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[dst].const.__base)
	-- Set stack memory maximum size bound
	e.reg_alloc(e.tmpvar, 2)
	if not vtype then
		vtype = cdef.typename(e.V[dst].type)
		-- Dereference pointer type to pointed type for size calculation
		if vtype:sub(-1) == '*' then vtype = vtype:sub(0, -2) end
	end
	local w = ffi.sizeof(vtype)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 2, 0, 0, w)
	-- Set source pointer
	if e.V[src].reg then
		e.reg_alloc(e.tmpvar, 3) -- Copy from original register
		e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 3, e.V[src].reg, 0, 0)
	else
		e.vreg(src, 3)
		e.reg_spill(src) -- Spill to avoid overwriting
	end
	if ofs and ofs > 0 then
		e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 3, 0, 0, ofs)
	end
	-- Call probe read helper
	ret = ret or e.tmpvar
	e.vset(ret)
	e.vreg(ret, 0, true, ffi.typeof('int32_t'))
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.probe_read)
	e.V[e.tmpvar].reg = nil  -- Free temporary registers
end

builtins[ffi.cast] = function (e, dst, ct, x)
	assert(e.V[ct].const, 'ffi.cast(ctype, x) called with bad ctype')
	e.vcopy(dst, x)
	if e.V[x].const and type(e.V[x].const) == 'table' then
		e.V[dst].const.__dissector = ffi.typeof(e.V[ct].const)
	end
	e.V[dst].type = ffi.typeof(e.V[ct].const)
	-- Specific types also encode source of the data
	-- This is because BPF has different helpers for reading
	-- different data sources, so variables must track origins.
	-- struct pt_regs - source of the data is probe
	-- struct skb     - source of the data is socket buffer
	-- struct X       - source of the data is probe/tracepoint
	if ffi.typeof(e.V[ct].const) == ffi.typeof('struct pt_regs') then
		e.V[dst].source = 'ptr_to_probe'
	end
end

builtins[ffi.new] = function (e, dst, ct, x)
	if type(ct) == 'number' then
		ct = ffi.typeof(e.V[ct].const) -- Get ctype from variable
	end
	assert(not x, 'NYI: ffi.new(ctype, ...) - initializer is not supported')
	assert(not cdef.isptr(ct, true), 'NYI: ffi.new(ctype, ...) - ctype MUST NOT be a pointer')
	e.vset(dst, nil, ct)
	e.V[dst].source = 'ptr_to_stack'
	e.V[dst].const = {__base = e.valloc(ffi.sizeof(ct), true), __dissector = ct}
	-- Set array dissector if created an array
	-- e.g. if ct is 'char [2]', then dissector is 'char'
	local elem_type = tostring(ct):match('ctype<(.+)%s%[(%d+)%]>')
	if elem_type then
		e.V[dst].const.__dissector = ffi.typeof(elem_type)
	end
end

builtins[ffi.copy] = function (e, ret, dst, src)
	assert(cdef.isptr(e.V[dst].type), 'ffi.copy(dst, src) - dst MUST be a pointer ty