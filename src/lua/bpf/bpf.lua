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
-- LuaJIT to BPF bytecode compiler.
--
-- The code generation phase is currently one-pass and produces:
-- * Compiled code in BPF bytecode format (https://www.kernel.org/doc/Documentation/networking/filter.txt)
-- * Variables with liveness analysis and other meta (spill information, compile-time value)
--
-- The code generator optimises as much as possible in single pass:
-- * Fold compile-time expressions and constant propagation
-- * Basic control flow analysis with dead code elimination (based on compile-time expressions)
-- * Single-pass optimistic register allocation
--
-- The first pass doesn't have variable lifetime visibility yet, so it relies on rewriter for further
-- optimisations such as:
-- * Dead store elimination (first-pass doesn't know if/when the variable is going to be used)
-- * Common sub-expression elimination (relies on DCE and liveness analysis)
-- * Orphan JMP elimination (removing this in first pass would break previous JMP targets)
-- * Better register allocation (needs to be recomputed after optimisations)

local ffi = require('ffi')
local bit = require('bit')
local S = require('syscall')
local bytecode = require('bpf.ljbytecode')
local cdef = require('bpf.cdef')
local proto = require('bpf.proto')
local builtins = require('bpf.builtins')

-- Constants
local ALWAYS, NEVER = -1, -2
local BPF = ffi.typeof('struct bpf')
local HELPER = ffi.typeof('struct bpf_func_id')

-- Symbolic table of constant expressions over numbers
local const_expr = {
	ADD = function (a, b) return a + b end,
	SUB = function (a, b) return a - b end,
	DIV = function (a, b) return a / b end,
	MOD = function (a, b) return a % b end,
	JEQ = function (a, b) return a == b end,
	JNE = function (a, b) return a ~= b end,
	JGE = function (a, b) return a >= b end,
	JGT = function (a, b) return a > b end,
}

local const_width = {
	[1] = BPF.B, [2] = BPF.H, [4] = BPF.W, [8] = BPF.DW,
}

-- Built-ins that are strict only (never compile-time expandable)
local builtins_strict = {
	[ffi.new] = true,
	[print]   = true,
}

-- Deep copy a table
local function table_copy(t)
	local copy = {}
	for n,v in pairs(t) do
		if type(v) == 'table' then
			v = table_copy(v)
		end
		copy[n] = v
	end
	return copy
end

-- Return true if the constant part is a proxy
local function is_proxy(x)
	return type(x) == 'table' and (x.__dissector or x.__map or x.__base)
end

-- Create compiler closure
local function create_emitter(env, stackslots, params, param_types)

local V = {}   -- Variable tracking / register allocator
local code = { -- Generated code
	pc = 0, bc_pc = 0,
	insn = ffi.new('struct bpf_insn[4096]'),
	fixup = {},
	reachable = true,
	seen_cmp = nil,
}
local Vstate = {} -- Track variable layout at basic block exits

-- Anything below this stack offset is free to use by caller
-- @note: There is no tracking memory allocator, so the caller may
-- lower it for persistent objects, but such memory will never
-- be reclaimed and the caller is responsible for resetting stack
-- top whenever the memory below is free to be reused
local stack_top = (stackslots + 1) * ffi.sizeof('uint64_t')

local function emit(op, dst, src, off, imm)
	local ins = code.insn[code.pc]
	ins.code = op
	ins.dst_reg = dst
	ins.src_reg = src
	ins.off = off
	ins.imm = imm
	code.pc = code.pc + 1
end

local function reg_spill(var)
	local vinfo = V[var]
	assert(vinfo.reg, 'attempt to spill VAR that doesn\'t have an allocated register')
	vinfo.spill = (var + 1) * ffi.sizeof('uint64_t') -- Index by (variable number) * (register width)
	emit(BPF.MEM + BPF.STX + BPF.DW, 10, vinfo.reg, -vinfo.spill, 0)
	vinfo.reg = nil
end

local function reg_fill(var, reg)
	local vinfo = V[var]
	assert(reg, 'attempt to fill variable to register but not register is allocated')
	assert(vinfo.spill, 'attempt to fill register with a VAR that isn\'t spilled')
	emit(BPF.MEM + BPF.LDX + BPF.DW, reg, 10, -vinfo.spill, 0)
	vinfo.reg = reg
	vinfo.spill = nil
end

-- Allocate a register (lazy simple allocator)
local function reg_alloc(var, reg)
	-- Specific register requested, must spill/move existing variable
	if reg then
		for k,v in pairs(V) do -- Spill any variable that has this register
			if v.reg == reg and not v.shadow then
				reg_spill(k)
				break
			end
		end
		return reg
	end
	-- Find free or least recently used slot
	local last, last_seen, used = nil, 0xffff, 0
	for k,v in pairs(V) do
		if v.reg then
			if not v.live_to or v.live_to < last_seen then
				last, last_seen = k, v.live_to or last_seen
			end
			used = bit.bor(used, bit.lshift(1, v.reg))
		end
	end
	-- Attempt to select a free register from R7-R9 (callee saved)
	local free = bit.bnot(used)
	if     bit.band(free, 0x80) ~= 0 then reg = 7
	elseif bit.band(free,0x100) ~= 0 then reg = 8
	elseif bit.band(free,0x200) ~= 0 then reg = 9
	end
	-- Select another variable to be spilled
	if not reg then
		assert(last)
		reg = V[last].reg
		reg_spill(last)
	end
	assert(reg, 'VAR '..var..'fill/spill failed')
	return reg
end

-- Set new variable
local function vset(var, reg, const, vtype)
	-- Must materialise all variables shadowing this variable slot, as it will be overwritten
	if V[var] and V[var].reg then
		for _, vinfo in pairs(V) do
			-- Shadowing variable MUST share the same type and attributes,
			-- but the register assignment may have changed
			if vinfo.shadow == var then
				vinfo.reg = V[var].reg
				vinfo.shadow = nil
			end
		end
	end
	-- Get precise type for CDATA or attempt to narrow numeric constant
	if not vtype and type(const) == 'cdata' then
		vtype = ffi.typeof(const)
	end
	V[var] = {reg=reg, const=const, type=vtype}
	-- Track variable source
	if V[var].const and type(const) == 'table' then
		V[var].source = V[var].const.source
	end
end

-- Materialize (or register) a variable in a register
-- If the register is nil, then the a new register is assigned (if not already assigned)
local function vreg(var, reg, reserve, vtype)
	local vinfo = V[var]
	assert(vinfo, 'VAR '..var..' not registered')
	vinfo.live_to = code.pc-1
	if (vinfo.reg and not reg) and not vinfo.shadow then return vinfo.reg end
	reg = reg_alloc(var, reg)
	-- Materialize variable shadow copy
	local src = vinfo
	while src.shadow do src = V[src.shadow] end
	if reserve then -- luacheck: ignore
		-- No load to register occurs
	elseif src.reg then
		emit(BPF.ALU64 + BPF.MOV + BPF.X, reg, src.reg, 0, 0)
	elseif src.spill then
		vinfo.spill = src.spill
		reg_fill(var, reg)
	elseif src.const then
		vtype = vtype or src.type
		if type(src.const) == 'table' and src.const.__base then
			-- Load pointer type
			emit(BPF.ALU64 + BPF.MOV + BPF.X, reg, 10, 0, 0)
			emit(BPF.ALU64 + BPF.ADD + BPF.K, reg, 0, 0, -src.const.__base)
		elseif type(src.const) == 'table' and src.const.__dissector then
			-- Load dissector offset (imm32), but keep the constant part (dissector proxy)
			emit(BPF.ALU64 + BPF.MOV + BPF.K, reg, 0, 0, src.const.off or 0)
		elseif vtype and ffi.sizeof(vtype) == 8 then
			-- IMM64 must be done in two instructions with imm64 = (lo(imm32), hi(imm32))
			emit(BPF.LD + BPF.DW, reg, 0, 0, ffi.cast('uint32_t', src.const))
			emit(0, 0, 0, 0, ffi.cast('uint32_t', bit.rshift(bit.rshift(src.const, 16), 16)))
			vinfo.const = nil -- The variable is live
		else
			emit(BPF.ALU64 + BPF.MOV + BPF.K, reg, 0, 0, src.const)
			vinfo.const = nil -- The variable is live
		end
	else assert(false, 'VAR '..var..' has neither register nor constant value') end
	vinfo.reg = reg
	vinfo.shadow = nil
	vinfo.live_from = code.pc-1
	vinfo.type = vtype or vinfo.type
	return reg
end

-- Copy variable
local function vcopy(dst, src)
	if dst == src then return end
	V[dst] = {reg=V[src].reg, const=V[src].const, shadow=src, source=V[src].source, type=V[src].type}
end

-- Dereference variable of pointer type
local function vderef(dst_reg, src_reg, vinfo)
	-- Dereference map pointers for primitive types
	-- BPF doesn't allow pointer arithmetics, so use the entry value
	assert(type(vinfo.const) == 'table' and vinfo.const.__dissector, 'cannot dereference a non-pointer variable')
	local vtype = vinfo.const.__dissector
	local w = ffi.sizeof(vtype)
	assert(const_width[w], 'NYI: sizeof('..tostring(vtype)..') not 1/2/4/8 bytes')
	if dst_reg ~= src_reg then
		emit(BPF.ALU64 + BPF.MOV + BPF.X, dst_reg, src_reg, 0, 0)    -- dst = src
	end
	-- Optimize the NULL check away if provably not NULL
	if not vinfo.source or vinfo.source:find('_or_null', 1, true) then
		emit(BPF.JMP + BPF.JEQ + BPF.K, src_reg, 0, 1, 0)            -- if (src != NULL)
	end
	emit(BPF.MEM + BPF.LDX + const_width[w], dst_reg, src_reg, 0, 0) --     dst = *src;
end

-- Allocate a space for variable
local function valloc(size, blank)
	local base = stack_top
	assert(stack_top + size < 512 * 1024, 'exceeded maximum stack size of 512kB')
	stack_top = stack_top + size
	-- Align to 8 byte boundary
	stack_top = math.ceil(stack_top/8)*8
	-- Current kernel version doesn't support ARG_PTR_TO_RAW_STACK
	-- so we always need to have memory initialized, remove this when supported
	if blank then
		if type(blank) == 'string' then
			local sp = 0
			while sp < size do
				-- TODO: no BPF_ST + BPF_DW instruction yet
				local as_u32 = ffi.new('uint32_t [1]')
				local sub = blank:sub(sp+1, sp+ffi.sizeof(as_u32))
				ffi.copy(as_u32, sub, #sub)
				emit(BPF.MEM + BPF.ST + BPF.W, 10, 0, -(stack_top-sp), as_u32[0])
				sp = sp + ffi.sizeof(as_u32)
			end
		elseif type(blank) == 'boolean' then
			reg_alloc(stackslots, 0)
			emit(BPF.ALU64 + BPF.MOV + BPF.K, 0, 0, 0, 0)
			for sp = base+8,stack_top,8 do
				emit(BPF.MEM + BPF.STX + BPF.DW, 10, 0, -sp, 0)
			end
		else error('NYI: will with unknown type '..type(blank)) end
	end
	return stack_top
end

-- Turn variable into scalar in register (or constant)
local function vscalar(a, w)
	assert(const_width[w], 'sizeof(scalar variable) must be 1/2/4/8')
	local src_reg
	-- If source is a pointer, we must dereference it first
	if cdef.isptr(V[a].type) then
		src_reg = vreg(a)
		local tmp_reg = reg_alloc(stackslots, 1) -- Clone variable in tmp register
		emit(BPF.ALU64 + BPF.MOV + BPF.X, tmp_reg, src_reg, 0, 0)
		vderef(tmp_reg, tmp_reg, V[a])
		src_reg = tmp_reg -- Materialize and dereference it
	-- Source is a value on stack, we must load it first
	elseif type(V[a].const) == 'table' and V[a].const.__base > 0 then
		src_reg = vreg(a)
		emit(BPF.MEM + BPF.LDX + const_width[w], src_reg, 10, -V[a].const.__base, 0)
		V[a].type = V[a].const.__dissector
		V[a].const = nil -- Value is dereferenced
	-- If source is an imm32 number, avoid register load
	elseif type(V[a].const) == 'number' and w < 8 then
		return nil, V[a].const
	-- Load variable from any other source
	else
		src_reg = vreg(a)
	end

	return src_reg, nil
end

-- Emit compensation code at the end of basic block to unify variable set layout on all block exits
-- 1. we need to free registers by spilling
-- 2. fill registers to match other exits from this BB
local function bb_end(Vcomp)
	for i,v in pairs(V) do
		if Vcomp[i] and Vcomp[i].spill and not v.spill then
			-- Materialize const