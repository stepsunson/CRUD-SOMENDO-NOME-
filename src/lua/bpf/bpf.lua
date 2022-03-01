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
			-- Materialize constant or shadowing variable to be able to spill
			if not v.reg and (v.shadow or cdef.isimmconst(v)) then
				vreg(i)
			end
			reg_spill(i)
		end
	end
	for i,v in pairs(V) do
		if Vcomp[i] and Vcomp[i].reg and not v.reg then
			vreg(i, Vcomp[i].reg)
		end
		-- Compensate variable metadata change
		if Vcomp[i] and Vcomp[i].source then
			V[i].source = Vcomp[i].source
		end
	end
end

local function CMP_STR(a, b, op)
	assert(op == 'JEQ' or op == 'JNE', 'NYI: only equivallence stack/string only supports == or ~=')
	-- I have no better idea how to implement it than unrolled XOR loop, as we can fixup only one JMP
	-- So: X(a,b) = a[0] ^ b[0] | a[1] ^ b[1] | ...
	--     EQ(a,b) <=> X == 0
	-- This could be optimised by placing early exits by rewriter in second phase for long strings
	local base, size = V[a].const.__base, math.min(#b, ffi.sizeof(V[a].type))
	local acc, tmp = reg_alloc(stackslots, 0), reg_alloc(stackslots+1, 1)
	local sp = 0
	emit(BPF.ALU64 + BPF.MOV + BPF.K, acc, 0, 0, 0)
	while sp < size do
		-- Load string chunk as imm32
		local as_u32 = ffi.new('uint32_t [1]')
		local sub = b:sub(sp+1, sp+ffi.sizeof(as_u32))
		ffi.copy(as_u32, sub, #sub)
		-- TODO: make this faster by interleaved load/compare steps with DW length
		emit(BPF.MEM + BPF.LDX + BPF.W, tmp, 10, -(base-sp), 0)
		emit(BPF.ALU64 + BPF.XOR + BPF.K, tmp, 0, 0, as_u32[0])
		emit(BPF.ALU64 + BPF.OR + BPF.X, acc, tmp, 0, 0)
		sp = sp + ffi.sizeof(as_u32)
	end
	emit(BPF.JMP + BPF[op] + BPF.K, acc, 0, 0xffff, 0)
	code.seen_cmp = code.pc-1
end

local function CMP_REG(a, b, op)
	-- Fold compile-time expressions
	if V[a].const and V[b].const and not (is_proxy(V[a].const) or is_proxy(V[b].const)) then
		code.seen_cmp = const_expr[op](V[a].const, V[b].const) and ALWAYS or NEVER
	else
		-- Comparison against compile-time string or stack memory
		if V[b].const and type(V[b].const) == 'string' then
			return CMP_STR(a, V[b].const, op)
		end
		-- The 0xFFFF target here has no significance, it's just a placeholder for
		-- compiler to replace it's absolute offset to LJ bytecode insn with a relative
		-- offset in BPF program code, verifier will accept only programs with valid JMP targets
		local a_reg, b_reg = vreg(a), vreg(b)
		emit(BPF.JMP + BPF[op] + BPF.X, a_reg, b_reg, 0xffff, 0)
		code.seen_cmp = code.pc-1
	end
end

local function CMP_IMM(a, b, op)
	local c = V[a].const
	if c and not is_proxy(c) then -- Fold compile-time expressions
		code.seen_cmp = const_expr[op](c, b) and ALWAYS or NEVER
	else
		-- Convert imm32 to number
		if type(b) == 'string' then
			if     #b == 1 then b = b:byte()
			elseif cdef.isptr(V[a].type) then
				-- String comparison between stack/constant string
				return CMP_STR(a, b, op)
			elseif #b <= 4 then
				-- Convert to u32 with network byte order
				local imm = ffi.new('uint32_t[1]')
				ffi.copy(imm, b, #b)
				b = builtins.hton(imm[0])
			else error('NYI: compare register with string, where #string > sizeof(u32)') end
		end
		-- The 0xFFFF target here has no significance, it's just a placeholder for
		-- compiler to replace it's absolute offset to LJ bytecode insn with a relative
		-- offset in BPF program code, verifier will accept only programs with valid JMP targets
		local reg = vreg(a)
		emit(BPF.JMP + BPF[op] + BPF.K, reg, 0, 0xffff, b)
		code.seen_cmp = code.pc-1
		-- Remember NULL pointer checks as BPF prohibits pointer comparisons
		-- and repeated checks wouldn't pass the verifier, only comparisons
		-- against constants are checked.
		if op == 'JEQ' and tonumber(b) == 0 and V[a].source then
			local pos = V[a].source:find('_or_null', 1, true)
			if pos then
				code.seen_null_guard = a
			end
		-- Inverse NULL pointer check (if a ~= nil)
		elseif op == 'JNE' and tonumber(b) == 0 and V[a].source then
			local pos = V[a].source:find('_or_null', 1, true)
			if pos then
				code.seen_null_guard = a
				code.seen_null_guard_inverse = true
			end
		end
	end
end

local function ALU_IMM(dst, a, b, op)
	-- Fold compile-time expressions
	if V[a].const and not is_proxy(V[a].const) then
			assert(cdef.isimmconst(V[a]), 'VAR '..a..' must be numeric')
			vset(dst, nil, const_expr[op](V[a].const, b))
	-- Now we need to materialize dissected value at DST, and add it
	else
		vcopy(dst, a)
		local dst_reg = vreg(dst)
		if cdef.isptr(V[a].type) then
			vderef(dst_reg, dst_reg, V[a])
			V[dst].type = V[a].const.__dissector
		else
			V[dst].type = V[a].type
		end
		emit(BPF.ALU64 + BPF[op] + BPF.K, dst_reg, 0, 0, b)
	end
end

local function ALU_REG(dst, a, b, op)
	-- Fold compile-time expressions
	if V[a].const and not (is_proxy(V[a].const) or is_proxy(V[b].const)) then
		assert(cdef.isimmconst(V[a]), 'VAR '..a..' must be numeric')
		assert(cdef.isimmconst(V[b]), 'VAR '..b..' must be numeric')
		if type(op) == 'string' then op = const_expr[op] end
		vcopy(dst, a)
		V[dst].const = op(V[a].const, V[b].const)
	else
		local src_reg = b and vreg(b) or 0 -- SRC is optional for unary operations
		if b and cdef.isptr(V[b].type) then
			-- We have to allocate a temporary register for dereferencing to preserve
			-- pointer in source variable that MUST NOT be altered
			reg_alloc(stackslots, 2)
			vderef(2, src_reg, V[b])
			src_reg = 2
		end
		vcopy(dst, a) -- DST may alias B, so copy must occur after we materialize B
		local dst_reg = vreg(dst)
		if cdef.isptr(V[a].type) then
			vderef(dst_reg, dst_reg, V[a])
			V[dst].type = V[a].const.__dissector
		end
		emit(BPF.ALU64 + BPF[op] + BPF.X, dst_reg, src_reg, 0, 0)
		V[stackslots].reg = nil  -- Free temporary registers
	end
end

local function ALU_IMM_NV(dst, a, b, op)
	-- Do DST = IMM(a) op VAR(b) where we can't invert because
	-- the registers are u64 but immediates are u32, so complement
	-- arithmetics wouldn't work
	vset(stackslots+1, nil, a)
	ALU_REG(dst, stackslots+1, b, op)
end

local function LD_ABS(dst, w, off)
	assert(off, 'LD_ABS called without offset')
	if w < 8 then
		local dst_reg = vreg(dst, 0, true, builtins.width_type(w)) -- Reserve R0
		emit(BPF.LD + BPF.ABS + const_width[w], dst_reg, 0, 0, off)
		if w > 1 and ffi.abi('le') then -- LD_ABS has htonl() semantics, reverse
			emit(BPF.ALU + BPF.END + BPF.TO_BE, dst_reg, 0, 0, w * 8)
		end
	elseif w == 8 then
		-- LD_ABS|IND prohibits DW, we need to do two 