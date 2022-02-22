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
lo