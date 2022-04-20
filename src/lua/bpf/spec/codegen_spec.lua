local ffi = require('ffi')
local S = require('syscall')

-- Normalize whitespace and remove empty lines
local function normalize_code(c)
	local res = {}
	for line in string.gmatch(c,'[^\r\n]+') do
		local op, d, s, t = line:match('(%S+)%s+(%S+)%s+(%S+)%s*([^-]*)')
		if op then
			t = t and t:match('^%s*(.-)%s*$')
			table.insert(res, string.format('%s\t%s %s %s', op, d, s, t))
		end
	end
	return table.concat(res, '\n')
end

-- Compile code and check result
local function compile(t)
	local bpf = require('bpf')
	-- require('jit.bc').dump(t.input)
	local code, err = bpf(t.input)
	assert.truthy(code)
	assert.falsy(err)
	if code then
		if t.expect then
			local got = normalize_code(bpf.dump_string(code, 1, true))
			-- if normalize_code(t.expect) ~= got then print(bpf.dump_string(code, 1)) end
			assert.same(normalize_code(t.expect), got)
		end
	end
end

-- Make a mock map variable
local function makemap(type, max_entries, key_ctype, val_ctype)
	if not key_ctype then key_ctype = ffi.typeof('uint32_t') end
	if not val_ctype then val_ctype = ffi.typeof('uint32_t') end
	if not max_entries then max_entries = 4096 end
	return {
		__map = true,
		max_entries = max_entries,
		key = ffi.new(ffi.typeof('$ [1]', key_ctype)),
		val = ffi.new(ffi.typeof('$ [1]', val_ctype)),
		map_type = S.c.BPF_MAP[type],
		key_type = key_ctype,
		val_type = val_ctype,
		fd = 42,
	}
end

describe('codegen', function()
	-- luacheck: ignore 113 211 212 311 511

	describe('constants', function()
		it('remove dead constant store', function()
			compile {
				input = function ()
					local proto = 5
				end,
				expect = [[
					MOV		R0	#0
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize constant', function()
			compile {
				input = function ()
					return 5
				end,
				expect = [[
					MOV		R0	#5
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize constant longer than i32', function()
			compile {
				input = function ()
					return 4294967295
				end,
				expect = [[
					LDDW	R0	#4294967295
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize cdata constant', function()
			compile {
				input = function ()
					return 5ULL
				end,
				expect = [[
					LDDW	R0	#5 -- composed instruction
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize signed cdata constant', function()
			compile {
				input = function ()
					return 5LL
				end,
				expect = [[
					LDDW	R0	#5 -- composed instruction
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize coercible numeric cdata constant', function()
			compile {
				input = function ()
					return 0x00005
				end,
				expect = [[
					MOV		R0	#5
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize constant through variable', function()
		compile {
			input = function ()
				local proto = 5
				return proto
			end,
			expect = [[
				MOV		R0	#5
				EXIT	R0	#0
			]]
		}
		end)
		it('eliminate constant expressions', function()
			compile {
				input = function ()
					return 2 + 3 - 0
				end,
				expect = [[
					MOV		R0	#5
					EXIT	R0	#0
				]]
			}
		end)
		it('eliminate constant expressions (if block)', function()
			compile {
				input = function ()
					local proto = 5
					if proto == 5 then
						proto = 1
					end
					return proto
				end,
				expect = [[
					MOV		R0	#1
					EXIT	R0	#0
				]]
			}
		end)
		it('eliminate negative constant expressions (if block) NYI', function()
			-- always negative condition is not fully eliminated
			compile {
				input = function ()
					local proto = 5
					if false then
						proto = 1
					end
					return proto
				end,
				expect = [[
					MOV		R7		#5
					STXDW	[R10-8] R7
					MOV		R7		#0
					JEQ		R7		#0 => 0005
					LDXDW	R0 		[R10-8]
					EXIT	R0		#0
				]]
			}
		end)
	end)

	describe('variables', function()
		it('classic packet access (fold constant offset)', function()
			compile {
				input = function (skb)
					return eth.ip.tos -- constant expression will fold
				end,
				expect = [[
					LDB		R0	skb[15]
					EXIT	R0	#0
				]]
			}
		end)
		it('classic packet access (load non-constant offset)', function()
			compile {
				input = function (skb)
					return eth.ip.udp.src_port -- need to skip variable-length header
				end,
				expect = [[
					LDB		R0			skb[14]
					AND		R0			#15
					LSH		R0			#2
					ADD		R0 			#14
					STXDW	[R10-16]	R0 -- NYI: erase dead store
					LDH		R0 			skb[R0+0]
					END		R0 			R0
					EXIT	R0 			#0
				]]
			}
		end)
		it('classic packet access (manipulate dissector offset)', function()
			compile {
				input = function (skb)
					local ptr = eth.ip.udp.data + 1
					return ptr[0] -- dereference dissector pointer
				end,
				expect = [[
					LDB		R0			skb[14]
					AND		R0			#15
					LSH		R0			#2
					ADD		R0			#14 -- NYI: fuse commutative operations in second pass
					ADD		R0			#8
					ADD		R0			#1
					STXDW	[R10-16] 	R0
					LDB		R0			skb[R0+0]
					EXIT	R0			#0
				]]
			}
		end)
		it('classic packet access (multi-byte load)', function()
			compile {
				input = function (skb)
					local ptr = eth.ip.udp.data
					return ptr(1, 5) -- load 4 bytes
				end,
				expect = [[
					LDB		R0			skb[14]
					AND		R0			#15
					LSH		R0			#2
					ADD		R0			#14
					ADD		R0			#8
					MOV		R7			R0
					STXDW	[R10-16]	R0 -- NYI: erase dead store
					LDW		R0			skb[R7+1]
					END		R0			R0
					EXIT	R0			#0
				]]
			}
		end)
		it('direct skb field access', function()
			compile {
				input = function (skb)
					return skb.len
				end,
				expect = [[
					LDXW	R7	[R6+0]
					MOV		R0	R7
					EXIT	R0	#0
				]]
			}
		end)
		it('direct skb data access (manipulate offset)', function()
			compile {
				input = function (skb)
					local ptr = skb.data + 5
					return ptr[0]
				end,
				expect = [[
					LDXW	R7	[R6+76]
					ADD		R7	#5
					LDXB	R8 	[R7+0] -- NYI: transform LD + ADD to LD + offset addressing
					MOV		R0 	R8
					EXIT	R0	#0
				]]
			}
		end)
		it('direct skb data access (offset boundary check)', function()
			compile {
				input = function (skb)
					local ptr = skb.data + 5
					if ptr < skb.data_end then
						return ptr[0]
					