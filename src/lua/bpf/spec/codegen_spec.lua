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
		it('mat