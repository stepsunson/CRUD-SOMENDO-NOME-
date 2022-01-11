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

local TracerPipe = require("bcc.tracerpipe")
local Table = require("bcc.table")
local Sym = require("bcc.sym")

local Bpf = class("BPF")

Bpf.static.open_kprobes = {}
Bpf.static.open_uprobes = {}
Bpf.static.perf_buffers = {}
Bpf.static.KPROBE_LIMIT = 1000
Bpf.static.tracer_pipe = nil
Bpf.static.DEFAULT_CFLAGS = {
  '-D__HAVE_BUILTIN_BSWAP16__',
  '-D__HAVE_BUILTIN_BSWAP32__',
  '-D__HAVE_BUILTIN_BSWAP64__',
}

function Bpf.static.check_probe_quota(n)
  local cur = table.count(Bpf.static.open_kprobes) + table.count(Bpf.static.open_uprobes)
  assert(cur + n <= Bpf.static.KPROBE_LIMIT, "number of open probes would exceed quota")
end

function Bpf.static.cleanup()
  local function detach_all(probe_type, all_probes)
    for key, fd in pairs(all_probes) do
      libbcc.bpf_close_perf_event_fd(fd)
      -- skip bcc-specific kprobes
      if not key:starts("bcc:") then
        if probe_type == "kprobes" then
          libbcc.bpf_detach_kprobe(key)
        elseif probe_type == "uprobes" then
          libbcc.bpf_detach_uprobe(key)
        end
      end
      all_probes[key] = nil
    end
  end

  detach_all("kprobes", Bpf.static.open_kprobes)
  detach_all("uprobes", Bpf.static.open_uprobes)

  for key, perf_buffer in pairs(Bpf.static.perf_buffers) do
    libbcc.perf_reader_free(perf_buffer)
    Bpf.static.perf_buffers[key] = nil
  end

  if Bpf.static.tracer_pipe ~= nil then
    Bpf.static.tracer_pipe:close()
  end
end

function Bpf.static.SymbolCache(pid)
  return Sym.create_cache(pid)
end

function Bpf.static.num_open_uprobes()
  return table.count(Bpf.static.open_uprobes)
end

function Bpf.static.num_open_kprobes()
  return table.count(Bpf.static.open_kprobes)
end

Bpf.static.SCRIPT_ROOT = "./"
function Bpf.static.script_root(root)
  local dir, file = root:match'(.*/)(.*)'
  Bpf.static.SCRIPT_ROOT = dir or "./"
  return Bpf
end

local function _find_file(script_root, filename)
  if filename == nil then
    return nil
  end

  if os.exists(filename) then
    return filename
  end

  if not filename:starts("/") then
    filename = script_root .. filename
    if os.exists(filename) then
      return filename
    end
  end

  assert(nil, "failed to find file "..filename.." (root="..script_root..")")
end

function Bpf:initialize(args)
  self.funcs = {}
  self.tables = {}

  if args.usdt and args.text then
    args.text = args.usdt:_get_text() .. args.text
  end

  local cflags = table.join(Bpf.DEFAULT_CFLAGS, args.cflags)
  local cflags_ary = ffi.new("const char *[?]", #cflags, cflags)

  local llvm_debug = rawget(_G, "LIBBCC_LLVM_DEBUG") or args.debug or 0
  assert(type(llvm_debug) == "number")

  if args.text then
    log.info("\n%s\n", args.text)
    self.module = libbcc.bpf_module_create_c_from_string(args.text, llvm_debug, cflags_ary, #cflags, true)
  elseif args.src_file then
    local src = _find_file(Bpf.SCRIPT_ROOT, args.src_file)

    self.module = libbcc.bpf_module_create_c(src, llvm_debug, cflags_ary, #cflags, true)
  end

  assert(self.module ~= nil, "failed to compile BPF module")

  if args.usdt then
    args.usdt:_attach_uprobes(self)
  end
end

function Bpf:load_funcs(prog_type)
  prog_type = prog_type or "BPF_PROG_TYPE_KPROBE"

  local result = {}
  local fn_count = tonumber(libbcc.bpf_num_functions(self.module))

  for i = 0,fn_count-1 do
    local name = ffi.string(libbcc.bpf_function_name(self.module, i))
    table.insert(result, self:load_func(name, prog_type))
  end

  return result
end

function Bpf:load_func(fn_name, prog_type)
  if self.funcs[fn_name] ~= nil then
    return self.funcs[fn_name]
  end

  assert(libbcc.bpf_function_start(self.module, fn_name) ~= nil,
    "unknown program: "..fn_name)

  local fd = libbcc.bcc_prog_load(prog_type,
    fn_name,
    libbcc.bpf_function_start(self.module, fn_name),
    libbcc.bpf_function_size(self.module, fn_name),
    libbcc.bpf_module_license(self.module),
    libbcc.bpf_module_kern_version(self.module),
    0, nil, 0)

  assert(fd >= 0, "failed to load BPF program "..fn_name)
  log.info("loaded %s (%d)", fn_name, fd)

  local fn = {bpf=self, name=fn_name, fd=fd}
  self.funcs[fn_name] = fn
  return fn
end

function Bpf:dump_func(fn_name)
  local sta