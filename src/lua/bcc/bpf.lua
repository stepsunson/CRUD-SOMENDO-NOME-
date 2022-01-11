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

  assert(n