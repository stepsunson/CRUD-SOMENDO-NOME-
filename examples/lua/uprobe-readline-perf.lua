#!/usr/bin/env bcc-lua
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
-- Trace readline() call from all bash instances (print bash commands from all running shells).
-- This is rough equivallent to `bashreadline` with output through perf event API.
-- Source: http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')
-- Perf event map
local sample_t = 'struct { uint64_t pid; char str[80]; }'
local events = bpf.map('p