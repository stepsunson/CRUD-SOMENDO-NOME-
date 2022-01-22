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
local Posix = require("bcc.vendor.posix")

local BaseTable = class("BaseTable")

BaseTable.static.BPF_MAP_TYPE_HASH = 1
BaseTable.static.BPF_MAP_TYPE_ARRAY = 2
BaseTable.static.BPF_MAP_TYPE_PROG_ARRAY = 3
BaseTable.static.BPF_MAP_TYPE_PERF_EVENT_ARRAY