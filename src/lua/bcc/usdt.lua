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
local Usdt = class("USDT")

Usdt.static.open_contexts = {}

function Usdt.static.cleanup()
  for _, context in ipairs(Usdt.static.open_contexts) do
    context:_cleanup()
  end
end

function Usdt:initialize(args)
  assert(args.pid or args.path)

  if args.pid then
    self.pid = args.pid
    self.context = libbcc.bcc_usdt_new_frompid(args.pid)
  elseif args.path then
    self.path = args.path
    self.context = libbcc