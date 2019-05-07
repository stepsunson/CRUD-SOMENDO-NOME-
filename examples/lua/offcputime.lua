#!/usr/bin/env bcc-lua
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

local program = [[
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US	1

struct key_t {
    char name[TASK_COMM_LEN];
    int stack_id;
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, 10240);

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if (FILTER) {
        pid = prev->pid;
        ts = bpf_ktime_get_ns();
       