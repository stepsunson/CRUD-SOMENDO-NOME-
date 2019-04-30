/*
 * TCPSendStack Summarize tcp_sendmsg() calling stack traces.
 *              For Linux, uses BCC, eBPF. Embedded C.
 *
 * Basic example of BCC in-kernel stack trace dedup.
 *
 * USAGE: TCPSendStack [duration]
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <unistd.h>
#include <algorithm>
#include <iostream>

#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct stack_key_t {
  int pid;
  char name[16];
  int user_stack;
  int kernel_stack;
};

BPF_STACK_TRACE(stack_traces, 16384);
BPF_HASH(counts, struct stack_key_t, uint64_t);

int on_tcp_send(struct pt_regs *ctx) {
  struct stack_key_t key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&key.name, sizeof(key.name));
  key.kernel_stack = stack_traces.get_stackid(ctx, 0);
  key.user_stack = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

  u64 zero = 0, *val;
  val = counts.lookup_or_try_init(&key, &zero);
  if (val) {
    (*val)++;
  }

  return 0;
}
)";

// Define the same struct to use in user space.
struct stack_key_t {
  int pid;
  char name[16];
  int user_stack;
  int kernel_stack;
};

int main(int argc, char** argv) {
  ebpf::BPF bpf;
  auto init_res = bpf.init(BPF_PROGRAM);
  if (!init_res.ok()) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  auto attach_res = bpf.attach_kprobe("tcp_sendmsg", "on_tcp_send");
  if (!attach_res.ok()) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  int probe_time = 10;
  if (argc == 2) {
    probe_time = atoi(argv[1]);
  }
  std::cout << "Probing for " << probe_time << " seconds" << std::endl;
  sleep(probe_time);

  auto detach_res = bpf.detach_kprobe("tcp_sendmsg");
  if (!detach_res.ok()) {
    std::cerr << detach_res.msg() << std::endl;
    return 1;
  }

  auto table =
      bpf.get_hash_table<stack_key_t, uint64_t>("counts").get_table_offline();
  std::sort(
      table.begin(), table.end(),
      [](std::pair<stack_key_t, uint64_t> a,
         std::pair<stack_key_t, uint64_t> b) { return a.second < b.second; }