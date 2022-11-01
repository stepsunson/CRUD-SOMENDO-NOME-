/*
 * deadlock.c  Detects potential deadlocks in a running process.
 *             For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright 2017 Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 1-Feb-2016   Kenny Yu   Created this.
 */

#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

// Maximum number of mutexes a single thread can hold at once.
// If the number is too big, the unrolled loops wil cause the stack
// to be too big, and the bpf verifier will fail.
#define MAX_HELD_MUTEXES 16

// Info about held mutexes. `mutex` will be 0 if not held.
struct held_mutex_t {
  u64 mutex;
  u64 stack_id;
};

// List of mutexes that a thread is holding. Whenever we loop over this array,
// we need to force the compiler to unroll the loop, otherwise the bcc verifier
// will fail because the loop will create a backwards edge.
struct thread_to_held_mutex_leaf_t {
  struct held_mutex_t held_mutexes[MAX_HELD_MUTEXES];
};

// Map of thread ID -> array of (mutex addresses, stack id)
BPF_HASH(thread_to_held_mutexes, u32, struct thread_to_held_mutex_leaf_t, MAX_THREADS);

// Key type for edges. Represents an edge from mutex1 => mutex2.
struct edges_key_t {
  u64 mutex1;
  u64 mutex2;
};

// Leaf type for edges. Holds information about where each mutex was acquired.
struct edges_leaf_t {
  u64 mutex1_stack_id;
  u64 mutex2_stack_id;
  u32 thread_pid;
  char comm[TASK_COMM_LEN];
};

// Represents all