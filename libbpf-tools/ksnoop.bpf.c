/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ksnoop.h"

/* For kretprobes, the instruction pointer in the struct pt_regs context
 * is the kretprobe_trampoline.  We derive the instruction pointer
 * by pushing it onto a function stack on entry and popping it on return.
 *
 * We could use bpf_get_func_ip(), but "stack mode" - where we
 * specify functions "a", "b and "c" and only want to see a trace if "a"
 * calls "b" and "b" calls "c" - utilizes this stack to determine if trace
 * data should be collected.
 */
#define FUNC_MAX_STACK_DEPTH	16
/* used to convince verifier we do not stray outside of array bounds */
#define FUNC_STACK_DEPTH_MASK	(FUNC_MAX_STACK_DEPTH - 1)

#ifndef ENOSPC
#define ENOSPC			28
#endif

struct func_stack {
	__u64 task;
	__u64 ips[FUNC_MAX_STACK_DEPTH];
	__u8 stack_depth;
};

#define MAX_TASKS		2048

/* function call stack hashed on a per-task key */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	/* function call stack for functions we are tracing */
	__uint(max_entries, MAX_TASKS);
	__type(key, __u64);
	__type(value, struct func_stack);
} ksnoop_func_stack SEC(".maps");

/* per-cpu trace info hashed on function address */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_FUNC_TRACES);
	__type(key, __u64);
	__type(value, struct trace);
} ksnoop_func_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(value_size, sizeof(int));
	__uint(key_size, sizeof(int));
} ksnoop_perf_map SEC(".maps");

static void clear_trace(struct trace *trace)
{
	__builtin_memset(&trace->trace_data, 0, sizeof(trace->trace_data));
	trace->data_flags = 0;
	trace->buf_len = 0;
}

static struct trace *get_trace(struct pt_regs *ctx, bool entry)
{
	__u8 stack_depth, last_stack_depth;
	struct func_stack *func_stack;
	__u64 ip, last_ip = 0, task;
	struct trace *trace;

	task = bpf_get_current_task();

	func_stack = bpf_map_lookup_elem(&ksnoop_func_stack, &task);
	if (!func_stack) {
		struct func_stack new_stack = { .task = task };

		bpf_map_update_elem(&ksnoop_func_stack, &task, &new_stack,
				    BPF_NOEXIST);
		func_stack = bpf_map_lookup_elem(&ksnoop_func_stack, &task);
		if (!func_stack)
			return NULL;
	}

	stack_depth = func_stack->stack_depth;
	if (stack_depth > FUNC_MAX_STACK_DEPTH)
		return NULL;

	if (entry) {
		ip = KSNOOP_IP_FIX(PT_REGS_IP_CORE(ctx));
		if (stack_depth >= FUNC_MAX_STACK_DEPTH - 1)
			return NULL;
		/* verifier doesn't like using "stack_depth - 1" as array index
		 * directly.
		 */
		last_stack_depth = stack_depth - 1;
		/* get address of last function we called */
		if (last_stack_depth >= 0 &&
		    last_stack_depth < FUNC_MAX_STACK_DEPTH)
			last_ip = func_stack->ips[last_stack_depth];
		/* push ip onto stack. return will pop it. */
		func_stack->ips[stack_depth] = ip;
		/* mask used in case bounds checks are optimized out */
		stack_depth = (stack_depth + 1) & FUNC_STACK_DEPTH_MASK;
		func_stack->stack_depth = stack_depth;
		/* rather than zero stack entries on popping, we zero the
		 * (stack_depth + 1)'th entry when pushing the current
		 * entry.  The reason we take this approach is that
		 * when tracking the set of functions we returned from,
		 * we want the history of functions we returned from to
		 * be preserved.
		 */
		if (stack_depth < FUNC_MAX_STACK_DEPTH)
			func_stack->ips[stack_depth] = 0;
	} else {
		if (stack_depth == 0 || stack_depth >= FUNC_MAX_STACK_DEPTH)
			return NULL;
		last_stack_depth = stack_depth;
		/* get address of last function we returned from */
		if (last_stack_depth >= 0 &&
		    last_stack_depth < FUNC_MAX_STACK_DEPTH)
			last_ip = func_stack->ips[last_stack_depth];
		if (stack_depth > 0) {
			/* logical OR convinces verifier that we don't
			 * end up with a < 0 value, translating to 0xff
			 * and an outside of map element access.
			 */
			stack_depth = (stack_depth - 1) & FUNC_STACK_DEPTH_MASK;
		}
		/* retrieve ip from stack as IP in pt_regs is
		 * bpf kretprobe trampoline address.
		 */
		if (stack_depth >= 0 && stack_depth < FUNC_MAX_STACK_DEPTH)
			ip = func_stack->ips[stack_depth];
		if (stack_depth >= 0 && stack_depth < FUNC_MAX_STACK_DEPTH)
			func_stack->stack_depth = stack_depth;
	}

	trace = bpf_map_lookup_elem(&ksnoop_func_map, &ip);
	if (!trace)
		return NULL;

	/* we may stash data on entry since predicates are a mix
	 * of entry/return; in such cases, trace->flags specifies
	 * KSNOOP_F_STASH, and we will output stashed data on return.
	 * If returning, make sure we don't clear our stashed data.
	 */
	if (!entry && (trace->flags & KSNOOP_F_STASH)) {
		/* skip clearing trace data */
		if (!(trace->data_flags & KSNOOP_F_STASHED)) {
			/* predicate must have failed */
			return NULL;
		}
		/* skip clearing trace data */
	} else {
		/* clear trace data before starting. */
		clear_trace(trace);
	}

	if (entry) {
		/* if in stack mode, check if previous fn matches */
		if (trace->prev_ip && trace->prev_ip != last_ip)
			return NULL;
		/* if tracing intermediate fn in stack of fns, stash data. */
		if (trace->next_ip)
			trace->data_flags 