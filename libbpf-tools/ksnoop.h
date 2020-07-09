/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

/* maximum number of different functions we can trace at once */
#define MAX_FUNC_TRACES			64

enum arg {
	KSNOOP_ARG1,
	KSNOOP_ARG2,
	KSNOOP_ARG3,
	KSNOOP_ARG4,
	KSNOOP_ARG5,
	KSNOOP_RETURN
};

/* we choose "return" as the name for the returned value because as
 * a C keyword it can't clash with a function entry parameter.
 */
#define KSNOOP_RETURN_NAME		"return"

/* if we can't get a type id for a type (such as module-specific type)
 * mark it as KSNOOP_ID_UNKNOWN since BTF lookup in bpf_snprintf_btf()
 * will fail and the data will be simply displayed as a __u64.
 */
#define KSNOOP_ID_UNKNOWN		0xffffffff

#define MAX_NAME			96
#define MAX_STR				256
#define MAX_PATH			512
#define MAX_VALUES			6
#define MAX_ARGS			(MAX_VALUES - 1)
#define KSNOOP_F_PTR			0x1	/* value is a pointer */
#define KSNOOP_F_MEMBER			0x2	/* member reference */
#define KSNOOP_F_ENTRY			0x4
#define KSNOOP_F_RETURN			0x8
#define KSNOOP_F_CUSTOM			0x10	/* custom trace */
#define KSNOOP_F_STASH			0x20	/* store values on entry,
						 * no perf events.
						 */
#define KSNOOP_F_STASHED		0x40	/* values stored on entry */

#define KSNOOP_F_PREDICATE_EQ		0x100
#define KSNOOP_F_PREDICATE_NOTEQ	0x200
#define KSNOOP_F_PREDICATE_GT		0x400
#define KSNOOP_F_PREDICATE_LT		0x800

#define KSNOOP_F_PREDICATE_MASK		(KSNOOP_F_PREDICATE_EQ | \
					 KSNOOP_F_PREDICATE_NOTEQ | \
					 KSNOOP_F_PREDICATE_GT | \
					 KSNOOP_F_PREDICATE_LT)

/* for kprobes, entry is function IP + sizeof(kprobe_opcode_t),
 * subtract in BPF prog context to get fn address.
 */
#ifdef __TARGET_ARCH_x86
#define KSNOOP_IP_FIX(ip)		(ip - sizeof(kprobe_opcode_t))
#else
#define KSNOOP_IP_FIX(ip)		ip
#endif

struct value {
	char name[MAX_STR];
	enum arg base_arg;
	__u32 offset;
	__u32 size;
	__u64 type_id;
	__u64 flag