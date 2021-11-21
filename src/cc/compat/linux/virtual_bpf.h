
R"********(
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_H__

#include <linux/types.h>
#include <linux/bpf_common.h>

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_JMP32	0x06	/* jmp mode in word width */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW		0x18	/* double word (64-bit) */
#define BPF_ATOMIC	0xc0	/* atomic memory ops - op type in immediate */
#define BPF_XADD	0xc0	/* exclusive add - legacy name */

/* alu/jmp fields */
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END		0xd0	/* flags for endianness conversion: */
#define BPF_TO_LE	0x00	/* convert to little-endian */
#define BPF_TO_BE	0x08	/* convert to big-endian */
#define BPF_FROM_LE	BPF_TO_LE
#define BPF_FROM_BE	BPF_TO_BE

/* jmp encodings */
#define BPF_JNE		0x50	/* jump != */
#define BPF_JLT		0xa0	/* LT is unsigned, '<' */
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_JSLT	0xc0	/* SLT is signed, '<' */
#define BPF_JSLE	0xd0	/* SLE is signed, '<=' */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

/* atomic op type fields (stored in immediate) */
#define BPF_FETCH	0x01	/* not an opcode on its own, used to build others */
#define BPF_XCHG	(0xe0 | BPF_FETCH)	/* atomic exchange */
#define BPF_CMPXCHG	(0xf0 | BPF_FETCH)	/* atomic compare-and-write */

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG	__MAX_BPF_REG

struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key {
	__u32	prefixlen;	/* up to 32 for AF_INET, 128 for AF_INET6 */
	__u8	data[0];	/* Arbitrary size */
};

struct bpf_cgroup_storage_key {
	__u64	cgroup_inode_id;	/* cgroup inode id */
	__u32	attach_type;		/* program attach type (enum bpf_attach_type) */
};

enum bpf_cgroup_iter_order {
	BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
	BPF_CGROUP_ITER_SELF_ONLY,		/* process only a single object. */
	BPF_CGROUP_ITER_DESCENDANTS_PRE,	/* walk descendants in pre-order. */
	BPF_CGROUP_ITER_DESCENDANTS_POST,	/* walk descendants in post-order. */
	BPF_CGROUP_ITER_ANCESTORS_UP,		/* walk ancestors upward. */
};

union bpf_iter_link_info {
	struct {
		__u32	map_fd;
	} map;
	struct {
		enum bpf_cgroup_iter_order order;

		/* At most one of cgroup_fd and cgroup_id can be non-zero. If
		 * both are zero, the walk starts from the default cgroup v2
		 * root. For walking v1 hierarchy, one should always explicitly
		 * specify cgroup_fd.
		 */
		__u32	cgroup_fd;
		__u64	cgroup_id;
	} cgroup;
	/* Parameters of task iterators. */
	struct {
		__u32	tid;
		__u32	pid;
		__u32	pid_fd;
	} task;
};

/* BPF syscall commands, see bpf(2) man-page for more details. */
/**
 * DOC: eBPF Syscall Preamble
 *
 * The operation to be performed by the **bpf**\ () system call is determined
 * by the *cmd* argument. Each operation takes an accompanying argument,
 * provided via *attr*, which is a pointer to a union of type *bpf_attr* (see
 * below). The size argument is the size of the union pointed to by *attr*.
 */
/**
 * DOC: eBPF Syscall Commands
 *
 * BPF_MAP_CREATE
 *	Description
 *		Create a map and return a file descriptor that refers to the
 *		map. The close-on-exec file descriptor flag (see **fcntl**\ (2))
 *		is automatically enabled for the new file descriptor.
 *
 *		Applying **close**\ (2) to the file descriptor returned by
 *		**BPF_MAP_CREATE** will delete the map (but see NOTES).
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_MAP_LOOKUP_ELEM
 *	Description
 *		Look up an element with a given *key* in the map referred to
 *		by the file descriptor *map_fd*.
 *
 *		The *flags* argument may be specified as one of the
 *		following:
 *
 *		**BPF_F_LOCK**
 *			Look up the value of a spin-locked map without
 *			returning the lock. This must be specified if the
 *			elements contain a spinlock.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_UPDATE_ELEM
 *	Description
 *		Create or update an element (key/value pair) in a specified map.
 *
 *		The *flags* argument should be specified as one of the
 *		following:
 *
 *		**BPF_ANY**
 *			Create a new element or update an existing element.
 *		**BPF_NOEXIST**
 *			Create a new element only if it did not exist.
 *		**BPF_EXIST**
 *			Update an existing element.
 *		**BPF_F_LOCK**
 *			Update a spin_lock-ed map element.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		May set *errno* to **EINVAL**, **EPERM**, **ENOMEM**,
 *		**E2BIG**, **EEXIST**, or **ENOENT**.
 *
 *		**E2BIG**
 *			The number of elements in the map reached the
 *			*max_entries* limit specified at map creation time.
 *		**EEXIST**
 *			If *flags* specifies **BPF_NOEXIST** and the element
 *			with *key* already exists in the map.
 *		**ENOENT**
 *			If *flags* specifies **BPF_EXIST** and the element with
 *			*key* does not exist in the map.
 *
 * BPF_MAP_DELETE_ELEM
 *	Description
 *		Look up and delete an element by key in a specified map.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_GET_NEXT_KEY
 *	Description
 *		Look up an element by key in a specified map and return the key
 *		of the next element. Can be used to iterate over all elements
 *		in the map.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		The following cases can be used to iterate over all elements of
 *		the map:
 *
 *		* If *key* is not found, the operation returns zero and sets
 *		  the *next_key* pointer to the key of the first element.
 *		* If *key* is found, the operation returns zero and sets the
 *		  *next_key* pointer to the key of the next element.
 *		* If *key* is the last element, returns -1 and *errno* is set
 *		  to **ENOENT**.
 *
 *		May set *errno* to **ENOMEM**, **EFAULT**, **EPERM**, or
 *		**EINVAL** on error.
 *
 * BPF_PROG_LOAD
 *	Description
 *		Verify and load an eBPF program, returning a new file
 *		descriptor associated with the program.
 *
 *		Applying **close**\ (2) to the file descriptor returned by
 *		**BPF_PROG_LOAD** will unload the eBPF program (but see NOTES).
 *
 *		The close-on-exec file descriptor flag (see **fcntl**\ (2)) is
 *		automatically enabled for the new file descriptor.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_OBJ_PIN
 *	Description
 *		Pin an eBPF program or map referred by the specified *bpf_fd*
 *		to the provided *pathname* on the filesystem.
 *
 *		The *pathname* argument must not contain a dot (".").
 *
 *		On success, *pathname* retains a reference to the eBPF object,
 *		preventing deallocation of the object when the original
 *		*bpf_fd* is closed. This allow the eBPF object to live beyond
 *		**close**\ (\ *bpf_fd*\ ), and hence the lifetime of the parent
 *		process.
 *
 *		Applying **unlink**\ (2) or similar calls to the *pathname*
 *		unpins the object from the filesystem, removing the reference.
 *		If no other file descriptors or filesystem nodes refer to the
 *		same object, it will be deallocated (see NOTES).
 *
 *		The filesystem type for the parent directory of *pathname* must
 *		be **BPF_FS_MAGIC**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_OBJ_GET
 *	Description
 *		Open a file descriptor for the eBPF object pinned to the
 *		specified *pathname*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_PROG_ATTACH
 *	Description
 *		Attach an eBPF program to a *target_fd* at the specified
 *		*attach_type* hook.
 *
 *		The *attach_type* specifies the eBPF attachment point to
 *		attach the program to, and must be one of *bpf_attach_type*
 *		(see below).
 *
 *		The *attach_bpf_fd* must be a valid file descriptor for a
 *		loaded eBPF program of a cgroup, flow dissector, LIRC, sockmap
 *		or sock_ops type corresponding to the specified *attach_type*.
 *
 *		The *target_fd* must be a valid file descriptor for a kernel
 *		object which depends on the attach type of *attach_bpf_fd*:
 *
 *		**BPF_PROG_TYPE_CGROUP_DEVICE**,
 *		**BPF_PROG_TYPE_CGROUP_SKB**,
 *		**BPF_PROG_TYPE_CGROUP_SOCK**,
 *		**BPF_PROG_TYPE_CGROUP_SOCK_ADDR**,
 *		**BPF_PROG_TYPE_CGROUP_SOCKOPT**,
 *		**BPF_PROG_TYPE_CGROUP_SYSCTL**,
 *		**BPF_PROG_TYPE_SOCK_OPS**
 *
 *			Control Group v2 hierarchy with the eBPF controller
 *			enabled. Requires the kernel to be compiled with
 *			**CONFIG_CGROUP_BPF**.
 *
 *		**BPF_PROG_TYPE_FLOW_DISSECTOR**
 *
 *			Network namespace (eg /proc/self/ns/net).
 *
 *		**BPF_PROG_TYPE_LIRC_MODE2**
 *
 *			LIRC device path (eg /dev/lircN). Requires the kernel
 *			to be compiled with **CONFIG_BPF_LIRC_MODE2**.
 *
 *		**BPF_PROG_TYPE_SK_SKB**,
 *		**BPF_PROG_TYPE_SK_MSG**
 *
 *			eBPF map of socket type (eg **BPF_MAP_TYPE_SOCKHASH**).
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_PROG_DETACH
 *	Description
 *		Detach the eBPF program associated with the *target_fd* at the
 *		hook specified by *attach_type*. The program must have been
 *		previously attached using **BPF_PROG_ATTACH**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_PROG_TEST_RUN
 *	Description
 *		Run the eBPF program associated with the *prog_fd* a *repeat*
 *		number of times against a provided program context *ctx_in* and
 *		data *data_in*, and return the modified program context
 *		*ctx_out*, *data_out* (for example, packet data), result of the
 *		execution *retval*, and *duration* of the test run.
 *
 *		The sizes of the buffers provided as input and output
 *		parameters *ctx_in*, *ctx_out*, *data_in*, and *data_out* must
 *		be provided in the corresponding variables *ctx_size_in*,
 *		*ctx_size_out*, *data_size_in*, and/or *data_size_out*. If any
 *		of these parameters are not provided (ie set to NULL), the
 *		corresponding size field must be zero.
 *
 *		Some program types have particular requirements:
 *
 *		**BPF_PROG_TYPE_SK_LOOKUP**
 *			*data_in* and *data_out* must be NULL.
 *
 *		**BPF_PROG_TYPE_RAW_TRACEPOINT**,
 *		**BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE**
 *
 *			*ctx_out*, *data_in* and *data_out* must be NULL.
 *			*repeat* must be zero.
 *
 *		BPF_PROG_RUN is an alias for BPF_PROG_TEST_RUN.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		**ENOSPC**
 *			Either *data_size_out* or *ctx_size_out* is too small.
 *		**ENOTSUPP**
 *			This command is not supported by the program type of
 *			the program referred to by *prog_fd*.
 *
 * BPF_PROG_GET_NEXT_ID
 *	Description
 *		Fetch the next eBPF program currently loaded into the kernel.
 *
 *		Looks for the eBPF program with an id greater than *start_id*
 *		and updates *next_id* on success. If no other eBPF programs
 *		remain with ids higher than *start_id*, returns -1 and sets
 *		*errno* to **ENOENT**.
 *
 *	Return
 *		Returns zero on success. On error, or when no id remains, -1
 *		is returned and *errno* is set appropriately.
 *
 * BPF_MAP_GET_NEXT_ID
 *	Description
 *		Fetch the next eBPF map currently loaded into the kernel.
 *
 *		Looks for the eBPF map with an id greater than *start_id*
 *		and updates *next_id* on success. If no other eBPF maps
 *		remain with ids higher than *start_id*, returns -1 and sets
 *		*errno* to **ENOENT**.
 *
 *	Return
 *		Returns zero on success. On error, or when no id remains, -1
 *		is returned and *errno* is set appropriately.
 *
 * BPF_PROG_GET_FD_BY_ID
 *	Description
 *		Open a file descriptor for the eBPF program corresponding to
 *		*prog_id*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_MAP_GET_FD_BY_ID
 *	Description
 *		Open a file descriptor for the eBPF map corresponding to
 *		*map_id*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_OBJ_GET_INFO_BY_FD
 *	Description
 *		Obtain information about the eBPF object corresponding to
 *		*bpf_fd*.
 *
 *		Populates up to *info_len* bytes of *info*, which will be in
 *		one of the following formats depending on the eBPF object type
 *		of *bpf_fd*:
 *
 *		* **struct bpf_prog_info**
 *		* **struct bpf_map_info**
 *		* **struct bpf_btf_info**
 *		* **struct bpf_link_info**
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_PROG_QUERY
 *	Description
 *		Obtain information about eBPF programs associated with the
 *		specified *attach_type* hook.
 *
 *		The *target_fd* must be a valid file descriptor for a kernel
 *		object which depends on the attach type of *attach_bpf_fd*:
 *
 *		**BPF_PROG_TYPE_CGROUP_DEVICE**,
 *		**BPF_PROG_TYPE_CGROUP_SKB**,
 *		**BPF_PROG_TYPE_CGROUP_SOCK**,
 *		**BPF_PROG_TYPE_CGROUP_SOCK_ADDR**,
 *		**BPF_PROG_TYPE_CGROUP_SOCKOPT**,
 *		**BPF_PROG_TYPE_CGROUP_SYSCTL**,
 *		**BPF_PROG_TYPE_SOCK_OPS**
 *
 *			Control Group v2 hierarchy with the eBPF controller
 *			enabled. Requires the kernel to be compiled with
 *			**CONFIG_CGROUP_BPF**.
 *
 *		**BPF_PROG_TYPE_FLOW_DISSECTOR**
 *
 *			Network namespace (eg /proc/self/ns/net).
 *
 *		**BPF_PROG_TYPE_LIRC_MODE2**
 *
 *			LIRC device path (eg /dev/lircN). Requires the kernel
 *			to be compiled with **CONFIG_BPF_LIRC_MODE2**.
 *
 *		**BPF_PROG_QUERY** always fetches the number of programs
 *		attached and the *attach_flags* which were used to attach those
 *		programs. Additionally, if *prog_ids* is nonzero and the number
 *		of attached programs is less than *prog_cnt*, populates
 *		*prog_ids* with the eBPF program ids of the programs attached
 *		at *target_fd*.
 *
 *		The following flags may alter the result:
 *
 *		**BPF_F_QUERY_EFFECTIVE**
 *			Only return information regarding programs which are
 *			currently effective at the specified *target_fd*.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_RAW_TRACEPOINT_OPEN
 *	Description
 *		Attach an eBPF program to a tracepoint *name* to access kernel
 *		internal arguments of the tracepoint in their raw form.
 *
 *		The *prog_fd* must be a valid file descriptor associated with
 *		a loaded eBPF program of type **BPF_PROG_TYPE_RAW_TRACEPOINT**.
 *
 *		No ABI guarantees are made about the content of tracepoint
 *		arguments exposed to the corresponding eBPF program.
 *
 *		Applying **close**\ (2) to the file descriptor returned by
 *		**BPF_RAW_TRACEPOINT_OPEN** will delete the map (but see NOTES).
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_BTF_LOAD
 *	Description
 *		Verify and load BPF Type Format (BTF) metadata into the kernel,
 *		returning a new file descriptor associated with the metadata.
 *		BTF is described in more detail at
 *		https://www.kernel.org/doc/html/latest/bpf/btf.html.
 *
 *		The *btf* parameter must point to valid memory providing
 *		*btf_size* bytes of BTF binary metadata.
 *
 *		The returned file descriptor can be passed to other **bpf**\ ()
 *		subcommands such as **BPF_PROG_LOAD** or **BPF_MAP_CREATE** to
 *		associate the BTF with those objects.
 *
 *		Similar to **BPF_PROG_LOAD**, **BPF_BTF_LOAD** has optional
 *		parameters to specify a *btf_log_buf*, *btf_log_size* and
 *		*btf_log_level* which allow the kernel to return freeform log
 *		output regarding the BTF verification process.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_BTF_GET_FD_BY_ID
 *	Description
 *		Open a file descriptor for the BPF Type Format (BTF)
 *		corresponding to *btf_id*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_TASK_FD_QUERY
 *	Description
 *		Obtain information about eBPF programs associated with the
 *		target process identified by *pid* and *fd*.
 *
 *		If the *pid* and *fd* are associated with a tracepoint, kprobe
 *		or uprobe perf event, then the *prog_id* and *fd_type* will
 *		be populated with the eBPF program id and file descriptor type
 *		of type **bpf_task_fd_type**. If associated with a kprobe or
 *		uprobe, the  *probe_offset* and *probe_addr* will also be
 *		populated. Optionally, if *buf* is provided, then up to
 *		*buf_len* bytes of *buf* will be populated with the name of
 *		the tracepoint, kprobe or uprobe.
 *
 *		The resulting *prog_id* may be introspected in deeper detail
 *		using **BPF_PROG_GET_FD_BY_ID** and **BPF_OBJ_GET_INFO_BY_FD**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_LOOKUP_AND_DELETE_ELEM
 *	Description
 *		Look up an element with the given *key* in the map referred to
 *		by the file descriptor *fd*, and if found, delete the element.
 *
 *		For **BPF_MAP_TYPE_QUEUE** and **BPF_MAP_TYPE_STACK** map
 *		types, the *flags* argument needs to be set to 0, but for other
 *		map types, it may be specified as:
 *
 *		**BPF_F_LOCK**
 *			Look up and delete the value of a spin-locked map
 *			without returning the lock. This must be specified if
 *			the elements contain a spinlock.
 *
 *		The **BPF_MAP_TYPE_QUEUE** and **BPF_MAP_TYPE_STACK** map types
 *		implement this command as a "pop" operation, deleting the top
 *		element rather than one corresponding to *key*.
 *		The *key* and *key_len* parameters should be zeroed when
 *		issuing this operation for these map types.
 *
 *		This command is only valid for the following map types:
 *		* **BPF_MAP_TYPE_QUEUE**
 *		* **BPF_MAP_TYPE_STACK**
 *		* **BPF_MAP_TYPE_HASH**
 *		* **BPF_MAP_TYPE_PERCPU_HASH**
 *		* **BPF_MAP_TYPE_LRU_HASH**
 *		* **BPF_MAP_TYPE_LRU_PERCPU_HASH**
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_FREEZE
 *	Description
 *		Freeze the permissions of the specified map.
 *
 *		Write permissions may be frozen by passing zero *flags*.
 *		Upon success, no future syscall invocations may alter the
 *		map state of *map_fd*. Write operations from eBPF programs
 *		are still possible for a frozen map.
 *
 *		Not supported for maps of type **BPF_MAP_TYPE_STRUCT_OPS**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_BTF_GET_NEXT_ID
 *	Description
 *		Fetch the next BPF Type Format (BTF) object currently loaded
 *		into the kernel.
 *
 *		Looks for the BTF object with an id greater than *start_id*
 *		and updates *next_id* on success. If no other BTF objects
 *		remain with ids higher than *start_id*, returns -1 and sets
 *		*errno* to **ENOENT**.
 *
 *	Return
 *		Returns zero on success. On error, or when no id remains, -1
 *		is returned and *errno* is set appropriately.
 *
 * BPF_MAP_LOOKUP_BATCH
 *	Description
 *		Iterate and fetch multiple elements in a map.
 *
 *		Two opaque values are used to manage batch operations,
 *		*in_batch* and *out_batch*. Initially, *in_batch* must be set
 *		to NULL to begin the batched operation. After each subsequent
 *		**BPF_MAP_LOOKUP_BATCH**, the caller should pass the resultant
 *		*out_batch* as the *in_batch* for the next operation to
 *		continue iteration from the current point.
 *
 *		The *keys* and *values* are output parameters which must point
 *		to memory large enough to hold *count* items based on the key
 *		and value size of the map *map_fd*. The *keys* buffer must be
 *		of *key_size* * *count*. The *values* buffer must be of
 *		*value_size* * *count*.
 *
 *		The *elem_flags* argument may be specified as one of the
 *		following:
 *
 *		**BPF_F_LOCK**
 *			Look up the value of a spin-locked map without
 *			returning the lock. This must be specified if the
 *			elements contain a spinlock.
 *
 *		On success, *count* elements from the map are copied into the
 *		user buffer, with the keys copied into *keys* and the values
 *		copied into the corresponding indices in *values*.
 *
 *		If an error is returned and *errno* is not **EFAULT**, *count*
 *		is set to the number of successfully processed elements.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		May set *errno* to **ENOSPC** to indicate that *keys* or
 *		*values* is too small to dump an entire bucket during
 *		iteration of a hash-based map type.
 *
 * BPF_MAP_LOOKUP_AND_DELETE_BATCH
 *	Description
 *		Iterate and delete all elements in a map.
 *
 *		This operation has the same behavior as
 *		**BPF_MAP_LOOKUP_BATCH** with two exceptions:
 *
 *		* Every element that is successfully returned is also deleted
 *		  from the map. This is at least *count* elements. Note that
 *		  *count* is both an input and an output parameter.
 *		* Upon returning with *errno* set to **EFAULT**, up to
 *		  *count* elements may be deleted without returning the keys
 *		  and values of the deleted elements.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_UPDATE_BATCH
 *	Description
 *		Update multiple elements in a map by *key*.
 *
 *		The *keys* and *values* are input parameters which must point
 *		to memory large enough to hold *count* items based on the key
 *		and value size of the map *map_fd*. The *keys* buffer must be
 *		of *key_size* * *count*. The *values* buffer must be of
 *		*value_size* * *count*.
 *
 *		Each element specified in *keys* is sequentially updated to the
 *		value in the corresponding index in *values*. The *in_batch*
 *		and *out_batch* parameters are ignored and should be zeroed.
 *
 *		The *elem_flags* argument should be specified as one of the
 *		following:
 *
 *		**BPF_ANY**
 *			Create new elements or update a existing elements.
 *		**BPF_NOEXIST**
 *			Create new elements only if they do not exist.
 *		**BPF_EXIST**
 *			Update existing elements.
 *		**BPF_F_LOCK**
 *			Update spin_lock-ed map elements. This must be
 *			specified if the map value contains a spinlock.
 *
 *		On success, *count* elements from the map are updated.
 *
 *		If an error is returned and *errno* is not **EFAULT**, *count*
 *		is set to the number of successfully processed elements.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		May set *errno* to **EINVAL**, **EPERM**, **ENOMEM**, or
 *		**E2BIG**. **E2BIG** indicates that the number of elements in
 *		the map reached the *max_entries* limit specified at map
 *		creation time.
 *
 *		May set *errno* to one of the following error codes under
 *		specific circumstances:
 *
 *		**EEXIST**
 *			If *flags* specifies **BPF_NOEXIST** and the element
 *			with *key* already exists in the map.
 *		**ENOENT**
 *			If *flags* specifies **BPF_EXIST** and the element with
 *			*key* does not exist in the map.
 *
 * BPF_MAP_DELETE_BATCH
 *	Description
 *		Delete multiple elements in a map by *key*.
 *
 *		The *keys* parameter is an input parameter which must point
 *		to memory large enough to hold *count* items based on the key
 *		size of the map *map_fd*, that is, *key_size* * *count*.
 *
 *		Each element specified in *keys* is sequentially deleted. The
 *		*in_batch*, *out_batch*, and *values* parameters are ignored
 *		and should be zeroed.
 *
 *		The *elem_flags* argument may be specified as one of the
 *		following:
 *
 *		**BPF_F_LOCK**
 *			Look up the value of a spin-locked map without
 *			returning the lock. This must be specified if the
 *			elements contain a spinlock.
 *
 *		On success, *count* elements from the map are updated.
 *
 *		If an error is returned and *errno* is not **EFAULT**, *count*
 *		is set to the number of successfully processed elements. If
 *		*errno* is **EFAULT**, up to *count* elements may be been
 *		deleted.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_LINK_CREATE
 *	Description
 *		Attach an eBPF program to a *target_fd* at the specified
 *		*attach_type* hook and return a file descriptor handle for
 *		managing the link.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_LINK_UPDATE
 *	Description
 *		Update the eBPF program in the specified *link_fd* to
 *		*new_prog_fd*.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_LINK_GET_FD_BY_ID
 *	Description
 *		Open a file descriptor for the eBPF Link corresponding to
 *		*link_id*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_LINK_GET_NEXT_ID
 *	Description
 *		Fetch the next eBPF link currently loaded into the kernel.
 *
 *		Looks for the eBPF link with an id greater than *start_id*
 *		and updates *next_id* on success. If no other eBPF links
 *		remain with ids higher than *start_id*, returns -1 and sets
 *		*errno* to **ENOENT**.
 *
 *	Return
 *		Returns zero on success. On error, or when no id remains, -1
 *		is returned and *errno* is set appropriately.
 *
 * BPF_ENABLE_STATS
 *	Description
 *		Enable eBPF runtime statistics gathering.
 *
 *		Runtime statistics gathering for the eBPF runtime is disabled
 *		by default to minimize the corresponding performance overhead.
 *		This command enables statistics globally.
 *
 *		Multiple programs may independently enable statistics.
 *		After gathering the desired statistics, eBPF runtime statistics
 *		may be disabled again by calling **close**\ (2) for the file
 *		descriptor returned by this function. Statistics will only be
 *		disabled system-wide when all outstanding file descriptors
 *		returned by prior calls for this subcommand are closed.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_ITER_CREATE
 *	Description
 *		Create an iterator on top of the specified *link_fd* (as
 *		previously created using **BPF_LINK_CREATE**) and return a
 *		file descriptor that can be used to trigger the iteration.
 *
 *		If the resulting file descriptor is pinned to the filesystem
 *		using  **BPF_OBJ_PIN**, then subsequent **read**\ (2) syscalls
 *		for that path will trigger the iterator to read kernel state
 *		using the eBPF program attached to *link_fd*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_LINK_DETACH
 *	Description
 *		Forcefully detach the specified *link_fd* from its
 *		corresponding attachment point.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_PROG_BIND_MAP
 *	Description
 *		Bind a map to the lifetime of an eBPF program.
 *
 *		The map identified by *map_fd* is bound to the program
 *		identified by *prog_fd* and only released when *prog_fd* is
 *		released. This may be used in cases where metadata should be
 *		associated with a program which otherwise does not contain any
 *		references to the map (for example, embedded in the eBPF
 *		program instructions).
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * NOTES
 *	eBPF objects (maps and programs) can be shared between processes.
 *
 *	* After **fork**\ (2), the child inherits file descriptors
 *	  referring to the same eBPF objects.
 *	* File descriptors referring to eBPF objects can be transferred over
 *	  **unix**\ (7) domain sockets.
 *	* File descriptors referring to eBPF objects can be duplicated in the
 *	  usual way, using **dup**\ (2) and similar calls.
 *	* File descriptors referring to eBPF objects can be pinned to the
 *	  filesystem using the **BPF_OBJ_PIN** command of **bpf**\ (2).
 *
 *	An eBPF object is deallocated only after all file descriptors referring
 *	to the object have been closed and no references remain pinned to the
 *	filesystem or attached (for example, bound to a program or device).
 */
enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN,
	BPF_PROG_RUN = BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD,
	BPF_BTF_GET_FD_BY_ID,
	BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
	BPF_MAP_LOOKUP_BATCH,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH,
	BPF_MAP_UPDATE_BATCH,
	BPF_MAP_DELETE_BATCH,
	BPF_LINK_CREATE,
	BPF_LINK_UPDATE,
	BPF_LINK_GET_FD_BY_ID,
	BPF_LINK_GET_NEXT_ID,
	BPF_ENABLE_STATS,
	BPF_ITER_CREATE,
	BPF_LINK_DETACH,
	BPF_PROG_BIND_MAP,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	/* BPF_MAP_TYPE_CGROUP_STORAGE is available to bpf programs attaching
	 * to a cgroup. The newer BPF_MAP_TYPE_CGRP_STORAGE is available to
	 * both cgroup-attached and other progs and supports all functionality
	 * provided by BPF_MAP_TYPE_CGROUP_STORAGE. So mark
	 * BPF_MAP_TYPE_CGROUP_STORAGE deprecated.
	 */
	BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS,
	BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_INODE_STORAGE,
	BPF_MAP_TYPE_TASK_STORAGE,
	BPF_MAP_TYPE_BLOOM_FILTER,
	BPF_MAP_TYPE_USER_RINGBUF,
	BPF_MAP_TYPE_CGRP_STORAGE,
};

/* Note that tracing related programs such as
 * BPF_PROG_TYPE_{KPROBE,TRACEPOINT,PERF_EVENT,RAW_TRACEPOINT}
 * are not subject to a stable API since kernel internal data
 * structures can change from release to release and may
 * therefore break existing tracing BPF programs. Tracing BPF
 * programs correspond to /a/ specific kernel which is to be
 * analyzed, and not /a/ specific kernel /and/ all future ones.
 */
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL, /* a program that can execute syscalls */
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS,
	BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE,
	BPF_CGROUP_SOCK_OPS,
	BPF_SK_SKB_STREAM_PARSER,
	BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_DEVICE,
	BPF_SK_MSG_VERDICT,
	BPF_CGROUP_INET4_BIND,
	BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT,
	BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND,
	BPF_CGROUP_INET6_POST_BIND,
	BPF_CGROUP_UDP4_SENDMSG,
	BPF_CGROUP_UDP6_SENDMSG,
	BPF_LIRC_MODE2,
	BPF_FLOW_DISSECTOR,
	BPF_CGROUP_SYSCTL,
	BPF_CGROUP_UDP4_RECVMSG,
	BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT,
	BPF_CGROUP_SETSOCKOPT,
	BPF_TRACE_RAW_TP,
	BPF_TRACE_FENTRY,
	BPF_TRACE_FEXIT,
	BPF_MODIFY_RETURN,
	BPF_LSM_MAC,
	BPF_TRACE_ITER,
	BPF_CGROUP_INET4_GETPEERNAME,
	BPF_CGROUP_INET6_GETPEERNAME,
	BPF_CGROUP_INET4_GETSOCKNAME,
	BPF_CGROUP_INET6_GETSOCKNAME,
	BPF_XDP_DEVMAP,
	BPF_CGROUP_INET_SOCK_RELEASE,
	BPF_XDP_CPUMAP,
	BPF_SK_LOOKUP,
	BPF_XDP,
	BPF_SK_SKB_VERDICT,
	BPF_SK_REUSEPORT_SELECT,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
	BPF_PERF_EVENT,
	BPF_TRACE_KPROBE_MULTI,
	BPF_LSM_CGROUP,
	__MAX_BPF_ATTACH_TYPE
};

#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	BPF_LINK_TYPE_STRUCT_OPS = 9,

	MAX_BPF_LINK_TYPE,
};

/* cgroup-bpf attach flags used in BPF_PROG_ATTACH command
 *
 * NONE(default): No further bpf programs allowed in the subtree.
 *
 * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
 * the program in this cgroup yields to sub-cgroup program.
 *
 * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
 * that cgroup program gets run in addition to the program in this cgroup.
 *
 * Only one program is allowed to be attached to a cgroup with
 * NONE or BPF_F_ALLOW_OVERRIDE flag.
 * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
 * release old program and attach the new one. Attach flags has to match.
 *
 * Multiple programs are allowed to be attached to a cgroup with
 * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
 * (those that were attached first, run first)
 * The programs of sub-cgroup are executed first, then programs of
 * this cgroup and then programs of parent cgroup.
 * When children program makes decision (like picking TCP CA or sock bind)
 * parent program has a chance to override it.
 *
 * With BPF_F_ALLOW_MULTI a new program is added to the end of the list of
 * programs for a cgroup. Though it's possible to replace an old program at
 * any position by also specifying BPF_F_REPLACE flag and position itself in
 * replace_bpf_fd attribute. Old program at this position will be released.
 *
 * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
 * A cgroup with NONE doesn't allow any programs in sub-cgroups.
 * Ex1:
 * cgrp1 (MULTI progs A, B) ->
 *    cgrp2 (OVERRIDE prog C) ->
 *      cgrp3 (MULTI prog D) ->
 *        cgrp4 (OVERRIDE prog E) ->
 *          cgrp5 (NONE prog F)
 * the event in cgrp5 triggers execution of F,D,A,B in that order.
 * if prog F is detached, the execution is E,D,A,B
 * if prog F and D are detached, the execution is E,A,B
 * if prog F, E and D are detached, the execution is C,A,B
 *
 * All eligible programs are executed regardless of return code from
 * earlier programs.
 */
#define BPF_F_ALLOW_OVERRIDE	(1U << 0)
#define BPF_F_ALLOW_MULTI	(1U << 1)
#define BPF_F_REPLACE		(1U << 2)

/* If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the
 * verifier will perform strict alignment checking as if the kernel
 * has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
 * and NET_IP_ALIGN defined to 2.
 */
#define BPF_F_STRICT_ALIGNMENT	(1U << 0)

/* If BPF_F_ANY_ALIGNMENT is used in BPF_PROF_LOAD command, the
 * verifier will allow any alignment whatsoever.  On platforms
 * with strict alignment requirements for loads ands stores (such
 * as sparc and mips) the verifier validates that all loads and
 * stores provably follow this requirement.  This flag turns that
 * checking and enforcement off.
 *
 * It is mostly used for testing when we want to validate the
 * context and memory access aspects of the verifier, but because
 * of an unaligned access the alignment check would trigger before
 * the one we are interested in.
 */
#define BPF_F_ANY_ALIGNMENT	(1U << 1)

/* BPF_F_TEST_RND_HI32 is used in BPF_PROG_LOAD command for testing purpose.
 * Verifier does sub-register def/use analysis and identifies instructions whose
 * def only matters for low 32-bit, high 32-bit is never referenced later
 * through implicit zero extension. Therefore verifier notifies JIT back-ends
 * that it is safe to ignore clearing high 32-bit for these instructions. This
 * saves some back-ends a lot of code-gen. However such optimization is not
 * necessary on some arches, for example x86_64, arm64 etc, whose JIT back-ends
 * hence hasn't used verifier's analysis result. But, we really want to have a
 * way to be able to verify the correctness of the described optimization on
 * x86_64 on which testsuites are frequently exercised.
 *
 * So, this flag is introduced. Once it is set, verifier will randomize high
 * 32-bit for those instructions who has been identified as safe to ignore them.
 * Then, if verifier is not doing correct analysis, such randomization will
 * regress tests to expose bugs.
 */
#define BPF_F_TEST_RND_HI32	(1U << 2)

/* The verifier internal test flag. Behavior is undefined */
#define BPF_F_TEST_STATE_FREQ	(1U << 3)

/* If BPF_F_SLEEPABLE is used in BPF_PROG_LOAD command, the verifier will
 * restrict map and helper usage for such programs. Sleepable BPF programs can
 * only be attached to hooks where kernel execution context allows sleeping.
 * Such programs are allowed to use helpers that may sleep like
 * bpf_copy_from_user().
 */
#define BPF_F_SLEEPABLE		(1U << 4)

/* If BPF_F_XDP_HAS_FRAGS is used in BPF_PROG_LOAD command, the loaded program
 * fully support xdp frags.
 */
#define BPF_F_XDP_HAS_FRAGS	(1U << 5)

/* link_create.kprobe_multi.flags used in LINK_CREATE command for
 * BPF_TRACE_KPROBE_MULTI attach type to create return probe.
 */
#define BPF_F_KPROBE_MULTI_RETURN	(1U << 0)

/* When BPF ldimm64's insn[0].src_reg != 0 then this can have
 * the following extensions:
 *
 * insn[0].src_reg:  BPF_PSEUDO_MAP_[FD|IDX]
 * insn[0].imm:      map fd or fd_idx
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map
 * verifier type:    CONST_PTR_TO_MAP
 */
#define BPF_PSEUDO_MAP_FD	1
#define BPF_PSEUDO_MAP_IDX	5

/* insn[0].src_reg:  BPF_PSEUDO_MAP_[IDX_]VALUE
 * insn[0].imm:      map fd or fd_idx
 * insn[1].imm:      offset into value
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map[0]+offset
 * verifier type:    PTR_TO_MAP_VALUE
 */
#define BPF_PSEUDO_MAP_VALUE		2
#define BPF_PSEUDO_MAP_IDX_VALUE	6

/* insn[0].src_reg:  BPF_PSEUDO_BTF_ID
 * insn[0].imm:      kernel btd id of VAR
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the kernel variable
 * verifier type:    PTR_TO_BTF_ID or PTR_TO_MEM, depending on whether the var
 *                   is struct/union.
 */
#define BPF_PSEUDO_BTF_ID	3
/* insn[0].src_reg:  BPF_PSEUDO_FUNC
 * insn[0].imm:      insn offset to the func
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the function
 * verifier type:    PTR_TO_FUNC.
 */
#define BPF_PSEUDO_FUNC		4

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL		1
/* when bpf_call->src_reg == BPF_PSEUDO_KFUNC_CALL,
 * bpf_call->imm == btf_id of a BTF_KIND_FUNC in the running kernel
 */
#define BPF_PSEUDO_KFUNC_CALL	2

/* flags for BPF_MAP_UPDATE_ELEM command */
enum {
	BPF_ANY		= 0, /* create new element or update existing */
	BPF_NOEXIST	= 1, /* create new element if it didn't exist */
	BPF_EXIST	= 2, /* update existing element */
	BPF_F_LOCK	= 4, /* spin_lock-ed map_lookup/map_update */
};

/* flags for BPF_MAP_CREATE command */
enum {
	BPF_F_NO_PREALLOC	= (1U << 0),
/* Instead of having one common LRU list in the
 * BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
 * which can scale and perform better.
 * Note, the LRU nodes (including free nodes) cannot be moved
 * across different LRU lists.
 */
	BPF_F_NO_COMMON_LRU	= (1U << 1),
/* Specify numa node during map creation */
	BPF_F_NUMA_NODE		= (1U << 2),

/* Flags for accessing BPF object from syscall side. */
	BPF_F_RDONLY		= (1U << 3),
	BPF_F_WRONLY		= (1U << 4),

/* Flag for stack_map, store build_id+offset instead of pointer */
	BPF_F_STACK_BUILD_ID	= (1U << 5),

/* Zero-initialize hash function seed. This should only be used for testing. */
	BPF_F_ZERO_SEED		= (1U << 6),

/* Flags for accessing BPF object from program side. */
	BPF_F_RDONLY_PROG	= (1U << 7),
	BPF_F_WRONLY_PROG	= (1U << 8),

/* Clone map from listener for newly accepted socket */
	BPF_F_CLONE		= (1U << 9),

/* Enable memory-mapping BPF map */
	BPF_F_MMAPABLE		= (1U << 10),

/* Share perf_event among processes */
	BPF_F_PRESERVE_ELEMS	= (1U << 11),

/* Create a map that is suitable to be an inner map with dynamic max entries */
	BPF_F_INNER_MAP		= (1U << 12),
};

/* Flags for BPF_PROG_QUERY. */

/* Query effective (directly attached + inherited from ancestor cgroups)
 * programs that will be executed for events within a cgroup.
 * attach_flags with this flag are always returned 0.
 */
#define BPF_F_QUERY_EFFECTIVE	(1U << 0)