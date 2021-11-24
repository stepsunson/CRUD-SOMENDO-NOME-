
R"********(
/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

/* Before bpf_helpers.h is included, uapi bpf.h has been
 * included, which references linux/types.h. This may bring
 * in asm_volatile_goto definition if permitted based on
 * compiler setup and kernel configs.
 *
 * clang does not support "asm volatile goto" yet.
 * So redefine asm_volatile_goto to some invalid asm code.
 * If asm_volatile_goto is actually used by the bpf program,
 * a compilation error will appear.
 */
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

/* In 4.18 and later, when CONFIG_FUNCTION_TRACER is defined, kernel Makefile adds
 * -DCC_USING_FENTRY. Let do the same for bpf programs.
 */
#if defined(CONFIG_FUNCTION_TRACER)
#define CC_USING_FENTRY
#endif

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_packet.h>
#include <linux/version.h>
#include <linux/log2.h>
#include <asm/page.h>

#ifndef CONFIG_BPF_SYSCALL
#error "CONFIG_BPF_SYSCALL is undefined, please check your .config or ask your Linux distro to enable this feature"
#endif

#ifdef PERF_MAX_STACK_DEPTH
#define BPF_MAX_STACK_DEPTH PERF_MAX_STACK_DEPTH
#else
#define BPF_MAX_STACK_DEPTH 127
#endif

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define BCC_SEC(NAME) __attribute__((section(NAME), used))

#ifdef B_WORKAROUND
#define BCC_SEC_HELPERS BCC_SEC("helpers")
#else
#define BCC_SEC_HELPERS
#endif

// Associate map with its key/value types
#define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)	\
        struct ____btf_map_##name {			\
                type_key key;				\
                type_val value;				\
        };						\
        struct ____btf_map_##name			\
        __attribute__ ((section(".maps." #name), used))	\
                ____btf_map_##name = { }

// Associate map with its key/value types for QUEUE/STACK map types
#define BPF_ANNOTATE_KV_PAIR_QUEUESTACK(name, type_val)  \
        struct ____btf_map_##name {     \
                type_val value;       \
        };            \
        struct ____btf_map_##name     \
        __attribute__ ((section(".maps." #name), used)) \
                ____btf_map_##name = { }

// Changes to the macro require changes in BFrontendAction classes
#define BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, _flags) \
struct _name##_table_t { \
  _key_type key; \
  _leaf_type leaf; \
  _leaf_type * (*lookup) (_key_type *); \
  _leaf_type * (*lookup_or_init) (_key_type *, _leaf_type *); \
  _leaf_type * (*lookup_or_try_init) (_key_type *, _leaf_type *); \
  int (*update) (_key_type *, _leaf_type *); \
  int (*insert) (_key_type *, _leaf_type *); \
  int (*delete) (_key_type *); \
  void (*call) (void *, int index); \
  void (*increment) (_key_type, ...); \
  void (*atomic_increment) (_key_type, ...); \
  int (*get_stackid) (void *, u64); \
  void * (*sk_storage_get) (void *, void *, int); \
  int (*sk_storage_delete) (void *); \
  void * (*inode_storage_get) (void *, void *, int); \
  int (*inode_storage_delete) (void *); \
  void * (*task_storage_get) (void *, void *, int); \
  int (*task_storage_delete) (void *); \
  u32 max_entries; \
  int flags; \
}; \
__attribute__((section("maps/" _table_type))) \
struct _name##_table_t _name = { .flags = (_flags), .max_entries = (_max_entries) }; \
BPF_ANNOTATE_KV_PAIR(_name, _key_type, _leaf_type)


// Changes to the macro require changes in BFrontendAction classes
#define BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags) \
struct _name##_table_t { \
  _leaf_type leaf; \
  int * (*peek) (_leaf_type *); \
  int * (*pop) (_leaf_type *); \
  int * (*push) (_leaf_type *, u64); \
  u32 max_entries; \
  int flags; \
}; \
__attribute__((section("maps/" _table_type))) \
struct _name##_table_t _name = { .flags = (_flags), .max_entries = (_max_entries) }; \
BPF_ANNOTATE_KV_PAIR_QUEUESTACK(_name, _leaf_type)

// define queue with 3 parameters (_type=queue/stack automatically) and default flags to 0
#define BPF_QUEUE_STACK3(_type, _name, _leaf_type, _max_entries) \
  BPF_QUEUESTACK(_type, _name, _leaf_type, _max_entries, 0)

// define queue with 4 parameters (_type=queue/stack automatically)
#define BPF_QUEUE_STACK4(_type, _name, _leaf_type, _max_entries, _flags) \
  BPF_QUEUESTACK(_type, _name, _leaf_type, _max_entries, _flags)

// helper for default-variable macro function
#define BPF_QUEUE_STACKX(_1, _2, _3, _4, NAME, ...) NAME

#define BPF_QUEUE(...) \
  BPF_QUEUE_STACKX(__VA_ARGS__, BPF_QUEUE_STACK4, BPF_QUEUE_STACK3)("queue", __VA_ARGS__)

#define BPF_STACK(...) \
  BPF_QUEUE_STACKX(__VA_ARGS__, BPF_QUEUE_STACK4, BPF_QUEUE_STACK3)("stack", __VA_ARGS__)

#define BPF_QUEUESTACK_PINNED(_table_type, _name, _leaf_type, _max_entries, _flags, _pinned) \
BPF_QUEUESTACK(_table_type ":" _pinned, _name, _leaf_type, _max_entries, _flags)

#define BPF_QUEUESTACK_PUBLIC(_table_type, _name, _leaf_type, _max_entries, _flags) \
BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags); \
__attribute__((section("maps/export"))) \
struct _name##_table_t __##_name

#define BPF_QUEUESTACK_SHARED(_table_type, _name, _leaf_type, _max_entries, _flags) \
BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags); \
__attribute__((section("maps/shared"))) \
struct _name##_table_t __##_name

#define BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, 0)

#define BPF_TABLE_PINNED7(_table_type, _key_type, _leaf_type, _name, _max_entries, _pinned, _flags) \
  BPF_F_TABLE(_table_type ":" _pinned, _key_type, _leaf_type, _name, _max_entries, _flags)

#define BPF_TABLE_PINNED6(_table_type, _key_type, _leaf_type, _name, _max_entries, _pinned) \
  BPF_F_TABLE(_table_type ":" _pinned, _key_type, _leaf_type, _name, _max_entries, 0)

#define BPF_TABLE_PINNEDX(_1, _2, _3, _4, _5, _6, _7, NAME, ...) NAME

// Define a pinned table with optional flags argument
#define BPF_TABLE_PINNED(...) \
  BPF_TABLE_PINNEDX(__VA_ARGS__, BPF_TABLE_PINNED7, BPF_TABLE_PINNED6)(__VA_ARGS__)

// define a table same as above but allow it to be referenced by other modules
#define BPF_TABLE_PUBLIC(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
__attribute__((section("maps/export"))) \
struct _name##_table_t __##_name

// define a table that is shared across the programs in the same namespace
#define BPF_TABLE_SHARED(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
__attribute__((section("maps/shared"))) \
struct _name##_table_t __##_name

// Identifier for current CPU used in perf_submit and perf_read
// Prefer BPF_F_CURRENT_CPU flag, falls back to call helper for older kernel
// Can be overridden from BCC
#ifndef CUR_CPU_IDENTIFIER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
#else
#define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
#endif
#endif

// Table for pushing custom events to userspace via perf ring buffer
#define BPF_PERF_OUTPUT(_name) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  /* map.perf_submit(ctx, data, data_size) */ \
  int (*perf_submit) (void *, void *, u32); \
  int (*perf_submit_skb) (void *, u32, void *, u32); \
  u32 max_entries; \
}; \
__attribute__((section("maps/perf_output"))) \
struct _name##_table_t _name = { .max_entries = 0 }

// Table for pushing custom events to userspace via ring buffer
#define BPF_RINGBUF_OUTPUT(_name, _num_pages) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  /* map.ringbuf_output(data, data_size, flags) */ \
  int (*ringbuf_output) (void *, u64, u64); \
  /* map.ringbuf_reserve(data_size) */ \
  void* (*ringbuf_reserve) (u64); \
  /* map.ringbuf_discard(data, flags) */ \
  void (*ringbuf_discard) (void *, u64); \
  /* map.ringbuf_submit(data, flags) */ \
  void (*ringbuf_submit) (void *, u64); \
  u32 max_entries; \
}; \
__attribute__((section("maps/ringbuf"))) \
struct _name##_table_t _name = { .max_entries = ((_num_pages) * PAGE_SIZE) }

// Table for reading hw perf cpu counters
#define BPF_PERF_ARRAY(_name, _max_entries) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  /* counter = map.perf_read(index) */ \
  u64 (*perf_read) (int); \
  int (*perf_counter_value) (int, void *, u32); \
  u32 max_entries; \
}; \
__attribute__((section("maps/perf_array"))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }

// Table for cgroup file descriptors
#define BPF_CGROUP_ARRAY(_name, _max_entries) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  int (*check_current_task) (int); \
  u32 max_entries; \
}; \
__attribute__((section("maps/cgroup_array"))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }

#define BPF_HASH1(_name) \
  BPF_TABLE("hash", u64, u64, _name, 10240)
#define BPF_HASH2(_name, _key_type) \
  BPF_TABLE("hash", _key_type, u64, _name, 10240)
#define BPF_HASH3(_name, _key_type, _leaf_type) \
  BPF_TABLE("hash", _key_type, _leaf_type, _name, 10240)
#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
  BPF_TABLE("hash", _key_type, _leaf_type, _name, _size)

// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME

// Define a hash function, some arguments optional
// BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)
#define BPF_HASH(...) \
  BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3, BPF_HASH2, BPF_HASH1)(__VA_ARGS__)

#define BPF_PERCPU_HASH1(_name) \
  BPF_TABLE("percpu_hash", u64, u64, _name, 10240)
#define BPF_PERCPU_HASH2(_name, _key_type) \
  BPF_TABLE("percpu_hash", _key_type, u64, _name, 10240)
#define BPF_PERCPU_HASH3(_name, _key_type, _leaf_type) \
  BPF_TABLE("percpu_hash", _key_type, _leaf_type, _name, 10240)