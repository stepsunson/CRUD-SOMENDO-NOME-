#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sysexits.h>

#include "libbpf.h"

// TODO: Remove this when CentOS 6 support is not needed anymore
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

static const char * const prog_type_strings[] = {
  [BPF_PROG_TYPE_UNSPEC] = "unspec",
  [BPF_PROG_TYPE_SOCKET_FILTER] = "socket filter",
  [BPF_PROG_TYPE_KPROBE] = "kprobe",
  [BPF_PROG_TYPE_SCHED_CLS] = "sched cls",
  [BPF_PROG_TYPE_SCHED_ACT] = "sched act",
  [BPF_PROG_TYPE_TRACEPOINT] = "tracepoint",
  [BPF_PROG_TYPE_XDP] = "xdp",
  [BPF_PROG_TYPE_PERF_EVENT] = "perf event",
  [BPF_PROG_TYPE_CGROUP_SKB] = "cgroup skb",
  [BPF_PROG_TYPE_CGROUP_SOCK] = "cgroup sock",
  [BPF_PROG_TYPE_LWT_IN] = "lwt in",
  [BPF_PROG_TYPE_LWT_OUT] = "lwt out",
  [BPF_PROG_TYPE_LWT_XMIT] = "lwt xmit",
  [BPF_PROG_TYPE_SOCK_OPS] = "sock ops",
  [BPF_PROG_TYPE_SK_SKB] = "sk skb",
  [BPF_PROG_TYPE_CGROUP_DEVICE] = "cgroup_device",
  [BPF_PROG_TYPE_SK_MSG] = "sk_msg",
  [BPF_PROG_TYPE_RAW_TRACEPOINT] = "raw_tracepoint",
  [BPF_PROG_TYPE_CGROUP_SOCK_ADDR] = "cgroup_sock_addr",
  [BPF_PROG_TYPE_LIRC_MODE2] = "lirc_mode2",
  [BPF_PROG_TYPE_SK_REUSEPORT] = "sk_reuseport",
  [BPF_PROG_TYPE_FLOW_DISSECTOR] = "flow_dissector",
  [BPF_PROG_TYPE_CGROUP_SYSCTL] = "cgroup_sysctl",
  [BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE] = "raw_tracepoint_writable",
  [BPF_PROG_TYPE_CGROUP_SOCKOPT] = "cgroup_sockopt",
  [BPF_PROG_TYPE_TRACING] = "tracing",
  [BPF_PROG_TYPE_STRUCT_OPS] = "struct_ops",
  [BPF_PROG_TYPE_EXT] = "ext",
  [BPF_PROG_TYPE_LSM] = "lsm",
  [BPF_PROG_TYPE_SK_LOOKUP] = "sk_lookup",
  [BPF_PROG_TYPE_SYSCALL] = "syscall",
};

static const char * const map_type_strings[] = {
  [BPF_MAP_TYPE_UNSPEC] = "unspec",
  [BPF_MAP_TYPE_HASH] = "hash",
  [BPF_MAP_TYPE_ARRAY] = "array",
  [BPF_MAP_TYPE_PROG_ARRAY] = "prog array",
  [BPF_MAP_TYPE_PERF_EVENT_ARRAY] = "perf-ev array",
  [BPF_MAP_TYPE_PERCPU_HASH] = "percpu hash",
  [BPF_MAP_TYPE_PERCPU_ARRAY] = "percpu array",
  [BPF_MAP_TYPE_STACK_TRACE] = "stack trace",
  [BPF_MAP_TYPE_CGROUP_ARRAY] = "cgroup array",
  [BPF_MAP_TYPE_LRU_HASH] = "lru hash",
  [BPF_MAP_TYPE_LRU_PERCPU_HASH] = "lru percpu hash",
  [BPF_MAP_TYPE_LPM_TRIE] = "lpm trie",
  [BPF_MAP_TYPE_ARRAY_OF_MAPS] = "array of maps",
  [BPF_MAP_TYPE_HASH_OF_MAPS] = "hash of maps",
  [BPF_MAP_TYPE_DEVMAP] = "devmap",
  [BPF_MAP_TYPE_SOCKMAP] = "sockmap",
  [BPF_MAP_TYPE_CPUMAP] = "cpumap",
  [BPF_MAP_TYPE_SOCKHASH] = "sockhash",
  [BPF_MAP_TYPE_CGROUP_STORAGE] = "cgroup_storage",
  [BPF_MAP_TYPE_REUSEPORT_SOCKARRAY] = "reuseport_sockarray",
  [BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE] = "precpu_cgroup_storage",
  [BPF_MAP_TYPE_QUEUE] = "queue",
  [BPF_MAP_TYPE_STACK] = "stack",
  [BPF_MAP_TYPE_SK_STORAGE] = "sk_storage",
  [BPF_MAP_TYPE_DEVMAP_HASH] = "devmap_hash",
  [BPF_MAP_TYPE_STRUCT_OPS] = "struct_ops",
  [BPF_MAP_TYPE_RINGBUF] = "ringbuf",
  [BPF_MAP_TYPE_INODE_STORAGE] = "inode_storage",
  [BPF_MAP_TYPE_TASK_STORAGE] = "task_storage",
  [BPF_MAP_TYPE_BLOOM_FILTER] = "bloom_filter",
  [BPF_MAP_TYPE_USER_RINGBUF] = "user_ringbuf",
  [BPF_MAP_TYPE_CGRP_STORAGE] = "cgrp_storage",
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define LAST_KNOWN_PROG_TYPE (ARRAY_SIZE(prog_type_strings) - 1)
#define LAST_KNOWN_MAP_TYPE (ARRAY_SIZE(map_type_strings) - 1)
#define min(x, y) ((x) < (y) ? (x) : (y))

static inline uint64_t ptr_to_u64(const void *ptr)
{
  return (uint64_t) (unsigned long) ptr;
}

static inline void * u64_to_ptr(uint64_t ptr)
{
  return (void *) (unsigned long ) ptr;
}

static int handle_get_next_errno(int eno)
{
  switch (eno) {
    case ENOENT:
      return 0;
    case EINVAL:
      fprintf(stderr, "Kernel does not support BPF introspection\n");
      return EX_UNAVAILABLE;
    case EPERM:
      fprintf(stderr,
              "Require CAP_SYS_ADMIN capability.  Please retry as root\n");
      return EX_NOPERM;
    default:
      fprintf(stderr, "%s\n", strerror(errno));
      return 1;
  }
}

static void print_prog