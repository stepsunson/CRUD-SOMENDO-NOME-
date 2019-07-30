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
  [BPF_MAP_TYPE_PERF_EVENT_ARRAY] = "perf-ev a