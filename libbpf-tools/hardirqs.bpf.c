// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	256

const volatile bool filter_cg = false;
const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile bool do_count = false;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
