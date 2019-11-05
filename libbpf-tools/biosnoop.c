// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on biosnoop(8) from BCC by Brendan Gregg.
// 29-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include "blk_types.h"
#include "biosnoop.h"
#include "biosnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static struct env {
	char *disk;
	int duration;
	bool timestamp;
	bool queued;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {};

static volatile __u64 start_ts;

const char *argp_program_version = "biosnoop 0.1";
const char