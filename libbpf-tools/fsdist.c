/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * fsdist  Summarize file system operations latency.
 *
 * Copyright (c) 2021 Wenbo Zhang
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on ext4dist(8) from BCC by Brendan Gregg.
 * 9-Feb-2021   Wenbo Zhang   Created this.
 * 20-May-2021   Hengqi Chen  Migrated to fsdist.
 */
#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fsdist.h"
#include "fsdist.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

enum fs_type {
	NONE,
	BTRFS,
	EXT4,
	NFS,
	XFS,
};

static struct fs_config {
	const char *fs;
	const char *op_funcs[F_MAX_OP];
} fs_configs[] = {
	[BTRFS] = { "btrfs", {
		[F_READ] = "btrfs_file_read_iter",
		[F_WRITE] = "btrfs_file_write_iter",
		[F_OPEN] = "btrfs_file_open",
		[F_FSYNC] = "btrfs_sync_file",
		[F_GETATTR] = NULL, /* not supported */
	}},
	[EXT4] = { "ext4", {
		[F_READ] = "ext4_file_read_iter",
		[F_WRITE] = "ext4_file_write_iter",
		[F_OPEN] = "ext4_file_open",
		[F_FSYNC] = "ext4_sync_file",
		[F_GETATTR] = "ext4_file_getattr",
	}},
	[NFS] = { "nfs", {
		[F_READ] = "nfs_file_read",
		[F_WRITE] = "nfs_file_write",
		[F_OPEN] = "nfs_file_open",
		[F_FSYNC] = "nfs_file_fsync",
		[F_GETATTR] = "nfs_getattr",
	}},
	[XFS] = { "xfs", {
		[F_READ] = "xfs_file_read_iter",
		[F_WRITE] = "xfs_file_write_iter",
		[F_OPEN] = "xfs_file_open",
		[F_FSYNC] = "xfs_file_fsync",
		[F_GETATTR] = NULL, /* not supported */
	}},
};

static char *file_op_names[] = {
	[F_READ] = "read",
	[F_WRITE] = "write",
	[F_OPEN] = "open",
	[F_FSYNC] = "fsync",
	[F_GETATTR] = "getattr",
};

static struct hist zero;
static volatile sig_atomic_t exiting;

/* options */
static enum fs_type fs_type = NONE;
static bool emit_timestamp = false;
static bool timestamp_in_ms = false;
static pid_t target_pid = 0;
static int interval = 99999999;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "fsdist 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize file system operations latency.\n"
"\n"
"Usage: fsdist [-h] [-t] [-T] [-m] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLE