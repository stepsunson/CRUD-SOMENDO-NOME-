/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * fsslower  Trace file system operations slower than a threshold.
 *
 * Copyright (c) 2020 Wenbo Zhang
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on xfsslower(8) from BCC by Brendan Gregg & Dina Goldshtein.
 * 9-Mar-2020   Wenbo Zhang   Created this.
 * 27-May-2021  Hengqi Chen   Migrated to fsslower.
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

#include "fsslower.h"
#include "fsslower.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	64
#define PERF_POLL_TIMEOUT_MS	100

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
	}},
	[EXT4] = { "ext4", {
		[F_READ] = "ext4_file_read_iter",
		[F_WRITE] = "ext4_file_write_iter",
		[F_OPEN] = "ext4_file_open",
		[F_FSYNC] = "ext4_sync_file",
	}},
	[NFS] = { "nfs", {
		[F_READ] = "nfs_file_read",
		[F_WRITE] = "nfs_file_write",
		[F_OPEN] = "nfs_file_open",
		[F_FSYNC] = "nfs_file_fsync",
	}},
	[XFS] = { "xfs", {
		[F_READ] = "xfs_file_read_iter",
		[F_WRITE] = "xfs_file_write_iter",
		[F_OPEN] = "xfs_file_open",
		[F_FSYNC] = "xfs_file_fsync",
	}},
};

static char file_op[] = {
	[F_READ] = 'R',
	[F_WRITE] = 'W',
	[F_OPEN] = 'O',
	[F_FS