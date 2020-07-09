/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * mountsnoop  Trace mount and umount[2] syscalls
 *
 * Copyright (c) 2021 Hengqi Chen
 * 30-May-2021   Hengqi Chen   Created this.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mountsnoop.h"
#include "mountsnoop.skel.h"
#include "compat.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

/* https://www.gnu.org/software/gnulib/manual/html_node/strerrorname_005fnp.html */
#if !defined(__GLIBC__) || __GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 32)
	const char *strerrorname_np(int errnum)
	{
		return NULL;
	}
#endif

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool emit_timestamp = false;
static bool output_vertically = false;
static bool verbose = false;
static const char *flag_names[] = {
	[0] = "MS_RDONLY",
	[1] = "MS_NOSUID",
	[2] = "MS_NODEV",
	[3] = "MS_NOEXEC",
	[4] = "MS_SYNCHRONOUS",
	[5] = "MS_REMOUNT",
	[6] = "MS_MANDLOCK",
	[7] = "MS_DIRSYNC",
	[8] = "MS_NOSYMFOLLOW",
	[9] = "MS_NOATIME",
	[10] = "MS_NODIRATIME",
	[11] = "MS_BIND",
	[12] = "MS_MOVE",
	[13] = "MS_REC",
	[14] = "MS_VERBOSE",
	[15] = "MS_SILENT",
	[16] = "MS_POSIXACL",
	[17] = "MS_UNBINDABLE",
	[18] = "MS_PRIVATE",
	[19] = "MS_SLAVE",
	[20] = "MS_SHARED",
	[21] = "MS_RELATIME",
	[22] = "MS_KERNMOUNT",
	[23] = "MS_I_VERSION",
	[24] = "MS_STRICTATIME",
	[25] = "MS_LAZYTIME",
	[26] = "MS_SUBMOUNT",
	[27] = "MS_NOREMOTELOCK",
	[28] = "MS_NOSEC",
	[29] = "MS_BORN",
	[30] = "MS_ACTIVE",
	[31] = "MS_NOUSER",
};
static const int flag_count = sizeof(flag_names) / sizeof(flag_names[0]);

const char *argp_program_version = "mountsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const c