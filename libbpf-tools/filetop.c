/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * filetop Trace file reads/writes by process.
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on filetop(8) from BCC by Brendan Gregg.
 * 17-Jul-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "filetop.h"
#include "filetop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

enum SORT {
	ALL,
	READS,
	WRITES,
	RBYTES,
	WBYTES,
};

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool clear_screen = true;
static bool regular_file_only = true;
static int output_rows = 20;
static int sort_by = ALL;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "filetop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace file reads/writes by process.\n"
"\n"
"USAGE: filetop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    filetop            # file I/O top, refresh every 1s\n"
"    filetop -