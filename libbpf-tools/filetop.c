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
"    filetop -p 1216    # only trace PID 1216\n"
"    filetop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "all", 'a', NULL, 0, "Include special files" },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, reads, writes, rbytes, wbytes]" },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, rows;
	static int pos_args;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'C':
		clear_screen = false;
		break;
	case 'a':
		regular_file_only = false;
		break;
	case 's':
		if (!strcmp(arg, "all")) {
			sort_by = ALL;
		} else if (!strcmp(arg, "reads")) {
			sort_by = READS;
		} else if (!strcmp(arg, "writes")) {
			sort_by = WRITES;
		} else if (!strcmp(arg, "rbytes")) {
			sort_by = RBYTES;
		} else if (!strcmp(arg, "wbytes")) {
			sort_by = WBYTES;
		} else {
			warn("invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		rows = strtol(arg, NULL, 10);
		if (errno || rows <= 0) {
			warn("invalid rows: %s\n", arg);
			argp_usage(state);
		}
		output_rows = rows;
		if (output_rows > OUTPUT_ROWS_LIMIT)
			output_rows = OUTPUT_ROWS_LIMIT;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0) {
				warn("invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno || count <= 0) {
				warn("invalid count\n");
				argp_usage(state);
			}
		} else {
	