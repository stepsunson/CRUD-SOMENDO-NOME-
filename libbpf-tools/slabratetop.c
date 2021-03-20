/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * slabratetop Trace slab kmem_cache_alloc by process.
 * Copyright (c) 2022 Rong Tao
 *
 * Based on slabratetop(8) from BCC by Brendan Gregg.
 * 07-Jan-2022   Rong Tao   Created this.
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
#include "slabratetop.h"
#include "slabratetop.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

enum SORT_BY {
	SORT_BY_CACHE_NAME,
	SORT_BY_CACHE_COUNT,
	SORT_BY_CACHE_SIZE,
};

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool clear_screen = true;
static int output_rows = 20;
static int sort_by = SORT_BY_CACHE_SIZE;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "slabratetop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace slab kmem cache alloc by process.\n"
"\n"
"USAGE: slabratetop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    slabratetop            # slab rate top, refresh every 1s\n"
"    slabratetop -p 181     # only trace PID 181\n"
"    slabratetop -s count   # sort columns by count\n"
"    slabratetop -r 100     # print 100 rows\n"
"    slabratetop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "sort", 's', "SORT", 0, "Sort columns, default size [name, count, size]" },
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
	case 's':
		if (!strcmp(arg, "name")) {
			sort_by = SORT_BY_CACHE_NAME;
		} else if (!strcmp(arg, "count")) {
			sort_by = SORT_BY_CACHE_COUNT;
		} else if (!strcmp(arg, "size")) {
			sort_by = SORT_BY_CACHE_SIZE;
		} else {
			warn("invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	c