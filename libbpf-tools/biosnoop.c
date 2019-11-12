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
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace block I/O.\n"
"\n"
"USAGE: biosnoop [--help] [-d DISK] [-c CG] [-Q]\n"
"\n"
"EXAMPLES:\n"
"    biosnoop              # trace all block I/O\n"
"    biosnoop -Q           # include OS queued time in I/O time\n"
"    biosnoop 10           # trace for 10 seconds only\n"
"    biosnoop -d sdc       # trace sdc only\n"
"    biosnoop -c CG        # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time" },
	{ "disk",  'd', "DISK",  0, "Trace this disk only" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified/CG", 0, "Trace process in cgroup path"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'Q':
		env.queued = true;
		break;
	case 'c':
		env.cg = true;
		env.cgroupspath = arg;
		break;
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > DISK_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtoll(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void blk_fill_rwbs(char *rwbs, unsigned int op)
{
	int i = 0;

	if (op & REQ_PREFLUSH)
		rwbs[i++] = 'F';

	switch 