// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on biostacks(8) from BPF-Perf-Tools-Book by Brendan Gregg.
// 10-Aug-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "biostacks.h"
#include "biostacks.skel.h"
#include "trace_helpers.h"

static struct env {
	char *disk;
	int duration;
	bool milliseconds;
	bool verbose;
} env = {
	.duration = -1,
};

const char *argp_program_version = "biostacks 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Tracing block I/O with init stacks.\n"
"\n"
"USAGE: biostacks [--help] [-d DISK] [-m] [duration]\n"
"\n"
"EXAMPLES:\n"
"    biostacks              # trace block I/O with init stacks.\n"
"    biostacks 1            # trace for 1 seconds only\n"
"    biostacks -d sdc       # trace sdc only\n";

static const struct argp_option opts[] = {
	{ "disk",  'd', "DISK",  0, "Trace this disk only" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
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
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > DISK_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		break;
	case 'm':
		env.milliseconds = true;
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