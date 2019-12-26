// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on cpudist(8) from BCC by Brendan Gregg & Dina Goldshtein.
// 8-May-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cpudist.h"
#include "cpudist.skel.h"
#include "trace_helpers.h"

static struct env {
	time_t interval;
	pid_t pid;
	char *cgroupspath;
	bool cg;
	int times;
	bool offcpu;
	bool timestamp;
	bool per_process;
	bool per_thread;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 99999999,
	.pid = -1,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "cpudist 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize on-CPU time per task as a histogram.\n"
"\n"
"USAGE: cpudist [--help] [-O] [-T] [-m] [-P] [-L] [-p PID] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    cpudist              # summarize on-CPU time as a histogram"
"    cpudist -O           # summarize off-CPU time as a histogram"
"    cpudist -c CG        # Trace process under cgroupsPath CG\n"
"    cpudist 1 10         # print 1 second summaries, 10 times"
"    cpudist -mT 1        # 1s summaries, milliseconds, and timestamps"
"    cpudist -P           # show each PID separately"
"    cpudist -p 185       # trace PID 185 only";

static const struct argp_option opts[] = {
	{ "offcpu", 'O', NULL, 0, "Measure off-CPU time" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "pids", 'P', NULL, 0, "Print a histogram per process ID" },
	{ "tids", 'L', NULL, 0, "Print a histogram per thread ID" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
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
	case 'm':
		env.milliseconds = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'p':
