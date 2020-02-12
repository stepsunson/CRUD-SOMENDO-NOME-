// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on cpufreq(8) from BPF-Perf-Tools-Book by Brendan Gregg.
// 10-OCT-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cpufreq.h"
#include "cpufreq.skel.h"
#include "trace_helpers.h"

static struct env {
	int duration;
	int freq;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.duration = -1,
	.freq = 99,
};

const char *argp_program_version = "cpufreq 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Sampling CPU freq system-wide & by process. Ctrl-C to end.\n"
"\n"
"USAGE: cpufreq [--help] [-d DURATION] [-f FREQUENCY] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    cpufreq         # sample CPU freq at 99HZ (default)\n"
"    cpufreq -d 5    # sample for 5 seconds only\n"
"    cpufreq -c CG   # Trace process under cgroupsPath CG\n"
"    cpufreq -f 199  # sample CPU freq at 199HZ\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to sample in seconds" },
	{ "frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'f':
		errno = 0;
		env.freq = strtol(arg, NULL, 10);
		if (errno || env.freq <= 0) {
			fprintf(stderr, "Invalid freq (in HZ): %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
			close(fd);
			return -1;
		}
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
}

static int init_freqs_mhz(__u32 *freqs_mhz, int nr_cpus)
{
	char path[64];
	FILE *f;
	int i;

	for (i = 0; i < nr_cpus; i++) {
		snprintf(path, sizeof(path),
			"/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq",
			i);

		f = fopen(path, "r");
		if (!f) {
			fprintf(stderr, "failed to open '%s': %s\n", path,
				strerror(errno));
			return -1;