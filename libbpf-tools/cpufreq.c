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
	{ NULL, 'h