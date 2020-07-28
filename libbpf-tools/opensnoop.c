// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS	100

#define NSEC_PER_SEC		1000000000ULL

static volatile sig_atomic_t exiting = 0;

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

static struct env {
	pid_t pid;
	pid_t tid;
	uid_t uid;
	int duration;
	bool verbose;
	bool timestamp;
	bool print_uid;
	bool extended;
	bool failed;
	char *name;
#ifdef USE_BLAZESYM
	bool callers;
#endif
} env = {
	.uid = INVALID_UID
};

const char *argp_program_version = "opensnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace open family syscalls\n"
"\n"
"USAGE: opensnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID] [-u UID] [-d DURATION]\n"
#ifdef USE_BLAZESYM
"                 [-n NAME] [-e] [-c]\n"
#else
"                 [-n NAME] [-e]\n"
#endif
"\n"
"EXAMPLES:\n"
"    ./opensnoop           # trace all open() syscalls\n"
"    ./opensnoop -T        # include timestamps\n"
"    ./opensnoop -U        # include UID\n"
"    ./opensnoop -x        # only show failed opens\n"
"    ./opensnoop -p 181    # only trace PID 181\n"
"    ./opensnoop -t 123    # only trace TID 123\n"
"    ./opensnoop -u 1000   # only trace UID 1000\n"
"    ./opensnoop -d 10     # trace for 10 seconds only\n"
"    ./opensnoop -n main   # only print process names containing \"main\"\n"
"    ./opensnoop -e        # show extended fields\n"
#ifdef USE_BLAZESYM
"    ./opensnoop -c        # show calling functions\n"
#endif
"";

static const struct argp_option opts[] = {
	{ "du