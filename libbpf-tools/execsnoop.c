// Based on execsnoop(8) from BCC by Brendan Gregg and others.
//
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES   64
#define PERF_POLL_TIMEOUT_MS	100
#define MAX_ARGS_KEY 259

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char *name;
	const char *line;
	bool print_uid;
	bool verbose;
	int max_args;
	char *cgroupspath;
	bool cg;
} env = {
	.max_args = DEFAULT_MAXARGS,
	.uid = INVALID_UID
};

static struct timespec start_time;

const char *argp_program_version = "execsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace exec syscalls\n"
"\n"
"USAGE: execsnoop [-h] [-T] [-t] [-x] [-u UID] [-q] [-n NAME] [-l LINE] [-U] [-c CG]\n"
"                 [--max-args MAX_ARGS]\n"
"\n"
"EXAMPLES:\n"
"   ./execsnoop           # trace all exec() syscalls\n"
"   ./execsnoop -x        # include failed exec()s\n"
"   ./execsnoop -T        # include time (HH:MM:SS)\n"
"