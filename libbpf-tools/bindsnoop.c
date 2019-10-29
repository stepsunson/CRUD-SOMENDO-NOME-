/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on bindsnoop(8) from BCC by Pavel Dubovitsky.
 * 11-May-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bindsnoop.h"
#include "bindsnoop.skel.h"
#include "trace_helpers.h"
#include "btf_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct env {
	char	*cgroupspath;
	bool	cg;
} env;

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static pid_t target_pid = 0;
static bool ignore_errors = true;
static char *target_ports = NULL;
static bool verbose = false;

const char *argp_program_version = "bindsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace bind syscalls.\n"
"\n"
"USAGE: bindsnoop [-h] [-t] [-x] [-p PID] [-P ports] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    bindsnoop             # trace all bind syscall\n"
"    bindsnoop -t          # include timestamps\n"
"    bindsnoop -x          # include errors on output\n"
"    bindsnoop -p 1216     # only trace PID 1216\n"
"    bindsnoop -c CG       # Trace process under cgroupsPath CG\n"
"    bindsnoop -P 80,81    # only trace port 80 and 81\n"
"\n"
"Socket options are reported as:\n"
"  SOL_IP     IP_FREEBIND              F....\n"
"  SOL_IP     IP_TRANSPARENT           .T...\n"
"  SOL_IP     IP_BIND_ADDRESS_NO_PORT  ..N..\n"
"  SOL_SOCKET SO_REUSEADDR             ...R.\n"
"  SOL_SOCKET SO_REUSEPORT             ....r\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "failed", 'x', NULL, 0, "Include errors on output." },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "ports", 'P', "PORTS", 0, "Comma-separated list of ports to trace." },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, port_num;
	char *port;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'P':
		if (!arg) {
			warn("No ports specifi