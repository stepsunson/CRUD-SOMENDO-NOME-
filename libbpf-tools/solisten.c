/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * solisten  Trace IPv4 and IPv6 listen syscalls
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on solisten(8) from BCC by Jean-Tiare Le Bigot
 * 31-May-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "solisten.h"
#include "solisten.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "solisten 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace IPv4 and IPv6 listen syscalls.\n"
"\n"
"USAGE: solisten [-h] [-t] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    solisten           # trace listen syscalls\n"
"    solisten -t        # output with timestamp\n"
"    solisten -p 1216   # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "timestamp",