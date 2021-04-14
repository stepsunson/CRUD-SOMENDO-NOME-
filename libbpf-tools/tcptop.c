/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * tcptop Trace sending and received operation over IP.
 * Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
 *
 * Based on tcptop(8) from BCC by Brendan Gregg.
 * 03-Mar-2022   Francis Laniel   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcptop.h"
#include "tcptop.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

#define IPV4 0
#define PORT_LENGTH 5

enum SORT {
	ALL,
	SENT,
	RECEIVED,
};

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = -1;
static char *cgroup_path;
static bool cgroup_filtering = false;
static bool clear_screen = true;
static bool no_summary = false;
static bool ipv4_only = false;
static bool ipv6_only = false;
static int output_rows = 20;
static int sort_by = ALL;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "tcptop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace sending and received operation over IP.\n"
"\n"
"USAGE: tcptop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    tcptop            # TCP top, refresh every 1s\n"
"    tcptop -p 1216    # only trace PID 1216\n"
"    tcptop -c path    # only trace the given cgroup path\n"
"    tcptop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "ipv4", '4', NULL, 0, "trace IPv4 family only" },
	{ "ipv6", '6', NULL, 0, "trace IPv6 family only" },
	{ "nosummary", 'S', NULL, 0, "Skip system summary line"},
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, sent, received]" },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

struct info_t {
	struct ip_key_t key;
	struct traffic_t value;
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
	case 'c':
		cgroup_path = arg;
		cgroup_filtering = true;
		break;
	case 'C':
		clear_screen = false;
		break;
	case 'S':
		no_summary = true;
		break;
	case '4':
		ipv4_only = true;
		if (ipv6_only) {
			warn("Only one --ipvX option should be used\n");
			argp_usage(state);
		}
		break;
	case '6':
		ipv6_only = true;
		if (ipv4_only) {
			warn("Only one --ipvX option should be used\n");
			argp_usage(state);
		}
		break;
	case 's':
		if (!strcmp(arg, "all")) {
			sort_by = ALL;
		} else if (!strcmp(arg, "sent")) {
			sort_by = SENT;
		} else if (!strcmp(arg, "received")) {
			sort_by = RECEIVED;
		} else {
			warn("invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		rows = strtol(arg, NULL, 10);
		if (errno || rows <= 0) {
			warn("invalid rows: %s\n", arg);
			argp_usage(state);
		}
		output_rows = rows;
		if (output_rows > OUTPUT_ROWS_LIMIT)
			output_rows = OUTPUT_ROWS_LIMIT;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0) {
				warn("invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno || count <= 0) {
				warn("invalid count\n");
				argp_usage(state);
			}
		} else {
			warn("unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int sort_column(const void *obj1, const void *obj2)
{
	struct info_t *i1 = (struct info_t *)obj1;
	struct info_t *i2 = (struct info_t *)obj2;

	if (i1->key.family != i2->key.family)
		/*
		 * i1 - i2 because we want to sort by increasing order (first AF_INET then
		 * AF_INET6).
		 */
		return i1->key.family - i2->key.family;

	if (sort_by == SENT)
		return i2->value.sent - i1->value.sent;
	else if (sort_by == RECEIVED)
		return i2->value.received - i1->value.received;
	else
		return (i2->value.sent + i2->value.received) - (i1->value.sent + i1->value.received);
}

static int print_stat(struct tcptop_bpf *obj)
{
	FILE *f;
	time_t t;
	struct tm *tm;
	char ts[16], buf[256];
	struct ip_key_t key, *prev_key = NULL;
	static struct info_t infos[OUTPUT_ROWS_LIMIT];
	int n, i, err = 0;
	int fd = bpf_map__fd(obj->maps.ip_map);
	int rows = 0;
	bool ipv6_header_printed = false;

	if (!no_summary) {
		f = fopen("/proc/loadavg", "r");
		if (f) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			memset(buf, 0, sizeof(buf));
			n = fread(buf, 1, sizeof(buf), f);
			if (n)
				printf("%8s loadavg: %s\n", ts, buf);
			fclose(f);
		}
	}

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &infos[rows].key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_lookup_elem(fd, &infos[rows].key, &infos[rows].value);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &infos[rows].key;
		rows++;
	}

	printf("%-6s %-12s %-21s %-21s %6s %6s", "PID", "COMM", "LADDR", "RADDR",
				 "RX_KB", "TX_KB\n");

	qsort(infos, row