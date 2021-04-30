// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Google LLC. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <gelf.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

/*
 * Returns 0 on success; -1 on failure.  On sucess, returns via `path` the full
 * path to the program for pid.
 */
int get_pid_binary_path(pid_t pid, char *path, size_t path_sz)
{
	ssize_t ret;
	char proc_pid_exe[32];

	if (snprintf(proc_pid_exe, sizeof(proc_pid_exe), "/proc/%d/exe", pid)
	    >= sizeof(proc_pid_exe)) {
		warn("snprintf /proc/PID/exe failed");
		return -1;
	}
	ret = readlink(proc_pid_exe, path, path_sz);
	if (ret < 0) {
		warn("No such pid %d\n", pid);
		return -1;
	}
	if (ret >= path_sz) {
		warn("readlink truncation");
		return -1;
	}
	path[ret] = '\0';

	return 0;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to a library matching the name `lib` that is loaded into pid's address
 * space.
 */
int get_pid_lib_path(pid_t pid, const char *lib, char *path, size_t path_sz)
{
	FILE *maps;
	char *p;
	char proc_pid_maps[32];
	char line_buf[1024];
	char path_buf[1024];

	if (snprintf(proc_pid_maps, sizeof(proc_pid_maps), "/proc/%d/maps", pid)
	    >= sizeof(proc_pid_maps)) {
		warn("snprintf /proc/PID/maps failed");
		return -1;
	}
	maps = fopen(proc_pid_maps, "r");
	if (!maps) {
		warn("No such pid %d\n", pid);
		return -1;
	}
	while (fgets(line_buf, sizeof(line_buf), maps)) {
		if (sscanf(line_buf, "%*x-%*x %*s %*x %*s %*u %s", path_buf) != 1)
			continue;
		/* e.g. /usr/lib/x86_64-linux-gnu/libc-2.31.so */
		p = strrchr(path_buf, '/');
		if (!p)
			continue;
		if (strncmp(p, "/lib", 4))
			continue;
		p += 4;
		if (strncmp(lib, p, strlen(lib)))
			continue;
		p += strlen(lib);
		/* libraries can have - or . after the name */
		if (*p != '.' && *p != '-')
			continue;
		if (strnlen(path_buf, 1024) >= path_sz) {
			warn("path size too small\n");
			return -1;
		}
		strcpy(path, path_buf);
		fclose(maps);
		return 0;
	}

	warn("Cannot find library %s\n", lib);
	fclose(maps);
	return -1;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to the program.
 */
static int which_program(const char *prog, char *path, size_t path_sz)
{
	FILE *which;
	char cmd[100];

	if (snprintf(cmd, sizeof(cmd), "which %s", prog) >= sizeof(cmd)) {
		warn("snprintf which prog failed");
		return -1;
	}
	which = popen(cmd, "r");
	if (!which) {
		warn("which failed");
		return -1;
	}
	if (!fgets(path, path_sz, which)) {
		warn("fgets which failed");
		pclose(which);
		return -1;
	}
	/* which has a \n at the end of the string */
	path[strlen(path) - 1] = '\0';
	pclose(which);
	return 0;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to the binary for the given pid.
 * 1) pid == x, binary == ""    : returns the path to x's program
 * 2) pid == x, binary == "foo" : returns the path to libfoo linked in x
 * 3) pid == 0, binary == ""    : failure: need a pid or a binary
 * 4) pid == 0, binary == "bar" : returns the path to `which bar`
 *
 * For case 4), ideally we'd like to search for libbar too, but we don't support
 * that yet.
 */
int resolve_binary_path(const char *binary, pid_t pid, char *path, size_t path_sz)
{
	if (!strcmp(binary, "")) {
		if (!pid) {
			warn("Uprobes need a pid or a binary\n");
			return -1;
		}
		return get_pid_binary_path(pid, path, path_sz);
	}
	if (pid)
		return get_pid_lib_path(pid, binary, path, path_sz);

	if (which_program(binary, path, path_sz)) {
		/*
		 * If the user is tracing a program by name, we can find it.
		 * But we can't find a library by name yet.  We'd nee