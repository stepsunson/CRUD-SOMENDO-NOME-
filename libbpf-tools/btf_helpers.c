
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <zlib.h>

#include "trace_helpers.h"
#include "btf_helpers.h"

extern unsigned char _binary_min_core_btfs_tar_gz_start[] __attribute__((weak));
extern unsigned char _binary_min_core_btfs_tar_gz_end[] __attribute__((weak));

#define FIELD_LEN 65
#define ID_FMT "ID=%64s"
#define VERSION_FMT "VERSION_ID=\"%64s"

struct os_info {
	char id[FIELD_LEN];
	char version[FIELD_LEN];
	char arch[FIELD_LEN];
	char kernel_release[FIELD_LEN];
};

static struct os_info * get_os_info()
{
	struct os_info *info = NULL;
	struct utsname u;
	size_t len = 0;
	ssize_t read;
	char *line = NULL;
	FILE *f;

	if (uname(&u) == -1)
		return NULL;
