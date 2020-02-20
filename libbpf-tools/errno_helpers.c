// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

#ifdef __x86_64__
static int errno_by_name_x86_64(const char *errno_name)
{

#define strcase(X, N) if (!strcmp(errno_name, (X))) return N

	strcase("EPERM", 1);
	strcase("ENOENT", 2);
	strcase("ESRCH", 3);
	strcase("EINTR", 4);
	strcase("EIO", 5);
	strcase("ENXIO", 6);
	strcase("E2BIG", 7);
	strcase("ENOEXEC", 8);
	strcase("EBADF", 9);
	strcase("ECHILD", 10);
	strcase("EAGAIN", 11);
	strcase("EWOULDBLOCK", 11);
	strcase("ENOMEM", 12);
	strcase("EACCES", 13);
	strcase("EFAULT", 14);
	strcase("ENOTBLK", 15);
	strcase("EBUSY", 16);
	strcase("EEXIST", 17);
	strcase("EXDEV", 18);
	strcase("ENODEV", 19);
	strcase("ENOTDIR", 20);
	strcase("EISDIR", 21);
	strcase("EINVAL", 22);
	strcase("ENFILE", 23);
	strcase("EMFILE", 24);
	strcase("ENOTTY", 25);
	strcase("ETXTBSY", 26);
	strcase("EFBIG", 27);
	strcase("ENOSPC", 28);
	strcase("ESPIPE", 29);
	strcase("EROFS", 30);
	strcase("EMLINK", 31);
	strcase("EPIPE", 32);
	strcase("EDOM", 33);
	strcase("ERANGE", 34);
	strcase("EDEADLK", 35);
	strcase("EDEADLOCK", 35);
	strcase("ENAMETOOLONG", 36);
	strcase("ENOLCK", 37);
	strcase("ENOSYS", 38);
	strcase("ENOTEMPTY", 39);
	strcase("ELOOP", 40);
	strcase("ENOMSG", 42);
	strcase("EIDRM", 43);
	strcase("ECHRNG", 44);
	strcase("EL2NSYNC", 45);
	strcase("EL3HLT", 46);
	strcase("EL3RST", 47);
	strcase("ELNRNG", 48);
	strcase("EUNATCH", 49);
	strcase("ENOCSI", 50);
	strcase("EL2HLT", 51);
	strcase("EBADE", 52);
	strcase("EBADR", 53);
	strcase("EXFULL", 54);
	strcase("ENOANO", 55);
	strcase("EBADRQC", 56);
	strcase("EBADSLT", 57);
	strcase("EBFONT", 59);
	strcase("ENOSTR", 60);
	strcase("ENODATA", 61);
	strcase("ETIME", 62);
	strcase("ENOSR", 63);
	st