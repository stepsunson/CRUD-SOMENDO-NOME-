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
	strcase("ENONET", 64);
	strcase("ENOPKG", 65);
	strcase("EREMOTE", 66);
	strcase("ENOLINK", 67);
	strcase("EADV", 68);
	strcase("ESRMNT", 69);
	strcase("ECOMM", 70);
	strcase("EPROTO", 71);
	strcase("EMULTIHOP", 72);
	strcase("EDOTDOT", 73);
	strcase("EBADMSG", 74);
	strcase("EOVERFLOW", 75);
	strcase("ENOTUNIQ", 76);
	strcase("EBADFD", 77);
	strcase("EREMCHG", 78);
	strcase("ELIBACC", 79);
	strcase("ELIBBAD", 80);
	strcase("ELIBSCN", 81);
	strcase("ELIBMAX", 82);
	strcase("ELIBEXEC", 83);
	strcase("EILSEQ", 84);
	strcase("ERESTART", 85);
	strcase("ESTRPIPE", 86);
	strcase("EUSERS", 87);
	strcase("ENOTSOCK", 88);
	strcase("EDESTADDRREQ", 89);
	strcase("EMSGSIZE", 90);
	strcase("EPROTOTYPE", 91);
	strcase("ENOPROTOOPT", 92);
	strcase("EPROTONOSUPPORT", 93);
	strcase("ESOCKTNOSUPPORT", 94);
	strcase("ENOTSUP", 95);
	strcase("EOPNOTSUPP", 95);
	strcase("EPFNOSUPPORT", 96);
	strcase("EAFNOSUPPORT", 97);
	strcase("EADDRINUSE", 98);
	strcase("EADDRNOTAVAIL", 99);
	strcase("ENETDOWN", 100);
	strcase("ENETUNREACH", 101);
	strcase("ENETRESET", 102);
	strcase("ECONNABORTED", 103);
	strcase("ECONNRESET", 104);
	strcase("ENOBUFS", 105);
	strcase("EISCONN", 106);
	strcase("ENOTCONN", 107);
	strcase("ESHUTDOWN", 108);
	strcase("ETOOMANYREFS", 109);
	strcase("ETIMEDOUT", 110);
	strcase("ECONNREFUSED", 111);
	strcase("EHOSTDOWN", 112);
	strcase("EHOSTUNREACH", 113);
	strcase("EALREADY", 114);
	strcase("EINPROGRESS", 115);
	strcase("ESTALE", 116);
	strcase("EUCLEAN", 117);
	strcase("ENOTNAM", 118);
	strcase("ENAVAIL", 119);
	strcase("EISNAM", 120);
	strcase("EREMOTEIO", 121);
	strcase("EDQUOT", 122);
	strcase("ENOMEDIUM", 123);
	strcase("EMEDIUMTYPE", 124);
	strcase("ECANCELED", 125);
	strcase("ENOKEY", 126);
	strcase("EKEYEXPIRED", 127);
	strcase("EKEYREVOKED", 128);
	strcase("EKEYREJECTED", 129);
	strcase("EOWNERDEAD", 130);
	strcase("ENOTRECOVERABLE", 131);
	strcase("ERFKILL", 132);
	strcase("EHWPOISON", 133);

#undef strcase

	return -1;

}
#endif

/* Try to find the errno number using the errno(1) program */
static int errno_by_name_dynamic(const char *errno_name)
{
	int i, len = strlen(errno_name);
	int err, number = -1;
	char buf[128];