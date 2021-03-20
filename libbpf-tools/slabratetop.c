/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * slabratetop Trace slab kmem_cache_alloc by process.
 * Copyright (c) 2022 Rong Tao
 *
 * Based on slabratetop(8) from BCC by Brendan Gregg.
 * 07-Jan-2022   Rong Tao   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "slabratetop.h"
#include "slabratetop.sk