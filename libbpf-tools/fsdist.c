/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * fsdist  Summarize file system operations latency.
 *
 * Copyright (c) 2021 Wenbo Zhang
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on ext4dist(8) from BCC by Brendan Gregg.
 * 9-Feb-2021   Wenbo Zhang   Created this.
 * 20-May-2021   Hengqi Chen  Migrated to fsdist.
 */
#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <s