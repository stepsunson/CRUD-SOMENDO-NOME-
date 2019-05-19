/*
 * dns_matching.c  Drop DNS packets requesting DNS name contained in hash map
 *    For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright (c) 2016 Rudi Floren.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 11-May-2016  Rudi Floren Created this.
 */

#