/*
 * Copyright (c) 2019 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BCC_BTF_H
#define BCC_BTF_H

#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <map>
#include <vector>

#include "bpf_module.h"

struct btf;
struct btf_type;

namespace btf_ext_vendored {

/*
 * The .BTF.ext ELF section layout defined as
 *   struct btf_ext_header
 *   func_info subsection
 *
 * The func_info subsection layout:
 *   record size for struct bpf_func_info in the func_info subsection
 *   struct btf_sec_func_info for section #1
 *   a list of bpf_func_info records for section #1
 *     where struct bpf_func_info mimics one in include/uapi/linux/bpf.h
 *     but may not be identical
 *   struct btf_sec_func_info for section #2
 *   a list of bpf_func_info records for section #2
 *   ......
 *
 * Note that the bpf_func_info record size in .BTF.ext may not
 * be the same as the one defined in include/uapi/linux/bpf.h.
 * The loader should ensure that record_size meets minimum
 * requirement and pass the record as is to the kernel. The
 * kernel will handle the func_info properly based on its contents.
 */
struct btf_ext_header {
        uint16_t magic;
        uint8_t version;
        uint8_t flags;
        uint32_t hdr_len;

        /* All offsets are in bytes relative to the end of this header */
        uint32_t func_info_off;
        uint32_t func_info_len;
        uint32_t line_info_off;
        uint32_t line_info_len;

        /* optional part of .BTF.ext header */
        uint32_t core_relo_off;
        uint32_t core_relo_len;
};

struct btf_ext_info {
        /*
         * info points to the individual info section (e.g. func_info and
         * line_info) from the .BTF.ext. It does not include the __u32 rec_size.
         */
        void *info;
        uint32_t rec_size;
        uint32_t len;
};

struct btf_ext {
        union {
                struct btf_ext_header *hdr;
                void *data;
        };
        struct btf_ext_info func_info;
        struct btf_ext_info line_info;
        struct btf_ext_info core_relo_info;
        uint32_t data_size;
};

struct btf_ext_info_sec {
        uint32_t   sec_name_off;
        uint32_t   num_info;
        /* Followed by num_info * record_size number of bytes */
        uint8_t    data[];
};

struct btf_ext *btf_ext__new(const uint8_t *data, uint32_t size);
void btf_ext__free(struct btf_ext *btf_ext);
int btf_ext__reloc_func_info(const struct btf *btf,
                         