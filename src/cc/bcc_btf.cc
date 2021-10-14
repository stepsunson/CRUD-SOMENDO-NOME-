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

#include "bcc_btf.h"
#include <stdarg.h>
#include <string.h>
#include "linux/btf.h"
#include "libbpf.h"
#include "bcc_libbpf_inc.h"
#include <vector>
#include <byteswap.h>

#define BCC_MAX_ERRNO       4095
#define BCC_IS_ERR_VALUE(x) ((x) >= (unsigned long)-BCC_MAX_ERRNO)
#define BCC_IS_ERR(ptr) BCC_IS_ERR_VALUE((unsigned long)ptr)
#ifndef offsetofend
# define offsetofend(TYPE, FIELD) \
	        (offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
#endif

namespace btf_ext_vendored {

/* The minimum bpf_func_info checked by the loader */
struct bpf_func_info_min {
        uint32_t   insn_off;
        uint32_t   type_id;
};

/* The minimum bpf_line_info checked by the loader */
struct bpf_line_info_min {
        uint32_t   insn_off;
        uint32_t   file_name_off;
        uint32_t   line_off;
        uint32_t   line_col;
};

struct btf_ext_sec_setup_param {
        uint32_t off;
        uint32_t len;
        uint32_t min_rec_size;
        struct btf_ext_info *ext_info;
        const char *desc;
};

static int btf_ext_setup_info(struct btf_ext *btf_ext,
                              struct btf_ext_sec_setup_param *ext_sec)
{
        const struct btf_ext_info_sec *sinfo;
        struct btf_ext_info *ext_info;
        uint32_t info_left, record_size;
        /* The start of the info sec (including the __u32 record_size). */
        void *info;

        if (ext_sec->len == 0)
                return 0;

        if (ext_sec->off & 0x03) {
                /*pr_debug(".BTF.ext %s section is not aligned to 4 bytes\n",
                     ext_sec->desc);*/
                return -EINVAL;
        }

        info = (uint8_t*)btf_ext->data + btf_ext->hdr->hdr_len + ext_sec->off;
        info_left = ext_sec->len;

        if ((uint8_t*)btf_ext->data + btf_ext->data_size < (uint8_t*)info + ext_sec->len) {
                /*pr_debug("%s section (off:%u len:%u) is beyond the end of the ELF section .BTF.ext\n",
                         ext_sec->desc, ext_sec->off, ext_sec->len);*/
                return -EINVAL;
        }

        /* At le