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

        /* At least a record size */
        if (info_left < sizeof(uint32_t)) {
                /*pr_debug(".BTF.ext %s record size not found\n", ext_sec->desc);*/
                return -EINVAL;
        }

        /* The record size needs to meet the minimum standard */
        record_size = *(uint32_t *)info;
        if (record_size < ext_sec->min_rec_size ||
            record_size & 0x03) {
                /*pr_debug("%s section in .BTF.ext has invalid record size %u\n",
                         ext_sec->desc, record_size);*/
                return -EINVAL;
        }

        sinfo = (struct btf_ext_info_sec*)((uint8_t*)info + sizeof(uint32_t));
        info_left -= sizeof(uint32_t);

        /* If no records, return failure now so .BTF.ext won't be used. */
        if (!info_left) {
                /*pr_debug("%s section in .BTF.ext has no records", ext_sec->desc);*/
                return -EINVAL;
        }

        while (info_left) {
                unsigned int sec_hdrlen = sizeof(struct btf_ext_info_sec);
                uint64_t total_record_size;
                uint32_t num_records;

                if (info_left < sec_hdrlen) {
                        /*pr_debug("%s section header is not found in .BTF.ext\n",
                             ext_sec->desc);*/
                        return -EINVAL;
                }

                num_records = sinfo->num_info;
                if (num_records == 0) {
                        /*pr_debug("%s section has incorrect num_records in .BTF.ext\n",
                             ext_sec->desc);*/
                        return -EINVAL;
                }

                total_record_size = sec_hdrlen +
                                    (uint64_t)num_records * record_size;
                if (info_left < total_record_size) {
                        /*pr_debug("%s section has incorrect num_records in .BTF.ext\n",
                             ext_sec->desc);*/
                        return -EINVAL;
                }

                info_left -= total_record_size;
                sinfo = (struct btf_ext_info_sec *)((uint8_t*)sinfo + total_record_size);
        }

        ext_info = ext_sec->ext_info;
        ext_info->len = ext_sec->len - sizeof(uint32_t);
        ext_info->rec_size = record_size;
        ext_info->info = (uint8_t*)info + sizeof(uint32_t);

        return 0;
}

static int btf_ext_setup_func_info(struct btf_ext *btf_ext)
{
        struct btf_ext_sec_setup_param param = {
                .off = btf_ext->hdr->func_info_off,
                .len = btf_ext->hdr->func_info_len,
                .min_rec_size = sizeof(struct bpf_func_info_min),
                .ext_info = &btf_ext->func_info,
                .desc = "func_info"
        };

        return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_setup_line_info(struct btf_ext *btf_ext)
{
        struct btf_ext_sec_setup_param param = {
                .off = btf_ext->hdr->line_info_off,
                .len = btf_ext->hdr->line_info_len,
                .min_rec_size = sizeof(struct bpf_line_info_min),
                .ext_info = &btf_ext->line_info,
                .desc = "line_info",
        };

        return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_setup_core_relos(struct btf_ext *btf_ext)
{
        struct btf_ext_sec_setup_param param = {
                .off = btf_ext->hdr->core_relo_off,
                .len = btf_ext->hdr->core_relo_len,
                .min_rec_size = sizeof(struct bpf_core_relo),
                .ext_info = &btf_ext->core_relo_info,
                .desc = "core_relo",
        };

        return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_parse_hdr(uint8_t *data, uint32_t data_size)
{
        const struct btf_ext_header *hdr = (struct btf_ext_header *)data;

        if (data_size < offsetofend(struct btf_ext_header, hdr_len) ||
            data_size < hdr->hdr_len) {
                //pr_debug("BTF.ext header not found");
                return -EINVAL;
        }

        if (hdr->magic == bswap_16(BTF_MAGIC)) {
                //pr_warn("BTF.ext in non-native endianness is not supported\n");
                return -ENOTSUP;
        } else if (hdr->magic != BTF_MAGIC) {
                //pr_debug("Invalid BTF.ext magic:%x\n", hdr->magic);
                return -EINVAL;
        }

        if (hdr->version != BTF_VERSION) {
                //pr_debug("Unsupported BTF.ext version:%u\n", hdr->version);
                return -ENOTSUP;
        }

        if (hdr->flags) {
                //pr_debug("Unsupported BTF.ext flags:%x\n", hdr->flags);
                return -ENOTSUP;
        }

        if (data_size == hdr->hdr_len) {
                //pr_debug("BTF.ext has no data\n");
                return -EINVAL;
        }

        return 0;
}

void btf_ext__free(struct btf_ext *btf_ext)
{
	if((!btf_ext) || BCC_IS_ERR_VALUE((unsigned long)btf_ext))
                return;
        free(btf_ext->data);
        free(btf_ext);
}

struct btf_ext *btf_ext__new(const uint8_t *data, uint32_t size)
{
        struct btf_ext *btf_ext;
        int err;

        btf_ext = (struct btf_ext*)calloc(1, sizeof(struct btf_ext));
        if (!btf_ext)
                return (struct btf_ext*)-ENOMEM;

        btf_ext->data_size = size;
        btf_ext->data = malloc(size);
        if (!btf_ext->data) {
                err = -ENOMEM;
                goto done;
        }
        memcpy(btf_ext->data, data, size);

        err = btf_ext_parse_hdr((uint8_t*)btf_ext->data, size);
        if (err)
                goto done;

        if (btf_ext->hdr->hdr_len < offsetofend(struct btf_ext_header, line_info_len)) {
                err = -EINVAL;
                goto done;
        }

        err = btf_ext_setup_func_info(btf_ext);
        if (err)
                goto done;

        err = btf_ext_setup_line_info(btf_ext);
        if (err)
                goto done;

        if (btf_ext->hdr->hdr_len < offsetofend(struct btf_ext_header, core_relo_len)) {
                err = -EINVAL;
                goto done;
        }

        err = btf_ext_setup_core_relos(btf_ext);
        if (err)
                goto done;

done:
        if (err) {
                btf_ext__free(btf_ext);
                return (struct btf_ext*)(uintptr_t)err;
        }

        return btf_ext;
}

static int btf_ext_reloc_info(const struct btf *btf,
                              const struct btf_ext_info *ext_info,
                              const char *sec_name, uint32_t insns_cnt,
                              void **info, uint32_t *cnt)
{
        uint32_t sec_hdrlen = sizeof(struct btf_ext_info_sec);
        uint32_t i, record_size, existing_len, records_len;
        struct btf_ext_info_sec *sinfo;
        const char *info_sec_name;
        uint64_t remain_len;
        void *data;

        record_size = ext_info->rec_size;
        sinfo = (struct btf_ext_info_sec*)ext_info->info;
        remain_len = ext_info->len;
        while (remain_len > 0) {
                records_len = sinfo->num_info * record_size;
                info_sec_name = btf__name_by_offset(btf, sinfo->sec_name_off);
                if (strcmp(info_sec_name, sec_name)) {
                        remain_len -= sec_hdrlen + records_len;
                        sinfo = (struct btf_ext_info_sec*)((uint8_t *)sinfo + sec_hdrlen + records_len);
                        continue;
                }

                existing_len = (*cnt) * record_size;
                data = realloc(*info, existing_len + records_len);
                if (!data)
                        return -ENOMEM;

                memcpy((uint8_t*)data + existing_len, sinfo->data, records_len);
                /* adjust insn_off only, the rest data will be passed
                 * to the kernel.
                 */
                for (i = 0; i < sinfo->num_info; i++) {
                        uint32_t *insn_off;

                        insn_off = (uint32_t *)((uint8_t*)data + existing_len + (i * record_size));
                        *insn_off = *insn_off / sizeof(struct bpf_insn) + insns_cnt;
                }
                *info = data;
                *cnt += sinfo->num_info;
                return 0;
        }

        return -ENOENT;
}

int btf_ext__reloc_func_info(const struct btf *btf,
                             const struct btf_ext *btf_ext,
                             const char *sec_name, uint32_t insns_cnt,
                         