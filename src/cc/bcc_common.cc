
/*
 * Copyright (c) 2015 PLUMgrid, Inc.
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
#include "bcc_common.h"
#include "bpf_module.h"

extern "C" {
void * bpf_module_create_c(const char *filename, unsigned flags, const char *cflags[],
                           int ncflags, bool allow_rlimit, const char *dev_name) {
  auto mod = new ebpf::BPFModule(flags, nullptr, true, "", allow_rlimit, dev_name);
  if (mod->load_c(filename, cflags, ncflags) != 0) {
    delete mod;
    return nullptr;
  }
  return mod;
}

void * bpf_module_create_c_from_string(const char *text, unsigned flags, const char *cflags[],
                                       int ncflags, bool allow_rlimit, const char *dev_name) {
  auto mod = new ebpf::BPFModule(flags, nullptr, true, "", allow_rlimit, dev_name);
  if (mod->load_string(text, cflags, ncflags) != 0) {
    delete mod;
    return nullptr;
  }
  return mod;
}

bool bpf_module_rw_engine_enabled() {
  return ebpf::bpf_module_rw_engine_enabled();
}

void bpf_module_destroy(void *program) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return;
  delete mod;
}

size_t bpf_num_functions(void *program) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return 0;
  return mod->num_functions();
}

const char * bpf_function_name(void *program, size_t id) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return nullptr;
  return mod->function_name(id);
}

void * bpf_function_start(void *program, const char *name) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return nullptr;
  return mod->function_start(name);
}

void * bpf_function_start_id(void *program, size_t id) {