--[[
Copyright 2016 GitHub, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]
local ffi = require("ffi")

ffi.cdef[[
enum bpf_prog_type {
  BPF_PROG_TYPE_UNSPEC,
  BPF_PROG_TYPE_SOCKET_FILTER,
  BPF_PROG_TYPE_KPROBE,
  BPF_PROG_TYPE_SCHED_CLS,
  BPF_PROG_TYPE_SCHED_ACT,
};

int bcc_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, int map_flags);
int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags);
int bpf_lookup_elem(int fd, void *key, void *value);
int bpf_delete_elem(int fd, void *key);
int bpf_get_next_key(int fd, void *key, void *next_key);

int bcc_prog_load(enum bpf_prog_type prog_type, const char *name,
  const struct bpf_insn *insns, int insn_len,
  const char *license, unsigned kern_version,
  int log_level, char *log_buf, unsigned log_buf_size);
int bpf_attach_socket(int sockfd, int progfd);

/* create RAW socket and bind to interface 'name' */
int bpf_open_raw_sock(const char *name);

typedef void (*perf_reader_raw_cb)(void *cb_cookie, void *raw, int raw_size);
typedef void (*perf_reader_lost_cb)(void *cb_cookie, uint64_t lost);

int bpf_attach_kprobe(int progfd, int attach_type, const char *ev_name,
                      const char *fn_name, uint64_t fn_offset, int maxactive);

int bpf_detach_kprobe(const char *ev_name);

int bpf_attach_uprobe(int progfd, int attach_type, const char *ev_name,
                      const char *binary_path, uint64_t offset, int pid);

int bpf_detach_uprobe(const char *ev_name);

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb, perf_reader_lost_cb lost_cb, void *cb_cookie, int pid, int cpu, int page_cnt);

int bpf_close_perf_event_fd(int fd);
]]

ffi.cdef[[
void * bpf_module_create_c(const char *filename, unsigned flags, const char *cflags[], int ncflags, bool allow_rlimit);
void * bpf_module_create_c_from_string(const char *text, unsigned flags, const char *cflags[], int ncflags, bool allow_rlimit);
voi