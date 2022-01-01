/*
 * Copyright (c) 2016 GitHub, Inc.
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
#pragma once

#include <algorithm>
#include <memory>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "bcc_proc.h"
#include "bcc_syms.h"
#include "file_desc.h"

class ProcStat {
  std::string procfs_;
  std::string root_symlink_;
  std::string mount_ns_symlink_;
  // file descriptor of /proc/<pid>/root open with O_PATH used to get into root
  // of process after it exits; unlike a dereferenced root symlink, *at calls
  // to this use the process's mount namespace
  int root_fd_ = -1;
  // store also root path and mount namespace pair to detect its changes
  std::string root_, mount_ns_;
  ino_t inode_;
  bool getinode_(ino_t &inode);

 public:
  ProcStat(int pid);
  ~ProcStat() {
    if (root_fd_ > 0)
      close(root_fd_);
  }
  bool refresh_root();
  int get_root_fd() { return root_fd_; }
  bool is_stale();
  void reset() { getinode_(inode_); }