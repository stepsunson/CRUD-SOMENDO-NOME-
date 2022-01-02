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
};

class SymbolCache {
public:
  virtual ~SymbolCache() = default;

  virtual void refresh() = 0;
  virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym, bool demangle = true) = 0;
  virtual bool resolve_name(const char *module, const char *name,
                            uint64_t *addr) = 0;
};

class KSyms : SymbolCache {
  struct Symbol {
    Symbol(const char *name, const char *mod, uint64_t addr) : name(name), mod(mod), addr(addr) {}
    std::string name;
    std::string mod;
    uint64_t addr;

    bool operator<(const Symbol &rhs) const { return addr < rhs.addr; }
  };

  std::vector<Symbol> syms_;
  std::unordered_map<std::string, uint64_t> symnames_;
  static void _add_symbol(const char *, const char *, uint64_t, void *);

public:
  virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym, bool demangle = true) override;
  virtual bool resolve_name(const char *unused, const char *name,
                            uint64_t *addr) override;
  virtual void refresh() override;
};

class ProcSyms : SymbolCache {
  struct NameIdx {
    size_t section_idx;
    size_t str_table_idx;
    size_t str_len;
    bool debugfile;
  };

  struct Symbol {
    Symbol(const std::string *name, uint64_t start, uint64_t size)
        : is_name_resolved(true), start(start), size(size) {
      data.name = name;
    }
    Symbol(size_t section_idx, size_t str_table_idx, size_t str_len, uint64_t start,
           uint64_t size, bool debugfile)
        : is_name_resolved(false), start(start), size(size) {
      data.name_idx.section_idx = section_idx;
      data.name_idx.str_table_idx = str_table_idx;
      data.name_idx.str_len = str_len;
      data.name_idx.debugfile = debugfile;
    }
    bool is_name_resolved;
    union {
      struct NameIdx name_idx;
      const std::string *name{nullptr};
    } data;
    uint64_t start;
    uint64_t size;

    bool operator<(const struct Symbol& rhs) const {
      return start < rhs.start;
    }
  };

  enum class ModuleType {
    UNKNOWN,
    EXEC,
    SO,
    PERF_MAP,
    VDSO
  };

  class ModulePath {
    // helper class to get a usable module path in