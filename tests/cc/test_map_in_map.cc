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

#include <linux/version.h>
#include <unistd.h>
#include <string>

#include "BPF.h"
#include "catch.hpp"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)

TEST_CASE("test hash of maps", "[hash_of_maps]") {
  {
    const std::string BPF_PROGRAM = R"(
      BPF_ARRAY(cntl, int, 1);
      BPF_ARRAY(ex1, int, 1024);
      BPF_ARRAY(ex2, int, 1024);
      BPF_ARRAY(ex3, u64, 1024);
      BPF_HASH_OF_MAPS(maps_hash, int, "ex1", 10);

      int syscall__getuid(void *ctx) {
         int key = 0, data, *val, cntl_val;
         void *inner_map;

         val = cntl.lookup(&key);
         if (!val || *val == 0)
           return 0;

         // cntl_val == 1 : lookup and update
         cntl_val = *val;
         inner_map = maps_hash.lookup(&key);
         if (!inner_map)
           return 0;

         if (cntl_val == 1) {
           val = bpf_map_lookup_elem(inner_map, &key);
           if (val) {
             data = 1;
             bpf_map_update_elem(inner_map, &key, &data, 0);
           }
         }

         return 0;
      }
    )";

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.ok(