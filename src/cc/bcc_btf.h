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
 *   func_i