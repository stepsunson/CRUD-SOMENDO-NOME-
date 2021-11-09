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
#include <map>
#include <string>
#include <vector>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/TargetSelect.h>

#include "common.h"
#include "bpf_module.h"
#include "table_storage.h"

namespace ebpf {

using std::map;
using std::move;
using std::string;
using std::unique_ptr;
using std::vector;
using namespace llvm;

bool bpf_module_rw_engine_enabled(void) {
  return true;
}

void BPFModule::initialize_rw_engine() {
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
}

void BPFModule::cleanup_rw_engine() {
  rw_engine_.reset();
}

static LoadInst *createLoad(IRBuilder<> &B, Value *addr, bool isVolatile = false)
{
#if LLVM_MAJOR_VERSION >= 15
  if (isa<AllocaInst>(addr))
    return B.CreateLoad(dyn_cast<AllocaInst>(addr)->getAllocatedType(), addr, isVolatile);
  else
    return B.CreateLoad(addr->getType(), addr, isVolatile);
#elif LLVM_MAJOR_VERSION >= 13
  return B.CreateLoad(addr->getType()->getPointerElementType(), addr, isVolatile);
#else
  return B.CreateLoad(addr, isVolati