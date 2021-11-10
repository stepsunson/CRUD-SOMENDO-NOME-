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
  return B.CreateLoad(addr, isVolatile);
#endif
}

static Value *createInBoundsGEP(IRBuilder<> &B, Value *ptr, ArrayRef<Value *>idxlist)
{
#if LLVM_MAJOR_VERSION >= 15
  if (isa<GlobalValue>(ptr))
    return B.CreateInBoundsGEP(dyn_cast<GlobalValue>(ptr)->getValueType(), ptr, idxlist);
  else
    return B.CreateInBoundsGEP(ptr->getType(), ptr, idxlist);
#elif LLVM_MAJOR_VERSION >= 13
  return B.CreateInBoundsGEP(ptr->getType()->getScalarType()->getPointerElementType(),
                             ptr, idxlist);
#else
  return B.CreateInBoundsGEP(ptr, idxlist);
#endif
}

static void debug_printf(Module *mod, IRBuilder<> &B, const string &fmt, vector<Value *> args) {
  GlobalVariable *fmt_gvar = B.CreateGlobalString(fmt, "fmt");
  args.insert(args.begin(), createInBoundsGEP(B, fmt_gvar, vector<Value *>({B.getInt64(0), B.getInt64(0)})));
  args.insert(args.begin(), B.getInt64((uintptr_t)stderr));
  Function *fprintf_fn = mod->getFunction("fprintf");
  if (!fprintf_fn) {
    vector<Type *> fprintf_fn_args({B.getInt64Ty(), B.getInt8PtrTy()});
    FunctionType *fprintf_fn_type = FunctionType::get(B.getInt32Ty(), fprintf_fn_args, /*isvarArg=*/true);
    fprintf_fn = Function::Create(fprintf_fn_type, GlobalValue::ExternalLinkage, "fprintf", mod);
    fprintf_fn->setCallingConv(CallingConv::C);
    fprintf_fn->addFnAttr(Attribute::NoUnwind);
  }
  B.CreateCall(fprintf_fn, args);
}

static void finish_sscanf(IRBuilder<> &B, vector<Value *> *args, string *fmt,
                          const map<string, Value *> &locals, bool exact_args) {
  // fmt += "%n";
  // int nread = 0;
  // int n = sscanf(s, fmt, args..., &nread);
  // if (n < 0) return -1;
  // s = &s[nread];
  Value *sptr = locals.at("sptr");
  Value *nread = locals.at("nread");
  Function *cur_fn = B.GetInsertBlock()->getParent();
  Function *sscanf_fn = B.GetInsertBlock()->getModule()->getFunction("sscanf");
  *fmt += "%n";
  B.CreateStore(B.getInt32(0), nread);
  GlobalVariable *fmt_gvar = B.CreateGlobalString(*fmt, "fmt");
  (*args)[1] = createInBoundsGEP(B, fmt_gvar, {B.getInt64(0), B.getInt64(0)});
  (*args)[0] = createLoad(B, sptr);
  args->push_back(nread);
  CallInst *c