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
  CallInst *call = B.CreateCall(sscanf_fn, *args);
  call->setTailCall(true);

  BasicBlock *label_true = BasicBlock::Create(B.getContext(), "", cur_fn);
  BasicBlock *label_false = BasicBlock::Create(B.getContext(), "", cur_fn);

  // exact_args means fail if don't consume exact number of "%" inputs
  // exact_args is disabled for string parsing (empty case)
  Value *cond = exact_args ? B.CreateICmpNE(call, B.getInt32(args->size() - 3))
                           : B.CreateICmpSLT(call, B.getInt32(0));
  B.CreateCondBr(cond, label_true, label_false);

  B.SetInsertPoint(label_true);
  B.CreateRet(B.getInt32(-1));

  B.SetInsertPoint(label_false);
  // s = &s[nread];
  B.CreateStore(
      createInBoundsGEP(B, createLoad(B, sptr), {createLoad(B, nread, true)}), sptr);

  args->resize(2);
  fmt->clear();
}

// recursive helper to capture the arguments
static void parse_type(IRBuilder<> &B, vector<Value *> *args, string *fmt,
                       Type *type, Value *out,
                       const map<string, Value *> &locals, bool is_writer) {
  if (StructType *st = dyn_cast<StructType>(type)) {
    *fmt += "{ ";
    unsigned idx = 0;
    for (auto field : st->elements()) {
      parse_type(B, args, fmt, field, B.CreateStructGEP(type, out, idx++),
                 locals, is_writer);
      *fmt += " ";
    }
    *fmt += "}";
  } else if (ArrayType *at = dyn_cast<ArrayType>(type)) {
    if (at->getElementType() == B.getInt8Ty()) {
      // treat i8[] as a char string instead of as an array of u8's
      if (is_writer) {
        *fmt += "\"%s\"";
        args->push_back(out);
      } else {
        // When reading strings, scanf doesn't support empty "", so we need to
        // break this up into multiple scanf calls. To understand it, let's take
        // an example:
        // struct Event {
        //   u32 a;
        //   struct {
        //     char x[64];
        //     int y;
        //   } b[2];
        //   u32 c;
        // };
        // The writer string would look like:
        //  "{ 0x%x [ { \"%s\" 0x%x } { \"%s\" 0x%x } ] 0x%x }"
        // But the reader string needs to restart at each \"\".
        //  reader0(const char *s, struct Event *val) {
        //    int nread, rc;
        //    nread = 0;
        //    rc = sscanf(s, "{ %i [ { \"%n", &val->a, &nread);
        //    if (rc != 1) return -1;
        //    s += nread; nread = 0;
        //    rc = sscanf(s, "%[^\"]%n", &val->b[0].x, &nread);
        //    if (rc < 0) return -1;
        //    s += nread; nread = 0;
        //    rc = sscanf(s, "\" %i } { \"%n", &val->b[0].y, &nread);
        //    if (rc != 1) return -1;
        //    s += nread; nread = 0;
        //    rc = sscanf(s, "%[^\"]%n", &val->b[1].x, &nread);
        //    if (rc < 0) return -1;
        //    s += nread; nread = 0;
        //    rc = sscanf(s, "\" %i } ] %i }%n", &val->b[1].y, &val->c, &nread);
        //    if (rc != 2) return -1;
        //    s += nread; nread = 0;
        //    return 0;
        //  }
        *fmt += "\"";
        finish_sscanf(B, args, fmt, locals, true);

        *fmt = "%[^\"]";
        args->push_back(out);
        finish_sscanf(B, args, fmt, locals, false);

        *fmt = "\"";
      }
    } else {
      *fmt += "[ ";
      for (size_t i = 0; i < at->getNumElements(); ++i) {
        parse_type(B, args, fmt, at->getElementType(),
                   B.CreateStructGEP(type, out, i), locals, is_writer);
        *fmt += " ";
      }
      *fmt += "]";
    }
  } else if (isa<PointerType>(type)) {
    *fmt += "0xl";
    if (is_writer)
      *fmt += "x";
    else
      *fmt += "i";
  } else if (IntegerType *it = dyn_cast<IntegerType>(type)) {
    if (is_writer)
      *fmt += "0x";
    if (it->getBitWidth() <= 8)
      *fmt += "%hh";
    else if (it->getBitWidth() <= 16)
      *fmt += "%h";
    else if (it->getBitWidth() <= 32)
      *fmt += "%";
    else
      *fmt += "%l";
    if (is_writer)
      *fmt += "x";
    else
      *fmt += "i";
    args->push_back(is_writer ? createLoad(B, out) : out);
  }
}

// make_reader generates a dynamic function in the instruction set of the host
// (not bpf) that is able to convert c-strings in the pretty-print format of
// make_writer back into binary representatio