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
#include <linux/bpf.h>
#include <linux/version.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <stdlib.h>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/MultiplexConsumer.h>
#include <clang/Rewrite/Core/Rewriter.h>
#include <clang/Lex/Lexer.h>

#include "frontend_action_common.h"
#include "b_frontend_action.h"
#include "bpf_module.h"
#include "common.h"
#include "loader.h"
#include "table_storage.h"
#include "arch_helper.h"
#include "bcc_libbpf_inc.h"

#include "libbpf.h"
#include "bcc_syms.h"

namespace ebpf {

constexpr int MAX_CALLING_CONV_REGS = 6;
const char *calling_conv_regs_x86[] = {
  "di", "si", "dx", "cx", "r8", "r9"
};
const char *calling_conv_syscall_regs_x86[] = {
  "di", "si", "dx", "r10", "r8", "r9"
};
const char *calling_conv_regs_ppc[] = {"gpr[3]", "gpr[4]", "gpr[5]",
                                       "gpr[6]", "gpr[7]", "gpr[8]"};

const char *calling_conv_regs_s390x[] = { "gprs[2]", "gprs[3]", "gprs[4]",
					 "gprs[5]", "gprs[6]" };
const char *calling_conv_syscall_regs_s390x[] = { "orig_gpr2", "gprs[3]", "gprs[4]",
					 "gprs[5]", "gprs[6]" };

const char *calling_conv_regs_arm64[] = {"regs[0]", "regs[1]", "regs[2]",
                                       "regs[3]", "regs[4]", "regs[5]"};
const char *calling_conv_syscall_regs_arm64[] = {"orig_x0", "regs[1]", "regs[2]",
                                       "regs[3]", "regs[4]", "regs[5]"};

const char *calling_conv_regs_mips[] = {"regs[4]", "regs[5]", "regs[6]",
                                       "regs[7]", "regs[8]", "regs[9]"};

const char *calling_conv_regs_riscv64[] = {"a0", "a1", "a2",
                                       "a3", "a4", "a5"};

const char *calling_conv_regs_loongarch[] = {"regs[4]", "regs[5]", "regs[6]",
					     "regs[7]", "regs[8]", "regs[9]"};


void *get_call_conv_cb(bcc_arch_t arch, bool for_syscall)
{
  const char **ret;

  switch(arch) {
    case BCC_ARCH_PPC:
    case BCC_ARCH_PPC_LE:
      ret = calling_conv_regs_ppc;
      break;
    case BCC_ARCH_S390X:
      ret = calling_conv_regs_s390x;
      if (for_syscall)
        ret = calling_conv_syscall_regs_s390x;
      break;
    case BCC_ARCH_ARM64:
      ret = calling_conv_regs_arm64;
      if (for_syscall)
        ret = calling_conv_syscall_regs_arm64;
      break;
    case BCC_ARCH_MIPS:
      ret = calling_conv_regs_mips;
      break;
    case BCC_ARCH_RISCV64:
      ret = calling_conv_regs_riscv64;
      break;
    case BCC_ARCH_LOONGARCH:
      ret = calling_conv_regs_loongarch;
      break;
    default:
      if (for_syscall)
        ret = calling_conv_syscall_regs_x86;
      else
        ret = calling_conv_regs_x86;
  }

  return (void *)ret;
}

const char **get_call_conv(bool for_syscall = false) {
  const char **ret;

  ret = (const char **)run_arch_callback(get_call_conv_cb, for_syscall);
  return ret;
}

const char *pt_regs_syscall_regs(void) {
  const char **calling_conv_regs;
  // Equivalent of PT_REGS_SYSCALL_REGS(ctx) ((struct pt_regs *)PT_REGS_PARM1(ctx))
  calling_conv_regs = (const char **)run_arch_callback(get_call_conv_cb, false);
  return calling_conv_regs[0];
}

/* Use resolver only once per translation */
static void *kresolver = NULL;
static void *get_symbol_resolver(void) {
  if (!kresolver)
    kresolver = bcc_symcache_new(-1, nullptr);
  retu