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
  return kresolver;
}

static std::string check_bpf_probe_read_kernel(void) {
  bool is_probe_read_kernel;
  void *resolver = get_symbol_resolver();
  uint64_t addr = 0;
  is_probe_read_kernel = bcc_symcache_resolve_name(resolver, nullptr,
                          "bpf_probe_read_kernel", &addr) >= 0 ? true: false;

  /* If bpf_probe_read is not found (ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) is
   * not set in newer kernel, then bcc would anyway fail */
  if (is_probe_read_kernel)
    return "bpf_probe_read_kernel";
  else
    return "bpf_probe_read";
}

static std::string check_bpf_probe_read_user(llvm::StringRef probe,
        bool& overlap_addr) {
  if (probe.str() == "bpf_probe_read_user" ||
      probe.str() == "bpf_probe_read_user_str") {
    // Check for probe_user symbols in backported kernel before fallback
    void *resolver = get_symbol_resolver();
    uint64_t addr = 0;
    bool found = bcc_symcache_resolve_name(resolver, nullptr,
                  "bpf_probe_read_user", &addr) >= 0 ? true: false;
    if (found)
      return probe.str();

    /* For arch with overlapping address space, dont use bpf_probe_read for
     * user read. Just error out */
#if defined(__s390x__)
    overlap_addr = true;
    return "";
#endif

    if (probe.str() == "bpf_probe_read_user")
      return "bpf_probe_read";
    else
      return "bpf_probe_read_str";
  }
  return "";
}

using std::map;
using std::move;
using std::set;
using std::tuple;
using std::make_tuple;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;
using namespace clang;

class ProbeChecker : public RecursiveASTVisitor<ProbeChecker> {
 public:
  explicit ProbeChecker(Expr *arg, const set<tuple<Decl *, int>> &ptregs,
                        bool track_helpers, bool is_assign)
      : needs_probe_(false), is_transitive_(false), ptregs_(ptregs),
        track_helpers_(track_helpers), nb_derefs_(0), is_assign_(is_assign) {
    if (arg) {
      TraverseStmt(arg);
      if (arg->getType()->isPointerType())
        is_transitive_ = needs_probe_;
    }
  }
  explicit ProbeChecker(Expr *arg, const set<tuple<Decl *, int>> &ptregs,
                        bool is_transitive)
      : ProbeChecker(arg, ptregs, is_transitive, false) {}
  bool VisitCallExpr(CallExpr *E) {
    needs_probe_ = false;

    if (is_assign_) {
      // We're looking for a function that returns an external pointer,
      // regardless of the number of dereferences.
      for(auto p : ptregs_) {
        if (std::get<0>(p) == E->getDirectCallee()) {
          needs_probe_ = true;
          // ptregs_ stores the number of dereferences needed to get the external
          // pointer, while nb_derefs_ stores the number of dereferences
          // encountered.  So, any dereference encountered is one less
          // dereference needed to get the external pointer.
          nb_derefs_ -= std::get<1>(p);
          return false;
        }
      }
    } else {
      tuple<Decl *, int> pt = make_tuple(E->getDirectCallee(), nb_derefs_);
      if (ptregs_.find(pt) != ptregs_.end())
        needs_probe_ = true;
    }

    if (!track_helpers_)
      return false;
    if (VarDecl *V = dyn_cast_or_null<VarDecl>(E->getCalleeDecl()))
      needs_probe_ = V->getName() == "bpf_get_current_task";
    return false;
  }
  bool VisitMemberExpr(MemberExpr *M) {
    tuple<Decl *, int> pt = make_tuple(M->getMemberDecl(), nb_derefs_);
    if (ptregs_.find(pt) != ptregs_.end()) {
      needs_probe_ = true;
      return false;
    }
    if (M->isArrow()) {
      /* In A->b, if A is an external pointer, then A->b should be considered
       * one too.  However, if we're taking the address of A->b
       * (nb_derefs_ < 0), we should take it into account for the number of
       * indirections; &A->b is a pointer to A with an offset. */
      if (nb_derefs_ >= 0) {
        ProbeChecker checker = ProbeChecker(M->getBase(), ptregs_,
                                            track_helpers_, is_assign_);
        if (checker.needs_probe() && checker.get_nb_derefs() == 0) {
          needs_probe_ = true;
          return false;
        }
      }
      nb_derefs_++;
    }
    return true;
  }
  bool VisitUnaryOperator(UnaryOperator *E) {
    if (E->getOpcode() == UO_Deref) {
      /* In *A, if A is an external pointer, then *A should be considered one
       * too. */
      ProbeChecker checker = ProbeChecker(E->getSubExpr(), ptregs_,
                                          track_helpers_, is_assign_);
      if (checker.needs_probe() && checker.get_nb_derefs() == 0) {
        needs_probe_ = true;
        return false;
      }
      nb_derefs_++;
    } else if (E->getOpcode() == UO_AddrOf) {
      nb_derefs_--;
    }
    return true;
  }
  bool VisitDeclRefExpr(DeclRefExpr *E) {
    if (is_assign_) {
      // We're looking for an external pointer, regardless of the number of
      // dereferences.
      for(auto p : ptregs_) {
        if (std::get<0>(p) == E->getDecl()) {
          needs_probe_ = true;
          // ptregs_ stores the number of dereferences needed to get the external
          // pointer, while nb_derefs_ stores the number of dereferences
          // encountered.  So, any dereference encountered is one less
          // dereference needed to get the external pointer.
          nb_derefs_ -= std::get<1>(p);
          return false;
        }
      }
    } else {
      tuple<Decl *, int> pt = make_tuple(E->getDecl(), nb_derefs_);
      if (ptregs_.find(pt) != ptregs_.end())
        needs_probe_ = true;
    }
    return true;
  }
  bool needs_probe() const { return needs_probe_; }
  bool is_transitive() const { return is_transitive_; }
  int get_nb_derefs() const { return nb_derefs_; }
 private:
  bool needs_probe_;
  bool is_transitive_;
  const set<tuple<Decl *, int>> &ptregs_;
  bool track_helpers_;
  // Nb of dereferences we go through before finding the external pointer.
  // A negative number counts the number of addrof.
  int nb_derefs_;
  bool is_assign_;
};

// Visit a piece of the AST and mark it as needing probe reads
class ProbeSetter : public RecursiveASTVisitor<ProbeSetter> {
 public:
  explicit ProbeSetter(set<tuple<Decl *, int>> *ptregs, int nb_derefs)
      : ptregs_(ptregs), nb_derefs_(nb_derefs) {}
  bool VisitDeclRefExpr(DeclRefExpr *E) {
    tuple<Decl *, int> pt = make_tuple(E->getDecl(), nb_derefs_);
    ptregs_->insert(pt);
    return true;
  }
  explicit ProbeSetter(set<tuple<Decl *, int>> *ptregs)
      : ProbeSetter(ptregs, 0) {}
  bool VisitUnaryOperator(UnaryOperator *E) {
    if (E->getOpcode() == UO_Deref)
      nb_derefs_++;
    return true;
  }
  bool VisitMemberExpr(MemberExpr *M) {
    tuple<Decl *, int> pt = make_tuple(M->getMemberDecl(), nb_derefs_);
    ptregs_->insert(pt);
    return false;
  }
 private:
  set<tuple<Decl *, int>> *ptregs_;
  // Nb of dereferences we go through before getting to the actual variable.
  int nb_derefs_;
};

MapVisitor::MapVisitor(set<Decl *> &m) : m_(m) {}

bool MapVisitor::VisitCallExpr(CallExpr *Call) {
  if (MemberExpr *Memb = dyn_cast<MemberExpr>(Call->getCallee()->IgnoreImplicit())) {
    StringRef memb_name = Memb->getMemberDecl()->getName();
    if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Memb->getBase())) {
      if (SectionAttr *A = Ref->getDecl()->getAttr<SectionAttr>()) {
        if (!A->getName().startswith("maps"))
          return true;

        if (memb_name == "update" || memb_name == "insert") {
          ProbeChecker checker = ProbeChecker(Call->getArg(1), ptregs_, true,
                                              true);
          if (checker.needs_probe())
            m_.insert(Ref->getDecl());
        }
      }
    }
  }
  return true;
}

ProbeVisitor::ProbeVisitor(ASTContext &C, Rewriter &rewriter,
                           set<Decl *> &m, bool track_helpers) :
  C(C), rewriter_(rewriter), m_(m), ctx_(nullptr), track_helpers_(track_helpers),
  addrof_stmt_(nullptr), is_addrof_(false) {
  const char **calling_conv_regs = get_call_conv();
  cannot_fall_back_safely = (calling_conv_regs == calling_conv_regs_s390x || calling_conv_regs == calling_conv_regs_riscv64);
}

bool ProbeVisitor::assignsExtPtr(Expr *E, int *nbDerefs) {
  if (IsContextMemberExpr(E)) {
    *nbDerefs = 0;
    return true;
  }

  /* If the expression contains a call to another function, we need to visit
  * that function first to know if a rewrite is necessary (i.e., if the
  * function returns an external pointer). */
  if (!TraverseStmt(E))
    return false;

  Probe