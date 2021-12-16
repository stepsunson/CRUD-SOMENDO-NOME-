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

  ProbeChecker checker = ProbeChecker(E, ptregs_, track_helpers_,
                                      true);
  if (checker.is_transitive()) {
    // The negative of the number of dereferences is the number of addrof.  In
    // an assignment, if we went through n addrof before getting the external
    // pointer, then we'll need n dereferences on the left-hand side variable
    // to get to the external pointer.
    *nbDerefs = -checker.get_nb_derefs();
    return true;
  }

  if (E->IgnoreParenCasts()->getStmtClass() == Stmt::CallExprClass) {
    CallExpr *Call = dyn_cast<CallExpr>(E->IgnoreParenCasts());
    if (MemberExpr *Memb = dyn_cast<MemberExpr>(Call->getCallee()->IgnoreImplicit())) {
      StringRef memb_name = Memb->getMemberDecl()->getName();
      if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Memb->getBase())) {
        if (SectionAttr *A = Ref->getDecl()->getAttr<SectionAttr>()) {
          if (!A->getName().startswith("maps"))
            return false;

          if (memb_name == "lookup" || memb_name == "lookup_or_init" ||
              memb_name == "lookup_or_try_init") {
            if (m_.find(Ref->getDecl()) != m_.end()) {
              // Retrieved an ext. pointer from a map, mark LHS as ext. pointer.
              // Pointers from maps always need a single dereference to get the
              // actual value.  The value may be an external pointer but cannot
              // be a pointer to an external pointer as the verifier prohibits
              // storing known pointers (to map values, context, the stack, or
              // the packet) in maps.
              *nbDerefs = 1;
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}
bool ProbeVisitor::VisitVarDecl(VarDecl *D) {
  if (Expr *E = D->getInit()) {
    int nbDerefs;
    if (assignsExtPtr(E, &nbDerefs)) {
      // The negative of the number of addrof is the number of dereferences.
      tuple<Decl *, int> pt = make_tuple(D, nbDerefs);
      set_ptreg(pt);
    }
  }
  return true;
}

bool ProbeVisitor::TraverseStmt(Stmt *S) {
  if (whitelist_.find(S) != whitelist_.end())
    return true;
  auto ret = RecursiveASTVisitor<ProbeVisitor>::TraverseStmt(S);
  if (addrof_stmt_ == S) {
    addrof_stmt_ = nullptr;
    is_addrof_ = false;
  }
  return ret;
}

bool ProbeVisitor::VisitCallExpr(CallExpr *Call) {
  Decl *decl = Call->getCalleeDecl();
  if (decl == nullptr)
      return true;

  // Skip bpf_probe_read for the third argument if it is an AddrOf.
  if (VarDecl *V = dyn_cast<VarDecl>(decl)) {
    if (V->getName() == "bpf_probe_read" && Call->getNumArgs() >= 3) {
      const Expr *E = Call->getArg(2)->IgnoreParenCasts();
      whitelist_.insert(E);
      return true;
    }
  }

  if (FunctionDecl *F = dyn_cast<FunctionDecl>(decl)) {
    if (F->hasBody()) {
      unsigned i = 0;
      for (auto arg : Call->arguments()) {
        ProbeChecker checker = ProbeChecker(arg, ptregs_, track_helpers_,
                                            true);
        if (checker.needs_probe()) {
          tuple<Decl *, int> pt = make_tuple(F->getParamDecl(i),
                                             -checker.get_nb_derefs());
          ptregs_.insert(pt);
        }
        ++i;
      }
      if (fn_visited_.find(F) == fn_visited_.end()) {
        fn_visited_.insert(F);
        /* Maintains a stack of the number of dereferences for the external
         * pointers returned by each function in the call stack or -1 if the
         * function didn't return an external pointer. */
        ptregs_returned_.push_back(-1);
        TraverseDecl(F);
        int nb_derefs = ptregs_returned_.back();
        ptregs_returned_.pop_back();
        if (nb_derefs != -1) {
          tuple<Decl *, int> pt = make_tuple(F, nb_derefs);
          ptregs_.insert(pt);
        }
      }
    }
  }
  return true;
}
bool ProbeVisitor::VisitReturnStmt(ReturnStmt *R) {
  /* If this function wasn't called by another, there's no need to check the
   * return statement for external pointers. */
  if (ptregs_returned_.size() == 0)
    return true;

  /* Reverse order of traversals.  This is needed if, in the return statement,
   * we're calling a function that's returning an external pointer: we need to
   * know what the function is returning to decide what this function is
   * returning. */
  if (!TraverseStmt(R->getRetValue()))
    return false;

  ProbeChecker checker = ProbeChecker(R->getRetValue(), ptregs_,
                                      track_helpers_, true);
  if (checker.needs_probe()) {
    int curr_nb_derefs = ptregs_returned_.back();
    int nb_derefs = -checker.get_nb_derefs();
    /* If the function returns external pointers with different levels of
     * indirection, we handle the case with the highest level of indirection
     * and leave it to the user to manually handle other cases. */
    if (nb_derefs > curr_nb_derefs) {
      ptregs_returned_.pop_back();
      ptregs_returned_.push_back(nb_derefs);
    }
  }
  return true;
}
bool ProbeVisitor::VisitBinaryOperator(BinaryOperator *E) {
  if (!E->isAssignmentOp())
    return true;

  // copy probe attribute from RHS to LHS if present
  int nbDerefs;
  if (assignsExtPtr(E->getRHS(), &nbDerefs)) {
    ProbeSetter setter(&ptregs_, nbDerefs);
    setter.TraverseStmt(E->getLHS());
  }
  return true;
}
bool ProbeVisitor::VisitUnaryOperator(UnaryOperator *E) {
  if (E->getOpcode() == UO_AddrOf) {
    addrof_stmt_ = E;
    is_addrof_ = true;
  }
  if (E->getOpcode() != UO_Deref)
    return true;
  if (memb_visited_.find(E) != memb_visited_.end())
    return true;
  Expr *sub = E->getSubExpr();
  if (!ProbeChecker(sub, ptregs_, track_helpers_).needs_probe())
    return true;
  memb_visited_.insert(E);
  string pre, post;
  pre = "({ typeof(" + E->getType().getAsString() + ") _val; __builtin_memset(&_val, 0, sizeof(_val));";
  if (cannot_fall_back_safely)
    pre += " bpf_probe_read_kernel(&_val, sizeof(_val), (void *)";
  else
    pre += " bpf_probe_read(&_val, sizeof(_val), (void *)";
  post = "); _val; })";
  rewriter_.ReplaceText(expansionLoc(E->getOperatorLoc()), 1, pre);
  rewriter_.InsertTextAfterToken(expansionLoc(GET_ENDLOC(sub)), post);
  return true;
}
bool ProbeVisitor::VisitMemberExpr(MemberExpr *E) {
  if (memb_visited_.find(E) != memb_visited_.end()) return true;

  Expr *base;
  SourceLocation rhs_start, member;
  bool found = false;
  for (MemberExpr *M = E; M; M = dyn_cast<MemberExpr>(M->getBase())) {
    memb_visited_.insert(M);
    rhs_start = GET_ENDLOC(M);
    base = M->getBase();
    member = M->getMemberLoc();
    if (M->isArrow()) {
      found = true;
      break;
    }
  }
  if (!found)
    return true;
  if (member.isInvalid()) {
    error(GET_ENDLOC(base), "internal error: MemberLoc is invalid while preparing probe rewrite");
    return false;
  }

  if (!rewriter_.isRewritable(GET_BEGINLOC(E)))
    return true;

  // parent expr has addrof, skip the rewrite, set is_addrof_ to flase so
  // it won't affect next level of indirect address
  if (is_addrof_) {
    is_addrof_ = false;
    return true;
  }

  /* If the base of the dereference is a call to another function, we need to
   * visit that function first to know if a rewrite is necessary (i.e., if the
   * function returns an external pointer). */
  if (base->IgnoreParenCasts()->getStmtClass() == Stmt::CallExprClass) {
    CallExpr *Call = dyn_cast<CallExpr>(base->IgnoreParenCasts());
    if (!TraverseStmt(Call))
      return false;
  }

  // Checks to see if the expression references something that needs to be run
  // through bpf_probe_read.
  if (!ProbeChecker(base, ptregs_, track_helpers_).needs_probe())
    return true;

  // If the base is an array, we will skip rewriting. See issue #2352.
  if (E->getType()->isArrayType())
    return true;

  string rhs = rewriter_.getRewrittenText(expansionRange(SourceRange(rhs_start, GET_ENDLOC(E))));
  string base_type = base->getType()->getPointeeType().getAsString();
  string pre, post;
  pre = "({ typeof(" + E->getType().getAsString() + ") _val; __builtin_memset(&_val, 0, sizeof(_val));";
  if (cannot_fall_back_safely)
    pre += " bpf_probe_read_kernel(&_val, sizeof(_val), (void *)&";
  else
    pre += " bpf_probe_read(&_val, sizeof(_val), (void *)&";
  post = rhs + "); _val; })";
  rewriter_.InsertText(expansionLoc(GET_BEGINLOC(E)), pre);
  rewriter_.ReplaceText(expansionRange(SourceRange(member, GET_ENDLOC(E))), post);
  return true;
}
bool ProbeVisitor::VisitArraySubscriptExpr(ArraySubscriptExpr *E) {
  if (memb_visited_.find(E) != memb_visited_.end()) return true;
  if (!ProbeChecker(E, ptregs_, track_helpers_).needs_probe())
    return true;

  // Parent expr has addrof, skip the rewrite.
  if (is_addrof_)
    return true;

  // If the base is an array, we will skip rewriting. See issue #2352.
  if (E->getType()->isArrayType())
    return true;

  if (!rewriter_.isRewritable(GET_BEGINLOC(E)))
    return true;

  Expr *base = E->getBase();
  Expr *idx = E->getIdx();
  memb_visited_.insert(E);

  if (!rewriter_.isRewritable(GET_BEGINLOC(base)))
    return true;
  if (!rewriter_.isRewritable(GET_BEGINLOC(idx)))
    return true;


  string pre, lbracket, rbracket;
  LangOptions opts;
  SourceLocation lbracket_start, lbracket_end;
  SourceRange lbracket_range;

  /* For cases like daddr->s6_addr[4], clang encodes the end location of "base"
   * as "]". This makes it hard to rewrite the expression like
   * "daddr->s6_addr  [ 4 ]" since we do not know the end location
   * of "addr->s6_addr". Let us abort the operation if this is the case.
   */
  lbracket_start = Lexer::getLocForEndOfToken(GET_ENDLOC(base), 1,
                                              rewriter_.getSourceMgr(),
                                              opts).getLocWithOffset(1);
  lbracket_end = GET_BEGINLOC(idx).getLocWithOffset(-1);
  lbracket_range = expansionRange(SourceRange(lbracket_start, lbracket_end));
  if (rewriter_.getRewrittenText(lbracket_range).size() == 0)
    return true;

  pre = "({ typeof(" + E->getType().getAsString() + ") _val; __builtin_memset(&_val, 0, sizeof(_val));";
  if (cannot_fall_back_safely)
    pre += " bpf_probe_read_kernel(&_val, sizeof(_val), (void *)((";
  else
    pre += " bpf_probe_read(&_val, sizeof(_val), (void *)((";
  if (isMemberDereference(base)) {
    pre += "&";
    // If the base of the array subscript is a member dereference, we'll rewrite
    // both at the same time.
    addrof_stmt_ = base;
    is_addrof_ = true;
  }
  rewriter_.InsertText(expansionLoc(GET_BEGINLOC(base)), pre);

  /* Replace left bracket and any space around it.  Since Clang doesn't provide
   * a method to retrieve the left bracket, replace everything from the end of
   * the base to the start of the index. */
  lbracket = ") + (";
  rewriter_.ReplaceText(lbracket_range, lbracket);

  rbracket = "))); _val; })";
  rewriter_.ReplaceText(expansionLoc(E->getRBracketLoc()), 1, rbracket);

  return true;
}

bool ProbeVisitor::isMemberDereference(Expr *E) {
  if (E->IgnoreParenCasts()->getStmtClass() != Stmt::MemberExprClass)
    return false;
  for (MemberExpr *M = dyn_cast<MemberExpr>(E->IgnoreParenCasts()); M;
       M = dyn_cast<MemberExpr>(M->getBase()->IgnoreParenCasts())) {
    if (M->isArrow())
      return true;
  }
  return false;
}
bool ProbeVisitor::IsContextMemberExpr(Expr *E) {
  if (!E->getType()->isPointerType())
    return false;

  Expr *base;
  SourceLocation member;
  bool found = false;
  MemberExpr *M;
  Expr *Ex = E->IgnoreParenCasts();
  while (Ex->getStmtClass() == Stmt::ArraySubscriptExprClass
         || Ex->getStmtClass() == Stmt::MemberExprClass) {
    if (Ex->getStmtClass() == Stmt::ArraySubscriptExprClass) {
      Ex = dyn_cast<ArraySubscriptExpr>(Ex)->getBase()->IgnoreParenCasts();
    } else if (Ex->getStmtClass() == Stmt::MemberExprClass) {
      M = dyn_cast<MemberExpr>(Ex);
      base = M->getBase()->IgnoreParenCasts();
      member = M->getMemberLoc();
      if (M->isArrow()) {
        found = true;
        break;
      }
      Ex = base;
    }
  }
  if (!found) {
    return false;
  }
  if (member.isInvalid()) {
    return false;
  }

  if (DeclRefExpr *base_expr = dyn_cast<DeclRefExpr>(base)) {
    if (base_expr->getDecl() == ctx_) {
      return true;
    }
  }
  return false;
}

SourceRange
ProbeVisitor::expansionRange(SourceRange range) {
#if LLVM_MAJOR_VERSION >= 7
  return rewriter_.getSourceMgr().getExpansionRange(range).getAsRange();
#else
  return rewriter_.getSourceMgr().getExpansionRange(range);
#endif
}

SourceLocation
ProbeVisitor::expansionLoc(SourceLocation loc) {
  return rewriter_.getSourceMgr().getExpansionLoc(loc);
}

template <unsigned N>
DiagnosticBuilder ProbeVisitor::error(SourceLocation loc, const char (&fmt)[N]) {
  unsigned int diag_id = C.getDiagnostics().getCustomDiagID(DiagnosticsEngine::Error, fmt);
  return C.getDiagnostics().Report(loc, diag_id);
}

BTypeVisitor::BTypeVisitor(ASTContext &C, BFrontendAction &fe)
    : C(C), diag_(C.getDiagnostics()), fe_(fe), rewriter_(fe.rewriter()), out_(llvm::errs()) {
  const char **calling_conv_regs = get_call_conv();
  cannot_fall_back_safely = (calling_conv_regs == calling_conv_regs_s390x || calling_conv_regs == calling_conv_regs_riscv64);
}

void BTypeVisitor::genParamDirectAssign(FunctionDecl *D, string& preamble,
                                        const char **calling_conv_regs) {
  for (size_t idx = 0; idx < fn_args_.size(); idx++) {
    ParmVarDecl *arg = fn_args_[idx];

    if (idx >= 1) {
      // Move the args into a preamble section where the same params are
      // declared and initialized from pt_regs.
      // Todo: this init should be done only when the program requests it.
      string text = rewriter_.getRewrittenText(expansionRange(arg->getSourceRange()));
      arg->addAttr(UnavailableAttr::CreateImplicit(C, "ptregs"));
      size_t d = idx - 1;
      const char *reg = calling_conv_regs[d];
      preamble += " " + text + " = (" + arg->getType().getAsString() + ")" +
                  fn_args_[0]->getName().str() + "->" + string(reg) + ";";
    }
  }
}

void BTypeVisitor::genParamIndirectAssign(FunctionDecl *D, string& preamble,
                                          const char **calling_conv_regs) {
  string new_ctx;

  for (size_t idx = 0; idx < fn_args_.size(); idx++) {
    ParmVarDecl *arg = fn_args_[idx];

    if (idx == 0) {
      new_ctx = "__" + arg->getName().str();
      preamble += " struct pt_regs * " + new_ctx + " = (void *)" +
                  arg->getName().str() + "->" +
                  string(pt_regs_syscall_regs()) + ";";
    } else {
      // Move the args into a preamble section where the same params are
      // declared and initialized from pt_regs.
      // Todo: this init should be done only when the program requests it.
      string text = rewriter_.getRewrittenText(expansionRange(arg->getSourceRange()));
      size_t d = idx - 1;
      const char *reg = calling_conv_regs[d];
      preamble += "\n " + text + ";";
      if (cannot_fall_back_safely)
        preamble += " bpf_probe_read_kernel";
      else
        preamble += " bpf_probe_read";
      preamble += "(&" + arg->getName().str() + ", sizeof(" +
                  arg->getName().str() + "), &" + new_ctx + "->" +
                  string(reg) + ");";
    }
  }
}

void BTypeVisitor::rewriteFuncParam(FunctionDecl *D) {
  string preamble = "{\n";
  if (D->param_size() > 1) {
    bool is_syscall = false;
    if (strncmp(D->getName().str().c_str(), "syscall__", 9) == 0 ||
        strncmp(D->getName().str().c_str(), "kprobe____x64_sys_", 18) == 0)
      is_syscall = true;
    const char **calling_conv_regs = get_call_conv(is_syscall);

    // If function prefix is "syscall__" or "kprobe____x64_sys_",
    // the function will attach to a kprobe syscall function.
    // Guard parameter assiggnment with CONFIG_ARCH_HAS_SYSCALL_WRAPPER.
    // For __x64_sys_* syscalls, this is always true, but we guard
    // it in case of "syscall__" for other architectures.
    if (is_syscall) {
      preamble += "#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)\n";
      genParamIndirectAssign(D, preamble, calling_conv_regs);
      preamble += "\n#else\n";
      genParamDirectAssign(D, preamble, calling_conv_regs);
      preamble += "\n#endif\n";
    } else {
      genParamDirectAssign(D, preamble, calling_conv_regs);
    }
    rewriter_.ReplaceText(
        expansionRange(SourceRange(GET_ENDLOC(D->getParamDecl(0)),
                    GET_ENDLOC(D->getParamDecl(D->getNumParams() - 1)))),
        fn_args_[0]->getName());
  }
  // for each trace argument, convert the variable from ptregs to something on stack
  if (CompoundStmt *S = dyn_cast<CompoundStmt>(D->getBody()))
    rewriter_.ReplaceText(S->getLBracLoc(), 1, preamble);
}

bool BTypeVisitor::VisitFunctionDecl(FunctionDecl *D) {
  // put each non-static non-inline function decl in its own section, to be
  // extracted by the MemoryManager
  auto real_start_loc = rewriter_.getSourceMgr().getFileLoc(GET_BEGINLOC(D));
  if (fe_.is_rewritable_ext_func(D)) {
    current_fn_ = string(D->getName());
    string bd = rewriter_.getRewrittenText(expansionRange(D->getSourceRange()));
    auto func_info = fe_.prog_func_info_.add_func(current_fn_);
    if (!func_info) {
      // We should only reach add_func above once per function seen, but the
      // BPF_PROG-helper using macros in export/helpers.h (KFUNC_PROBE ..
      // LSM_PROBE) break this logic. TODO: adjust export/helpers.h to not
      // do so and bail out here, or find a better place to do add_func
      func_info = fe_.prog_func_info_.get_func(current_fn_);
      //error(GET_BEGINLOC(D), "redefinition of existing function");
      //return false;
    }
    func_info->src_ = bd;
    fe_.func_range_[current_fn_] = expansionRange(D->getSourceRange());
    if (!D->getAttr<SectionAttr>()) {
      string attr = string("__attribute__((section(\"") + BPF_FN_PREFIX +
                    D->getName().str() + "\")))\n";
      rewriter_.InsertText(real_start_loc, attr);
    }
    if (D->param_size() > MAX_CALLING_CONV_REGS + 1) {
      error(GET_BEGINLOC(D->getParamDecl(MAX_CALLING_CONV_REGS + 1)),
            "too many arguments, bcc only supports in-register parameters");
      return false;
    }

    fn_args_.clear();
    for (auto arg_it = D->param_begin(); arg_it != D->param_end(); arg_it++) {
      auto *arg = *arg_it;
      if (arg->getName() == "") {
        error(GET_ENDLOC(arg), "arguments to BPF program definition must be named");
        return false;
      }
      fn_args_.push_back(arg);
    }
    rewriteFuncParam(D);
  } else if (D->hasBody() &&
             rewriter_.getSourceMgr().getFileID(real_start_loc)
               == rewriter_.getSourceMgr().getMainFileID()) {
    // rewritable functions that are static should be always treated as helper
    rewriter_.InsertText(real_start_loc, "__attribute__((always_inline))\n");
  }
  return true;
}

// Reverse the order of call traversal so that parameters inside of
// function calls will get rewritten before the call itself, otherwise
// text mangling will result.
bool BTypeVisitor::TraverseCallExpr(CallExpr *Call) {
  for (auto child : Call->children())
    if (!TraverseStmt(child))
      return false;
  if (!WalkUpFromCallExpr(Call))
    return false;
  return true;
}

// convert calls of the type:
//  table.foo(&key)
// to:
//  bpf_table_foo_elem(bpf_pseudo_fd(table), &key [,&leaf])
bool BTypeVisitor::VisitCallExpr(CallExpr *Call) {
  // make sure node is a reference to a bpf table, which is assured by the
  // presence of the section("maps/<typename>") GNU __attribute__
  if (MemberExpr *Memb = dyn_cast<MemberExpr>(Call->getCallee()->IgnoreImplicit())) {
    StringRef memb_name = Memb->getMemberDecl()->getName();
    if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Memb->getBase())) {
      if (SectionAttr *A = Ref->getDecl()->getAttr<SectionAttr>()) {
        if (!A->getName().startswith("maps"))
          return true;

        string args = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(0)),
                                                   GET_ENDLOC(Call->getArg(Call->getNumArgs() - 1)))));

        // find the table fd, which was opened at declaration time
        TableStorage::iterator desc;
        Path local_path({fe_.id(), string(Ref->getDecl()->getName())});
        Path global_path({string(Ref->getDecl()->getName())});
        if (!fe_.table_storage().Find(local_path, desc)) {
          if (!fe_.table_storage().Find(global_path, desc)) {
            error(GET_ENDLOC(Ref), "bpf_table %0 failed to open") << Ref->getDecl()->getName();
            return false;
          }
        }
        string fd = to_string(desc->second.fd >= 0 ? desc->second.fd : desc->second.fake_fd);
        string prefix, suffix;
        string txt;
        auto rewrite_start = GET_BEGINLOC(Call);
        auto rewrite_end = GET_ENDLOC(Call);
        if (memb_name == "lookup_or_init" || memb_name == "lookup_or_try_init") {
          string name = string(Ref->getDecl()->getName());
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string arg1 = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));
          string lookup = "bpf_map_lookup_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string update = "bpf_map_update_elem_(bpf_pseudo_fd(1, " + fd + ")";
          txt  = "({typeof(" + name + ".leaf) *leaf = " + lookup + ", " + arg0 + "); ";
          txt += "if (!leaf) {";
          txt += " " + update + ", " + arg0 + ", " + arg1 + ", BPF_NOEXIST);";
          txt += " leaf = " + lookup + ", " + arg0 + ");";
          if (memb_name == "lookup_or_init") {
            txt += " if (!leaf) return 0;";
          }
          txt += "}";
          txt += "leaf;})";
        } else if (memb_name == "increment" || memb_name == "atomic_increment") {
          string name = string(Ref->getDecl()->getName());
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));

          string increment_value = "1";
          if (Call->getNumArgs() == 2) {
            increment_value = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));

          }

          string lookup = "bpf_map_lookup_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string update = "bpf_map_update_elem_(bpf_pseudo_fd(1, " + fd + ")";
          txt  = "({ typeof(" + name + ".key) _key = " + arg0 + "; ";
          txt += "typeof(" + name + ".leaf) *_leaf = " + lookup + ", &_key); ";
          txt += "if (_leaf) ";

          if (memb_name == "atomic_increment") {
            txt += "lock_xadd(_leaf, " + increment_value + ");";
          } else {
            txt += "(*_leaf) += " + increment_value + ";";
          }
          if (desc->second.type == BPF_MAP_TYPE_HASH) {
            txt += "else { typeof(" + name + ".leaf) _zleaf; __builtin_memset(&_zleaf, 0, sizeof(_zleaf)); ";
            txt += "_zleaf += " + increment_value + ";";
            txt += update + ", &_key, &_zleaf, BPF_NOEXIST); } ";
          }
          txt += "})";
        } else if (memb_name == "perf_submit") {
          string name = string(Ref->getDecl()->getName());
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string args_other = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(1)),
                                                           GET_ENDLOC(Call->getArg(2)))));
          txt = "bpf_perf_event_output(" + arg0 + ", (void *)bpf_pseudo_fd(1, " + fd + ")";
          txt += ", CUR_CPU_IDENTIFIER, " + args_other + ")";

          // e.g.
          // struct data_t { u32 pid; }; data_t data;
          // events.perf_submit(ctx, &data, sizeof(data));
          // ...
          //                       &data   ->     data    ->  typeof(data)        ->   data_t
          auto type_arg1 = Call->getArg(1)->IgnoreCasts()->getType().getTypePtr()->getPointeeType().getTypePtrOrNull();
          if (type_arg1 && type_arg1->isStructureType()) {
            auto event_type = type_arg1->getAsTagDecl();
            const auto *r = dyn_cast<RecordDecl>(event_type);
            std::vector<std::string> perf_event;

            for (auto it = r->field_begin(); it != r->field_end(); ++it) {
              // After LLVM commit aee49255074f
              // (https://github.com/llvm/llvm-project/commit/aee49255074fd4ef38d97e6e70cbfbf2f9fd0fa7)
              // array type change from `comm#char [16]` to `comm#char[16]`
              perf_event.push_back(it->getNameAsString() + "#" + it->getType().getAsString()); //"pid#u32"
            }
            fe_.perf_events_[name] = perf_event;
          }
        } else if (memb_name == "perf_submit_skb") {
          string skb = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string skb_len = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));
          string meta = rewriter_.getRewrittenText(expansionRange(Call->getArg(2)->getSourceRange()));
          string meta_len = rewriter_.getRewrittenText(expansionRange(Call->getArg(3)->getSourceRange()));
          txt = "bpf_perf_event_output(" +
            skb + ", " +
            "(void *)bpf_pseudo_fd(1, " + fd + "), " +
            "((__u64)" + skb_len + " << 32) | BPF_F_CURRENT_CPU, " +
            meta + ", " +
            meta_len + ");";
        } else if (memb_name == "get_stackid") {
          if (desc->second.type == BPF_MAP_TYPE_STACK_TRACE) {
            string arg0 =
                rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
            txt = "bcc_get_stackid(";
            txt += "bpf_pseudo_fd(1, " + fd + "), " + arg0;
            rewrite_end = GET_ENDLOC(Call->getArg(0));
            } else {
              error(GET_BEGINLOC(Call), "get_stackid only available on stacktrace maps");
              return false;
            }
        } else if (memb_name == "sock_map_update" || memb_name == "sock_hash_update") {
          string ctx = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string keyp = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));
          string flag = rewriter_.getRewrittenText(expansionRange(Call->getArg(2)->getSourceRange()));
          txt = "bpf_" + string(memb_name) + "(" + ctx + ", " +
            "(void *)bpf_pseudo_fd(1, " + fd + "), " + keyp + ", " + flag + ");";
        } else if (memb_name == "ringbuf_output") {
          string name = string(Ref->getDecl()->getName());
          string args = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(0)),
                                                           GET_ENDLOC(Call->getArg(2)))));
          txt = "bpf_ringbuf_output((void *)bpf_pseudo_fd(1, " + fd + ")";
          txt += ", " + args + ")";

          // e.g.
          // struct data_t { u32 pid; }; data_t data;
          // events.ringbuf_output(&data, sizeof(data), 0);
          // ...
          //                       &data   ->     data    ->  typeof(data)        ->   data_t
          auto type_arg0 = Call->getArg(0)->IgnoreCasts()->getType().getTypePtr()->getPointeeType().getTypePtr();
          if (type_arg0->isStructureType()) {
            auto event_type = type_arg0->getAsTagDecl();
            const auto *r = dyn_cast<RecordDecl>(event_type);
            std::vector<std::string> perf_event;

            for (auto it = r->field_begin(); it != r->field_end(); ++it) {
              perf_event.push_back(it->getNameAsString() + "#" + it->getType().getAsString()); //"pid#u32"
            }
            fe_.perf_events_[name] = perf_event;
          }
        } else if (memb_name == "ringbuf_reserve") {
          string name = string(Ref->getDecl()->getName());
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          txt = "bpf_ringbuf_reserve((void *)bpf_pseudo_fd(1, " + fd + ")";
          txt += ", " + arg0 + ", 0)"; // Flags in reserve are meaningless
        } else if (memb_name == "ringbuf_discard") {
          string name = string(Ref->getDecl()->getName());
          string args = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(0)),
                                                           GET_ENDLOC(Call->getArg(1)))));
          txt = "bpf_ringbuf_discard(" + args + ")";
        } else if (memb_name == "ringbuf_submit") {
          string name = string(Ref->getDecl()->getName());
          string args = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(0)),
                                                           GET_ENDLOC(Call->getArg(1)))));
          txt = "bpf_ringbuf_submit(" + args + ")";

          // e.g.
          // struct data_t { u32 pid; };
          // data_t *data = events.ringbuf_reserve(sizeof(data_t));
          // events.ringbuf_submit(data, 0);
          // ...
          //                       &data   ->     data    ->  typeof(data)        ->   data_t
          auto type_arg0 = Call->getArg(0)->IgnoreCasts()->getType().getTypePtr()->getPointeeType().getTypePtr();
          if (type_arg0->isStructureType()) {
            auto event_type = type_arg0->getAsTagDecl();
            const auto *r = dyn_cast<RecordDecl>(event_type);
            std::vector<std::string> perf_event;

            for (auto it = r->field_begin(); it != r->field_end(); ++it) {
              perf_event.push_back(it->getNameAsString() + "#" + it->getType().getAsString()); //"pid#u32"
            }
            fe_.perf_events_[name] = perf_event;
          }
        } else if (memb_name == "msg_redirect_hash" || memb_name == "sk_redirect_hash") {
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string args_other = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(1)),
                                                           GET_ENDLOC(Call->getArg(2)))));

          txt = "bpf_" + string(memb_name) + "(" + arg0 + ", (void *)bpf_pseudo_fd(1, " + fd + "), ";
          txt += args_other + ")";
        } else {
          if (memb_name == "lookup") {
            prefix = "bpf_map_lookup_elem";
            suffix = ")";
          } else if (memb_name == "update") {
            prefix = "bpf_map_update_elem";
            suffix = ", BPF_ANY)";
          } else if (memb_name == "insert") {
            if (desc->second.type == BPF_MAP_TYPE_ARRAY) {
              warning(GET_BEGINLOC(Call), "all element of an array already exist; insert() will have no effect");
            }
            prefix = "bpf_map_update_elem";
            suffix = ", BPF_NOEXIST)";
          } else if (memb_name == "delete") {
            prefix = "bpf_map_delete_elem";
            suffix = ")";
          } else if (memb_name == "call") {
            prefix = "bpf_tail_call_";
            suffix = ")";
          } else if (memb_name == "perf_read") {
            prefix = "bpf_perf_event_read";
            suffix = ")";
          } else if (memb_name == "perf_counter_value") {
            prefix = "bpf_perf_event_read_value";
            suffix = ")";
          } else if (memb_name == "check_current_task") {
            prefix = "bpf_current_task_under_cgroup";
            suffix = ")";
          } else if (memb_name == "redirect_map") {
            prefix = "bpf_redirect_map";
            suffix = ")";
          } else if (memb_name == "sk_storage_get") {
            prefix = "bpf_sk_storage_get";
            suffix = ")";
          } else if (memb_name == "sk_storage_delete") {
            prefix = "bpf_sk_storage_delete";
            suffix = ")";
          } else if (memb_name == "inode_storage_get") {
            prefix = "bpf_inode_storage_get";
            suffix = ")";
          } else if (memb_name == "inode_storage_delete") {
            prefix = "bpf_inode_storage_delete";
            suffix = ")";
          } else if (memb_name == "task_storage_get") {
            prefix = "bpf_task_storage_get";
            suffix = ")";
          } else if (memb_name == "task_storage_delete") {
            prefix = "bpf_task_storage_delete";
            suffix = ")";
          } else if (memb_name == "get_local_storage") {
            prefix = "bpf_get_local_storage";
            suffix = ")";
          } else if (memb_name == "push") {
            prefix = "bpf_map_push_elem";
            suffix = ")";
          } else if (memb_name == "pop") {
            prefix = "bpf_map_pop_elem";
            suffix = ")";
          } else if (memb_name == "peek") {
            prefix = "bpf_map_peek_elem";
            suffix = ")";
           } else {
            error(GET_BEGINLOC(Call), "invalid bpf_table operation %0") << memb_name;
            return false;
          }
          prefix += "((void *)bpf_pseudo_fd(1, " + fd + "), ";

          txt = prefix + args + suffix;
        }
        if (!rewriter_.isRewritable(rewrite_start) || !rewriter_.isRewritable(rewrite_end)) {
          error(GET_BEGINLOC(Call), "cannot use map function inside a macro");
          return false;
        }
        rewriter_.ReplaceText(expansionRange(SourceRange(rewrite_start, rewrite_end)), txt);
        return true;
      }
    }
  } else if (Call->getCalleeDecl()) {
    NamedDecl *Decl = dyn_cast<NamedDecl>(Call->getCalleeDecl());
    if (!Decl) return true;

    string text;

    // Bail out when bpf_probe_read_user is unavailable for overlappi