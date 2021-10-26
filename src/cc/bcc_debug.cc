/*
 * Copyright (c) 2017 Facebook, Inc.
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
#include <tuple>
#include <vector>

#if LLVM_MAJOR_VERSION >= 15
#include <llvm/DebugInfo/DWARF/DWARFCompileUnit.h>
#endif
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugLine.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#if LLVM_MAJOR_VERSION >= 15
#include <llvm/MC/MCSubtargetInfo.h>
#endif
#if LLVM_MAJOR_VERSION >= 14
#include <llvm/MC/TargetRegistry.h>
#else
#include <llvm/Support/TargetRegistry.h>
#endif

#include "bcc_debug.h"

namespace ebpf {

// ld_pseudo can only be disassembled properly
// in llvm 6.0, so having this workaround now
// until disto llvm versions catch up
#define WORKAROUND_FOR_LD_PSEUDO

using std::get;
using std::map;
using std::string;
using std::tuple;
using std::vector;
using namespace llvm;
using DWARFLineTable = DWARFDebugLine::LineTable;

void SourceDebugger::adjustInstSize(uint64_t &Size, uint8_t byte0,
                                   