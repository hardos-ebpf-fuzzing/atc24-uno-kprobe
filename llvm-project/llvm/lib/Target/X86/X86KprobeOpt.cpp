//===---- X86KprobeOpt.cpp - Implements Kprobe Optimization ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements Linux Kprobe Optimization for instructions not already
// handled by kprobe jump optimization.
//
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Target/TargetMachine.h"

#include <array>

using namespace llvm;

#define DEBUG_TYPE "x86-kprobe-opt"
#define X86_KPROBEOPT_PASS_NAME "Linux kprobe optimization"

STATISTIC(NumOptsAdded, "Number of kprobe-opt nop-opts added");

namespace {
/// Before optimizing a probe, Kprobes performs the following safety checks:
///
/// 1. Kprobes verifies that the region that will be replaced by the jump
///    instruction (the "optimized region") lies entirely within one function.
///    (A jump instruction is multiple bytes, and so may overlay multiple
///    instructions.)
/// 2. Kprobes analyzes the entire function and verifies that there is no jump
///    into the optimized region. Specifically:
///    1) the function contains no indirect jump;
///    2) the function contains no instruction that causes an exception (since
///       the fixup code triggered by the exception could jump back into the
///       optimized region -- Kprobes checks the exception tables to verify
///       this);
///    3) there is no near jump to the optimized region (other than to the first
///       byte).
/// 3. For each instruction in the optimized region, Kprobes verifies that the
///    instruction can be executed out of line.
///
/// 4. The instruction also needs to be boostable.
///
/// TODO: Seems 3 and 4 are the same, need to confirm
///
///
/// How this pass will handle the above cases:
///
/// 1. An nop can be inserted (preferrably) after the
///    terminating instruction of the function. It can be inserted before the
///    terminating instruction if that particular instruction is not
///    jump-optimizable given there are enough space.
///
///    Problem:
///    c3               ret # not enough space to jump optimize this ret
///    # end of current function
///
///    Solution:
///    c3               ret
///    0f 1f 44 00 00   nopl   0x0(%rax,%rax,1) # added instrumentation
///    # end of current function
///
/// 2.1 An indirect jump should always land on a beginning of a basic block
///     (function entry is also the beginning of the entry basic block of that
///     function). This means inserting nop right before the terminator of the
///     immediate basic block predecessor would prevent the problem that kprobe
///     jump optimization on that terminator results in a jump into the middle
///     of the new jump created by kprobe.
///
///     Problem:
///     48 8d 04 37   lea    (%rdi,%rsi,1),%rax # jump-optimize overwrites bb.1
///     bb.1: # start of basic block bb.1
///     48 29 d0      sub    %rdx,%rax # first byte no longer a inst boundary
///
///     Solution:
///     0f 1f 44 00 00   nopl   0x0(%rax,%rax,1) # added instrumentation
///     48 8d 04 37      lea    (%rdi,%rsi,1),%rax
///     bb.1: # start of basic block bb.1
///     48 29 d0         sub    %rdx,%rax
///
///     The BB in the previous case has no terminators and can only failthrough
///     into the next BB. A BB can also have a number of terminator instructions
///     at the end, in such case we only insert the nop before the first
///     terminator:
///
///     Problem:
///     0f 85 05 00 00 00   jne    0x5(%rip)
///     e9 65 00 00 00      jmp    0x65(%rip)
///     bb.1: # start of basic block bb.1
///     48 29 d0            sub    %rdx,%rax
///
///     Solution:
///     0f 1f 44 00 00      nopl   0x0(%rax,%rax,1) # added instrumentation
///     0f 85 05 00 00 00   jne    0x5(%rip)
///     e9 65 00 00 00      jmp    0x65(%rip)
///     bb.1: # start of basic block bb.1
///     48 29 d0            sub    %rdx,%rax
///
///     Here it is acutally not a instruction size issue, but an instruction
///     opcode problem -- jcc/jmp cannot be boosted. Adding nops between
///     terminators (between jne and jmp in this case) might cause CodeGen
///     backend to incorrectly emit undefined labels. Given that terminators
///     only perform control flow transfers w/o DEFs (that is, no change in
///     register/memory except %rip). Optimizing the first terminator should be
///     sufficient for kprobing all the terminators.
///
/// 2.2 TODO:
///
/// 2.3 Same as 2.1
///
/// 3. TODO:
///
/// 4. Insert a nop before non-boostable instructions
///
class X86KprobeOpt : public MachineFunctionPass {
public:
  static char ID;

  X86KprobeOpt() : MachineFunctionPass(ID) {}
  StringRef getPassName() const override { return X86_KPROBEOPT_PASS_NAME; }
  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  /// Machine instruction info used throughout the class.
  const X86InstrInfo *TII = nullptr;

  /// MC info used
  const MCInstrInfo *MCII;
  const MCSubtargetInfo *MCSTI;

  bool canBoost(MachineInstr &MI);

  /// Emit the KPROBE_OPT pseudo-instruction
  ///
  /// Define this function inline given its size
  void emitOpt(MachineBasicBlock &MBB, MachineBasicBlock::instr_iterator MBBI) {
    BuildMI(MBB, MBBI, MBBI->getDebugLoc(), TII->get(X86::KPROBE_OPT));
    ++NumOptsAdded;
  }

  /// Count the actual number of terminators in an MBB, excluding any debug
  /// instructions that are included by MachineBasicBlock::terminators
  unsigned numTerminators(MachineBasicBlock &MBB) {
    unsigned N = 0;
    MachineBasicBlock::iterator I = MBB.end();

    // Start from the bottom of the block and work up, examining the
    // terminator instructions.
    while (I != MBB.begin()) {
      --I;

      // Skip debug instructions
      if (I->isDebugInstr())
        continue;

      // Working from the bottom, when we see a non-terminator instruction,
      // we're done.
      if (!I->isTerminator())
        break;

      N++;
    }

    return N;
  }

  /// Given a machine basic block and an iterator into it, split the MBB so
  /// that the part before the iterator falls into the part starting at the
  /// iterator.  This returns the new MBB. If split fails, return a nullptr.
  ///
  /// This function is based on BranchFolder::SplitMBBAt
  MachineBasicBlock *splitMBBAt(MachineBasicBlock &CurMBB,
                                MachineBasicBlock::iterator I);

  // 2-byte boost table from arch/x86/kernel/kprobes/core.c
  static constexpr std::array<bool, 256> TwobyteIsBoostable = {
    0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1,
    0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1,
    0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0,
  };
};

char X86KprobeOpt::ID = 0;
} // end anonymous namespace

INITIALIZE_PASS(X86KprobeOpt, DEBUG_TYPE, X86_KPROBEOPT_PASS_NAME, false, false)

FunctionPass *llvm::createX86KprobeOptPass() { return new X86KprobeOpt(); }

/// Check whether an instruction can be boostable (can_boost function in
/// arch/x86/kernel/kprobes/core.c)
/// There are several conditions:
/// 1. The instruction cannot generate exceptions (e.g. page fault)
/// 2. It cannot have address-size override prefix and CS override prefix
/// 3. opcode-based filtering
///   1) 1-byte opcode
///   2) 2-byte opcode
bool X86KprobeOpt::canBoost(MachineInstr &MI) {
  /// TODO: Handle exceptions
  /// TODO: Handle 2-byte opcode

  unsigned Opcode = MI.getOpcode();
  const MCInstrDesc &Desc = MCII->get(Opcode);
  uint64_t TSFlags = Desc.TSFlags;
  unsigned CurOp = X86II::getOperandBias(Desc);

  // Do not touch pseudo instructions.
  if (X86II::isPseudo(TSFlags))
    return true;

  // 0x0F escape code
  switch (TSFlags & X86II::OpMapMask) {
  case X86II::TB: // Two-byte opcode map
    break;
  case X86II::T8:        // 0F 38
  case X86II::TA:        // 0F 3A
  case X86II::ThreeDNow: // 0F 0F, second 0F emitted by caller.
    return false;        // Cannot be boosted at all
  }

  // Determine where the memory operand starts, if present.
  int MemoryOperand = X86II::getMemoryOperandNo(TSFlags);
  // Get segment override opcode prefix.
  if (MemoryOperand != -1) {
    MemoryOperand += CurOp;
    // Cannot boost CS override prefix
    if (MI.getOperand(MemoryOperand + X86::AddrSegmentReg).getReg() == X86::CS)
      return false;
  }

  /// FIXME: address size opcode prefix cannot be boosted

  if ((TSFlags & X86II::OpMapMask) != X86II::TB) {
    switch (X86II::getBaseOpcodeFor(TSFlags)) {
    // bound
    case 0x62:

    // Conditional jumps
    case 0x70:
    case 0x71:
    case 0x72:
    case 0x73:
    case 0x74:
    case 0x75:
    case 0x76:
    case 0x77:
    case 0x78:
    case 0x79:
    case 0x7a:
    case 0x7b:
    case 0x7c:
    case 0x7d:
    case 0x7e:
    case 0x7f:

    // Call far
    case 0x9a:

    // Grp2
    case 0xc0:
    case 0xc1:

    // software exceptions
    case 0xcc:
    case 0xcd:
    case 0xce:

    // Grp2
    case 0xd0:
    case 0xd1:
    case 0xd2:
    case 0xd3:

    // (UD)
    case 0xd6:

    // ESC
    case 0xd8:
    case 0xd9:
    case 0xda:
    case 0xdb:
    case 0xdc:
    case 0xdd:
    case 0xde:
    case 0xdf:

    // LOOP*, JCXZ
    case 0xe0:
    case 0xe1:
    case 0xe2:
    case 0xe3:

    // near Call, JMP
    case 0xe8:
    case 0xe9:

    // Short JMP
    case 0xeb:

    // LOCK/REP, HLT
    case 0xf0:
    case 0xf1:
    case 0xf2:
    case 0xf3:
    case 0xf4:

    // Grp3
    case 0xf6:
    case 0xf7:

    // Grp4
    case 0xfe:
      // ... are not boostable
      return false;

    // Grp5
    case 0xff:
      // Only indirect jmp is boostable
      return X86::isJMP(Opcode);

    // Others are boostable
    default:
      return true;
    }
  } else {
    // Check the boost table
    return TwobyteIsBoostable[X86II::getBaseOpcodeFor(TSFlags)];
  }
}

MachineBasicBlock *X86KprobeOpt::splitMBBAt(MachineBasicBlock &CurMBB,
                                            MachineBasicBlock::iterator I) {
  assert(I->isTerminator() && "kprobe-opt must split BB at a terminator");

  // First check whether the split is valid

  // A terminator that isn't a branch can't easily be handled
  if (!I->isBranch())
    return nullptr;

  X86::CondCode BranchCode = X86::getCondFromBranch(*I);
  // Can't handle indirect branch
  if (BranchCode == X86::COND_INVALID)
    return nullptr;

  // In practice we should never have an undef eflags operand, if we do
  // abort here as we are not prepared to preserve the flag.
  if (I->findRegisterUseOperand(X86::EFLAGS)->isUndef())
    return nullptr;

  MachineBasicBlock *TBB = I->getOperand(0).getMBB();

  // Advance iterator to point to the instruction that will be the start of the
  // new BB
  ++I;

  if (!TII->isLegalToSplitMBBAt(CurMBB, I))
    return nullptr;

  // Start doing the split

  MachineFunction &MF = *CurMBB.getParent();

  // Create the fall-through block.
  MachineFunction::iterator MBBI = CurMBB.getIterator();
  MachineBasicBlock *NewMBB =
      MF.CreateMachineBasicBlock(CurMBB.getBasicBlock());
  MF.insert(++MBBI, NewMBB);

  // Move all the successors of this block to the specified block.
  NewMBB->transferSuccessors(&CurMBB);
  // TBB is also transferred, but it's actually a successor of CurBB
  NewMBB->removeSuccessor(TBB, /* NormalizeSuccProbs */ true);

  // Add back TBB
  CurMBB.addSuccessor(TBB);
  // Add an edge from CurMBB to NewMBB for the fall-through.
  CurMBB.addSuccessor(NewMBB);

  // Splice the code over.
  NewMBB->splice(NewMBB->end(), &CurMBB, I, CurMBB.end());

  // Fixup liveins
  LivePhysRegs LiveRegs;
  computeAndAddLiveIns(LiveRegs, *NewMBB);

  /// TODO: Do we need to fix liveouts as well?

  return NewMBB;
}

/// For debug use
//#define MF_TARGET "x86_event_sysfs_show"

bool X86KprobeOpt::runOnMachineFunction(MachineFunction &MF) {
  const Module *M = MF.getMMI().getModule();
  if (!M->getModuleFlag("kcfi"))
    return false;

#ifdef MF_TARGET
  if (MF.getName() == MF_TARGET)
    MF.print(errs());
#endif

  const auto &SubTarget = MF.getSubtarget<X86Subtarget>();
  TII = SubTarget.getInstrInfo();
  MCII = MF.getTarget().getMCInstrInfo();
  MCSTI = MF.getTarget().getMCSubtargetInfo();

  // Work list for terminators that may require BB split
  SmallVector<MachineInstr *, 8> TermWorkList;

  // First pass: fixup all non-boost-able instructions
  for (MachineBasicBlock &MBB : MF) {
    for (auto MII = MBB.instr_begin(), MIE = MBB.instr_end(); MII != MIE;
         ++MII) {
      if (!canBoost(*MII)) {
        emitOpt(MBB, MII);

        // Do not touch any other terminators except the first one
        if (MII->isTerminator()) {
          assert(MII == MBB.getFirstInstrTerminator() &&
                 "First visited terminator is not the first terminator in MBB");

          // There are more than one terminators, need to handle BB split later
          if (numTerminators(MBB) > 1)
            TermWorkList.push_back(&*MII);

          break;
        }
      }
    }
  }

  // Split the BBs here
  while (!TermWorkList.empty()) {
    MachineInstr *Term = TermWorkList.pop_back_val();
    MachineBasicBlock *NewMBB =
        splitMBBAt(*Term->getParent(), Term->getIterator());

    // Split failed, no bother
    if (!NewMBB)
      continue;

    // NewBB might need to be splitted again
    if (numTerminators(*NewMBB) > 1)
      TermWorkList.push_back(&*NewMBB->getFirstTerminator());
  }

  // Second pass: Fixup basic block boundaries
  for (MachineBasicBlock &MBB : MF) {
    // No need to fixup an empty BB
    if (MBB.empty())
      continue;

    MachineBasicBlock::iterator FirstTerm = MBB.getFirstTerminator();

    /// TODO: Only insert if inst size is less than 5

    if (FirstTerm == MBB.end()) {
      // This BB can only fallthrough, add an nop before the last inst

      // Find the last non-debug instruction
      MachineBasicBlock::instr_iterator B = MBB.instr_begin();
      MachineBasicBlock::instr_iterator I = MBB.instr_end();
      while (I != B && (--I)->isDebugInstr())
        ; /*noop */

      MachineBasicBlock::instr_iterator InsertBefore = I;

      // Do not emit extra nops if we already got one
      if (I == B || (--I)->getOpcode() != X86::KPROBE_OPT)
        emitOpt(MBB, InsertBefore);

    } else {
      // There are terminators at the end of the BB, add an nop before the
      // first terminator
      MachineBasicBlock::instr_iterator InsertBefore =
          FirstTerm.getInstrIterator();

      // Do not emit extra nops if we already got one
      if (FirstTerm == MBB.begin() ||
          (--FirstTerm)->getOpcode() != X86::KPROBE_OPT)
        emitOpt(MBB, InsertBefore);
    }
  }

  /// TODO: Handle exceptions

#ifdef MF_TARGET
  if (MF.getName() == MF_TARGET)
    MF.print(errs());
#endif

  return true;
}