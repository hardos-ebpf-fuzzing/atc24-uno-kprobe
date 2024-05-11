; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=sparcv9 -disable-sparc-leaf-proc | FileCheck %s

;; 1. When emitting code for v9, branches should always explicitly specify
;;    %icc or %xcc.
;; 2. There should never be a `ba` that jumps into two instructions immediately
;;    following it.

define void @i(i32 signext %sel) {
; CHECK-LABEL: i:
; CHECK:         .cfi_startproc
; CHECK-NEXT:  ! %bb.0: ! %entry
; CHECK-NEXT:    save %sp, -176, %sp
; CHECK-NEXT:    .cfi_def_cfa_register %fp
; CHECK-NEXT:    .cfi_window_save
; CHECK-NEXT:    .cfi_register %o7, %i7
; CHECK-NEXT:    cmp %i0, 0
; CHECK-NEXT:    be %icc, .LBB0_2
; CHECK-NEXT:    nop
; CHECK-NEXT:  ! %bb.1: ! %fbb
; CHECK-NEXT:    call f2
; CHECK-NEXT:    nop
; CHECK-NEXT:    ba .LBB0_3
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB0_2: ! %tbb
; CHECK-NEXT:    call f1
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB0_3: ! %end
; CHECK-NEXT:    call f3
; CHECK-NEXT:    nop
; CHECK-NEXT:    ret
; CHECK-NEXT:    restore
entry:
  %cond = icmp eq i32 %sel, 0
  br i1 %cond, label %tbb, label %fbb

fbb:
  call void @f2()
  br label %end

tbb:
  call void @f1()
  br label %end

end:
  call void @f3()
  ret void
}

define void @l(i64 %sel) {
; CHECK-LABEL: l:
; CHECK:         .cfi_startproc
; CHECK-NEXT:  ! %bb.0: ! %entry
; CHECK-NEXT:    save %sp, -176, %sp
; CHECK-NEXT:    .cfi_def_cfa_register %fp
; CHECK-NEXT:    .cfi_window_save
; CHECK-NEXT:    .cfi_register %o7, %i7
; CHECK-NEXT:    cmp %i0, 0
; CHECK-NEXT:    be %xcc, .LBB1_2
; CHECK-NEXT:    nop
; CHECK-NEXT:  ! %bb.1: ! %fbb
; CHECK-NEXT:    call f2
; CHECK-NEXT:    nop
; CHECK-NEXT:    ba .LBB1_3
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB1_2: ! %tbb
; CHECK-NEXT:    call f1
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB1_3: ! %end
; CHECK-NEXT:    call f3
; CHECK-NEXT:    nop
; CHECK-NEXT:    ret
; CHECK-NEXT:    restore
entry:
  %cond = icmp eq i64 %sel, 0
  br i1 %cond, label %tbb, label %fbb

fbb:
  call void @f2()
  br label %end

tbb:
  call void @f1()
  br label %end

end:
  call void @f3()
  ret void
}

declare void @f1(...)

declare void @f2(...)

declare void @f3(...)
