/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Kernel Probes NOP Optimization (KPROBE_NOP_OPT)
 *
 * Copyright (C) IBM Corporation, 2023
 * Copyright (C) UIUC, 2023
 * Jinghao Jia <jinghao7@illinois.edu>
 */

#include <linux/linkage.h>
#include <asm/segment.h>

    .code64
    .section .text, "ax"

/* Trampoline used by nop-opt */
SYM_FUNC_START(kprobe_nop_tramp)
	/* construct the pt_regs on stack */
	/* Looks like segment selector should point to kernel DS */
    push $__KERNEL_DS /* a0 */
	push %rsp /* 98 */
	pushf /* 90 */
	/* Save the rest of regs except orig_ax, ip, and cs */
	sub $24, %rsp
	push %rdi /* 70 */
	push %rsi /* 68 */
	push %rdx /* 60 */
	push %rcx /* 58 */
	push %rax /* 50 */
	push %r8 /* 48 */
	push %r9 /* 40 */
	push %r10 /* 38 */
	push %r11 /* 30 */
	push %rbx /* 28 */
	push %rbp /* 20 */
	push %r12 /* 18 */
	push %r13 /* 10 */
	push %r14 /* 08 */
	push %r15 /* 00 */
	/* call kprobe_nop_callback(ip, regs) */
	mov 0xa8(%rsp), %rdi
	mov %rsp, %rsi
	call kprobe_nop_callback
	/* Copy 'regs->flags' into 'regs->ss'. */
	mov 0x90(%rsp), %rdx
	mov %rdx, 0xa0(%rsp)
	/* restore registers */
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %rbp
	pop %rbx
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rax
	pop %rcx
	pop %rdx
	pop %rsi
	pop %rdi
	/* Skip over orig_ax, ip, cs, flags, and sp */
	add $40, %rsp
	/* And pop flags register from 'regs->ss'. */
	popf

    RET
SYM_FUNC_END(kprobe_nop_tramp)
