// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Kernel Probes NOP Optimization (KPROBE_NOP_OPT)
 *
 * Copyright (C) IBM Corporation, 2023
 * Copyright (C) UIUC, 2023
 * Jinghao Jia <jinghao7@illinois.edu>
 */

#include <linux/kprobes.h>
#include <linux/memory.h>
#include <asm/text-patching.h>

/* We are using the same trick as ftrace/mcount */
#define OPT_NOP_SIZE	MCOUNT_INSN_SIZE

const char opt_nop5[] = {0x0f, 0x1f, 0x44, 0x00, 0x08};

extern void kprobe_nop_tramp(void);

static int can_nop_opt(char *addr)
{
	char *nop_addr = addr - OPT_NOP_SIZE;
	char nop_code[MCOUNT_INSN_SIZE];

	/*
	 * Note:
	 * We are paranoid about modifying text, as if a bug was to happen, it
	 * could cause us to read or write to someplace that could cause harm.
	 * Carefully read and modify the code with probe_kernel_*(), and make
	 * sure what we read is what we expected it to be before modifying it.
	 */
	/* read the text we want to modify */
	if (copy_from_kernel_nofault(nop_code, nop_addr, OPT_NOP_SIZE)) {
		WARN_ON(1);
		return 0;
	}

	/* Check whether this insn has our nop before it */
	if (memcmp(nop_code, opt_nop5, OPT_NOP_SIZE) != 0) {
		return 0;
	}

	return 1;
}

int arch_prepare_nop_opt_kprobe(struct optimized_kprobe *op)
{
	if (!can_nop_opt(op->kp.addr))
		return -EILSEQ;

	op->optinsn.nop_opt = true;
	return 0;
}

void do_nop_opt(struct kprobe *p)
{
	const char *new;
	void *addr = p->addr - OPT_NOP_SIZE;

	lockdep_assert_held(&text_mutex);

	WARN_ON(kprobe_disabled(p));

	new = text_gen_insn(CALL_INSN_OPCODE, addr, kprobe_nop_tramp);

	/* First remove the int3, then create the call
	 */
	text_poke(p->addr, &p->opcode, INT3_INSN_SIZE);
	text_poke_sync();

	text_poke_bp(addr, new, OPT_NOP_SIZE, NULL);
}

void undo_nop_opt(struct kprobe *p)
{
	const char int3 = INT3_INSN_OPCODE;
	void *addr = p->addr - OPT_NOP_SIZE;

	lockdep_assert_held(&text_mutex);

	text_poke_bp(addr, opt_nop5, OPT_NOP_SIZE, NULL);

	text_poke(p->addr, &int3, INT3_INSN_SIZE);
	text_poke_sync();
}

void kprobe_nop_callback(unsigned long addr, struct pt_regs *regs)
{
	struct kprobe *kp;

	preempt_disable();
	kp = get_kprobe((void *)addr);

	/* This is possible if op is under delayed unoptimizing */
	if (kprobe_disabled(kp))
		goto out;

	if (kprobe_running()) {
		kprobes_inc_nmissed_count(kp);
	} else {
		struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();
		/* Adjust stack pointer
		 * We have decremented rsp by 16 (return addr and regs->ss)
		 */
		regs->sp += 2 * sizeof(long);
		/* Save skipped registers */
		regs->cs = __KERNEL_CS;
		regs->ip = addr + INT3_INSN_SIZE;
		regs->orig_ax = ~0UL;

		__this_cpu_write(current_kprobe, kp);
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;
		opt_pre_handler(kp, regs);
		__this_cpu_write(current_kprobe, NULL);
	}

out:
	preempt_enable();
}
NOKPROBE_SYMBOL(kprobe_nop_callback)