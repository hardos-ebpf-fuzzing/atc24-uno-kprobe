/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/syscalls.h>

static __always_inline u64 start(void)
{
    u64 t;
    asm volatile(
        "lfence\n\t"
        "rdtsc\n\t"
        "shl $32, %%rdx\n\t"
        "or %%rdx, %0\n\t"
        "lfence"
        : "=a"(t)
        :
        // "memory" avoids reordering. rdx = TSC >> 32.
        // "cc" = flags modified by SHL.
        : "rdx", "memory", "cc"
    );

    return t;
}

static __always_inline uint64_t stop(void)
{
    uint64_t t;
    asm volatile(
        "rdtscp\n\t"
        "shl $32, %%rdx\n\t"
        "or %%rdx, %0\n\t"
        "lfence"
        : "=a"(t)
        :
        // "memory" avoids reordering. rcx = TSC_AUX. rdx = TSC >> 32.
        // "cc" = flags modified by SHL.
        : "rcx", "rdx", "memory", "cc"
    );

    return t;
}

static int noinline kprobe_bench_test_func(int a)
{
    volatile u64 s = 0, e = 0;

    if (a == 2) {
        s = start();
        // Not jump-optimizable
        // asm volatile ("nop");
        // Neither boostable nor jump-optimizable
        asm volatile ("shr $1, %%r8b" ::: "r8b");
    }
    e = stop();

    return e - s;
}

SYSCALL_DEFINE1(kprobe_bench, int, a)
{
    u64 ret = 0;

    preempt_disable();

    ret = kprobe_bench_test_func(a);

    preempt_enable();

    return ret;
}