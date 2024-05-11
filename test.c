#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/unistd.h>

#define NR_ROUNDS	2048

int main(void)
{
	uint64_t result = 0;

	/* warm-up */
	for (int i = 0; i < 10; i++)
		syscall(__NR_kprobe_bench, 2);

	/* Now benchmark it */
	for (int i = 0; i < NR_ROUNDS; i++)
		result += syscall(__NR_kprobe_bench, 2);

	printf("Avg kprobe time (CPU cycles): %lu\n", result / NR_ROUNDS);

	return 0;
}
