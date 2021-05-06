#include <stdint.h>
#include <kernel/types.h>
#include <kernel/process.h>
#include <kernel/string.h>
#include <kernel/printf.h>

/**
 * @brief A tasklet is a kernel thread.
 */

extern void arch_enter_critical(void);
extern void arch_exit_critical(void);

typedef void (*tasklet_t) (void*,char*);

int create_kernel_tasklet(tasklet_t tasklet, const char * name, void * argp) {
	arch_enter_critical();

	arch_exit_critical();
}
