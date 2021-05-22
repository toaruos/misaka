#include <kernel/types.h>
#include <kernel/spinlock.h>
#include <kernel/process.h>

void spin_init(spin_lock_t lock) {
	lock[0] = 0;
	lock[1] = 0;
}

