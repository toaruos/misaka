#include <kernel/types.h>
#include <kernel/spinlock.h>
#include <kernel/process.h>

void spin_init(spin_lock_t lock) {
	lock[0] = 0;
	lock[1] = 0;
}

void spin_lock(spin_lock_t lock) {
	while (__sync_lock_test_and_set(lock, 0x01));
}

void spin_unlock(spin_lock_t lock) {
	__sync_lock_release(lock);
}
