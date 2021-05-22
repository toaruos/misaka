#pragma once

typedef volatile int spin_lock_t[2];
extern void spin_init(spin_lock_t lock);

#define spin_lock(lock) while (__sync_lock_test_and_set(lock, 0x01))
#define spin_unlock(lock) __sync_lock_release(lock)
