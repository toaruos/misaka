/**
 * @file kernel/arch/x86_64/mmu.c
 * @brief Memory management facilities for x86-64
 */
#include <stdint.h>
#include <kernel/string.h>
#include <kernel/printf.h>
#include <kernel/spinlock.h>
#include <kernel/arch/x86_64/pml.h>
#include <kernel/arch/x86_64/mmu.h>

/**
 * bitmap page allocator for 4KiB pages
 */
static uint32_t *frames;
static uint32_t nframes;

#define INDEX_FROM_BIT(b)  ((b) >> 5)
#define OFFSET_FROM_BIT(b) ((b) & 0x1F)

void mmu_frame_set(uintptr_t frame_addr) {
	/* If the frame is within bounds... */
	if (frame_addr < nframes * 4 * 0x400) {
		uint64_t frame  = frame_addr >> 12;
		uint64_t index  = INDEX_FROM_BIT(frame);
		uint32_t offset = OFFSET_FROM_BIT(frame);
		frames[index]  |= ((uint32_t)1 << offset);
	}
}

void mmu_frame_clear(uintptr_t frame_addr) {
	/* If the frame is within bounds... */
	if (frame_addr < nframes * 4 * 0x400) {
		uint64_t frame  = frame_addr >> 12;
		uint64_t index  = INDEX_FROM_BIT(frame);
		uint32_t offset = OFFSET_FROM_BIT(frame);
		frames[index]  &= ~((uint32_t)1 << offset);
	}
}

int mmu_frame_test(uintptr_t frame_addr) {
	if (!(frame_addr < nframes * 4 * 0x400)) return 0;
	uint64_t frame  = frame_addr >> 12;
	uint64_t index  = INDEX_FROM_BIT(frame);
	uint32_t offset = OFFSET_FROM_BIT(frame);
	return !!(frames[index] & ((uint32_t)1 << offset));
}

static spin_lock_t frame_alloc_lock = { 0 };
static spin_lock_t kheap_lock = { 0 };

uintptr_t mmu_first_n_frames(int n) {
	for (uint64_t i = 0; i < nframes * 0x1000; i += 0x1000) {
		int bad = 0;
		for (int j = 0; j < n; ++j) {
			if (mmu_frame_test(i + 0x1000 * j)) {
				bad = j + 1;
			}
		}
		if (!bad) {
			return i / 0x1000;
		}
	}
	return (uintptr_t)-1;
}

uintptr_t mmu_first_frame(void) {
	uintptr_t i, j;
	for (i = 0; i < INDEX_FROM_BIT(nframes); ++i) {
		if (frames[i] != (uint32_t)-1) {
			for (j = 0; j < (sizeof(uint32_t)*8); ++j) {
				uint32_t testFrame = (uint32_t)1 << j;
				if (!(frames[i] & testFrame)) return (i << 5) + j;
			}
		}
	}

	printf("error: out allocatable frames\n");
	while (1) {};
	return (uintptr_t)-1;
}

void mmu_frame_allocate(union PML * page, unsigned int flags) {
	if (page->bits.page != 0) {
		page->bits.size     = 0;
		page->bits.present  = 1;
		page->bits.writable = (flags & MMU_FLAG_WRITABLE) ? 1 : 0;
		page->bits.user     = (flags & MMU_FLAG_KERNEL)   ? 0 : 1;
		/* TODO NX, etc. */
	} else {
		spin_lock(frame_alloc_lock);
		uintptr_t index = mmu_first_frame();
		mmu_frame_set(index << 12);
		page->bits.size     = 0;
		page->bits.page     = index;
		page->bits.present  = 1;
		page->bits.writable = (flags & MMU_FLAG_WRITABLE) ? 1 : 0;
		page->bits.user     = (flags & MMU_FLAG_KERNEL)   ? 0 : 1;
		spin_unlock(frame_alloc_lock);
	}
}

void mmu_frame_map_address(union PML * page, unsigned int flags, uintptr_t physAddr) {
	page->bits.size     = 0;
	page->bits.present  = 1;
	page->bits.writable = (flags & MMU_FLAG_WRITABLE) ? 1 : 0;
	page->bits.user     = (flags & MMU_FLAG_KERNEL)   ? 0 : 1;
	page->bits.page     = physAddr >> 12;
	mmu_frame_set(physAddr);
}

/* Initial memory maps loaded by boostrap */
union PML init_page_region[2][512] __attribute__((aligned(0x1000))) = {0};

union PML high_base_pml[512] __attribute__((aligned(0x1000))) = {0};
union PML heap_base_pml[512] __attribute__((aligned(0x1000))) = {0};

/* Direct mapping of low memory */
union PML low_base_pmls[20][512] __attribute__((aligned(0x1000)))  = {0};
extern uint32_t * framebuffer;

union PML * current_pml = (union PML *)&init_page_region[0];

/**
 * Find the physical address at a given virtual address.
 */
uintptr_t mmu_map_to_physical(uintptr_t virtAddr) {
	uintptr_t realBits = virtAddr & 0xFFFFffffFFFFUL;
	uintptr_t pageAddr = realBits >> 12;
	unsigned int pml4_entry = (pageAddr >> 27) & 0x1FF;
	unsigned int pdp_entry  = (pageAddr >> 18) & 0x1FF;
	unsigned int pd_entry   = (pageAddr >> 9)  & 0x1FF;
	unsigned int pt_entry   = (pageAddr) & 0x1FF;

	union PML * root = current_pml;

	/* Get the PML4 entry for this address */
	if (!root[pml4_entry].bits.present) return (uintptr_t)-1;

	union PML * pdp = (union PML *)((uintptr_t)0xFFFFffff00000000UL | (root[pml4_entry].bits.page << 12));

	if (!pdp[pdp_entry].bits.present) return (uintptr_t)-2;
	if (pdp[pdp_entry].bits.size) return (pdp[pdp_entry].bits.page << 12) | (virtAddr & 0x3fffffff);

	union PML * pd = (union PML *)((uintptr_t)0xFFFFffff00000000UL | (pdp[pdp_entry].bits.page << 12));

	if (!pd[pd_entry].bits.present) return (uintptr_t)-3;
	if (pd[pd_entry].bits.size) return (pd[pd_entry].bits.page << 12) | (virtAddr & 0x1FFFFF);

	union PML * pt = (union PML *)((uintptr_t)0xFFFFffff00000000UL | (pd[pd_entry].bits.page << 12));

	if (!pt[pt_entry].bits.present) return (uintptr_t)-4;
	return (pt[pt_entry].bits.page << 12) | (virtAddr & 0xFFF);
}

union PML * mmu_get_page(uintptr_t virtAddr, int flags) {
	uintptr_t realBits = virtAddr & 0xFFFFffffFFFFUL;
	uintptr_t pageAddr = realBits >> 12;
	unsigned int pml4_entry = (pageAddr >> 27) & 0x1FF;
	unsigned int pdp_entry  = (pageAddr >> 18) & 0x1FF;
	unsigned int pd_entry   = (pageAddr >> 9)  & 0x1FF;
	unsigned int pt_entry   = (pageAddr) & 0x1FF;

	union PML * root = current_pml;

	/* Get the PML4 entry for this address */
	if (!root[pml4_entry].bits.present) {
		if (!(flags & MMU_GET_MAKE)) return NULL;
		spin_lock(frame_alloc_lock);
		uintptr_t newPage = mmu_first_frame() << 12;
		mmu_frame_set(newPage);
		spin_unlock(frame_alloc_lock);
		/* zero it */
		memset((void*)(0xFFFFffff00000000UL | newPage), 0, 4096);
		root[pml4_entry].raw = (newPage) | 0x07;
	}

	union PML * pdp = (union PML *)((uintptr_t)0xFFFFffff00000000UL | (root[pml4_entry].bits.page << 12));

	if (!pdp[pdp_entry].bits.present) {
		if (!(flags & MMU_GET_MAKE)) return NULL;
		spin_lock(frame_alloc_lock);
		uintptr_t newPage = mmu_first_frame() << 12;
		mmu_frame_set(newPage);
		spin_unlock(frame_alloc_lock);
		/* zero it */
		memset((void*)(0xFFFFffff00000000UL | newPage), 0, 4096);
		pdp[pdp_entry].raw = (newPage) | 0x07;
	}

	if (pdp[pdp_entry].bits.size) {
		printf("Warning: Tried to get page for a 1GiB page!\n");
		return NULL;
	}

	union PML * pd = (union PML *)((uintptr_t)0xFFFFffff00000000UL | (pdp[pdp_entry].bits.page << 12));

	if (!pd[pd_entry].bits.present) {
		if (!(flags & MMU_GET_MAKE)) return NULL;
		spin_lock(frame_alloc_lock);
		uintptr_t newPage = mmu_first_frame() << 12;
		mmu_frame_set(newPage);
		spin_unlock(frame_alloc_lock);
		/* zero it */
		memset((void*)(0xFFFFffff00000000UL | newPage), 0, 4096);
		pd[pd_entry].raw = (newPage) | 0x07;
	}

	if (pd[pd_entry].bits.size) {
		printf("Warning: Tried to get page for a 2MiB page!\n");
		return NULL;
	}

	union PML * pt = (union PML *)((uintptr_t)0xFFFFffff00000000UL | (pd[pd_entry].bits.page << 12));
	return (union PML *)&pt[pt_entry];
}

union PML * mmu_clone(union PML * from) {
	/* Clone the current PMLs... */
	if (!from) from = current_pml;

	/* First get a page for ourselves. */
	spin_lock(frame_alloc_lock);
	uintptr_t newPage = mmu_first_frame() << 12;
	mmu_frame_set(newPage);
	spin_unlock(frame_alloc_lock);
	union PML * pml4_out = (union PML*)(0xFFFFffff00000000UL | newPage);

	/* Zero bottom half */
	memset(&pml4_out[0], 0, 256 * sizeof(union PML));

	/* Copy top half */
	memcpy(&pml4_out[256], &from[256], 256 * sizeof(union PML));

	/* Copy PDPs */
	for (size_t i = 0; i < 256; ++i) {
		if (from[i].bits.present) {
			union PML * pdp_in = (union PML*)(0xFFFFffff00000000UL | (from[i].bits.page << 12));
			spin_lock(frame_alloc_lock);
			uintptr_t newPage = mmu_first_frame() << 12;
			mmu_frame_set(newPage);
			spin_unlock(frame_alloc_lock);
			union PML * pdp_out = (union PML*)(0xFFFFffff00000000UL | newPage);
			memset(pdp_out, 0, 512 * sizeof(union PML));
			pml4_out[i].raw = (newPage) | 0x07;

			/* Copy the PDs */
			for (size_t j = 0; j < 512; ++j) {
				if (pdp_in[j].bits.present) {
					union PML * pd_in = (union PML*)(0xFFFFffff00000000UL | (pdp_in[j].bits.page << 12));
					spin_lock(frame_alloc_lock);
					uintptr_t newPage = mmu_first_frame() << 12;
					mmu_frame_set(newPage);
					spin_unlock(frame_alloc_lock);
					union PML * pd_out = (union PML*)(0xFFFFffff00000000UL | newPage);
					memset(pd_out, 0, 512 * sizeof(union PML));
					pdp_out[j].raw = (newPage) | 0x07;

					/* Now copy the PTs */
					for (size_t k = 0; k < 512; ++k) {
						if (pd_in[k].bits.present) {
							union PML * pt_in = (union PML*)(0xFFFFffff00000000UL | (pd_in[k].bits.page << 12));
							spin_lock(frame_alloc_lock);
							uintptr_t newPage = mmu_first_frame() << 12;
							mmu_frame_set(newPage);
							spin_unlock(frame_alloc_lock);
							union PML * pt_out = (union PML*)(0xFFFFffff00000000UL | newPage);
							memset(pt_out, 0, 512 * sizeof(union PML));
							pd_out[k].raw = (newPage) | 0x07;

							/* Now, finally, copy pages */
							for (size_t l = 0; l < 512; ++l) {
								uintptr_t address = ((i << (9 * 3 + 12)) | (j << (9*2 + 12)) | (k << (9 + 12)) | (l << 12));
								if (address >= 0x200000000 && address <= 0x400000000) continue;
								if (pt_in[l].bits.present) {
									if (pt_in[l].bits.user) {
										char * page_in = (char*)(0xFFFFffff00000000UL | (pt_in[l].bits.page << 12));
										spin_lock(frame_alloc_lock);
										uintptr_t newPage = mmu_first_frame() << 12;
										mmu_frame_set(newPage);
										spin_unlock(frame_alloc_lock);
										char * page_out = (char *)(0xFFFFffff00000000UL | newPage);
										memcpy(page_out,page_in,4096);
										pt_out[l].bits.page = newPage >> 12;
										pt_out[l].bits.present = 1;
										pt_out[l].bits.user = 1;
										pt_out[l].bits.writable = pt_in[l].bits.writable;
										pt_out[l].bits.writethrough = pt_out[l].bits.writethrough;
										pt_out[l].bits.accessed = pt_out[l].bits.accessed;
										pt_out[l].bits.size = pt_out[l].bits.size;
										pt_out[l].bits.global = pt_out[l].bits.global;
										pt_out[l].bits.nx = pt_out[l].bits.nx;
									} else {
										/* If it's not a user page, just copy directly */
										pt_out[l].raw = pt_in[l].raw;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return pml4_out;
}

uintptr_t mmu_allocate_a_frame(void) {
	spin_lock(frame_alloc_lock);
	uintptr_t index = mmu_first_frame();
	mmu_frame_set(index << 12);
	spin_unlock(frame_alloc_lock);
	return index;
}

uintptr_t mmu_allocate_n_frames(int n) {
	spin_lock(frame_alloc_lock);
	uintptr_t index = mmu_first_n_frames(n);
	for (int i = 0; i < n; ++i) {
		mmu_frame_set((index+i) << 12);
	}
	spin_unlock(frame_alloc_lock);
	return index;
}

/**
 * TODO:
 * Both of these can check _just_ the right ranges...
 */
size_t mmu_count_user(union PML * from) {
	size_t out = 0;

	for (size_t i = 0; i < 256; ++i) {
		if (from[i].bits.present) {
			union PML * pdp_in = (union PML*)(0xFFFFffff00000000UL | (from[i].bits.page << 12));
			for (size_t j = 0; j < 512; ++j) {
				if (pdp_in[j].bits.present) {
					union PML * pd_in = (union PML*)(0xFFFFffff00000000UL | (pdp_in[j].bits.page << 12));
					for (size_t k = 0; k < 512; ++k) {
						if (pd_in[k].bits.present) {
							union PML * pt_in = (union PML*)(0xFFFFffff00000000UL | (pd_in[k].bits.page << 12));
							for (size_t l = 0; l < 512; ++l) {
								/* Calculate final address to skip SHM */
								uintptr_t address = ((i << (9 * 3 + 12)) | (j << (9*2 + 12)) | (k << (9 + 12)) | (l << 12));
								if (address >= 0x200000000 && address <= 0x400000000) continue;
								if (pt_in[l].bits.present) {
									if (pt_in[l].bits.user) {
										out++;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return out;
}

size_t mmu_count_shm(union PML * from) {
	size_t out = 0;

	for (size_t i = 0; i < 256; ++i) {
		if (from[i].bits.present) {
			union PML * pdp_in = (union PML*)(0xFFFFffff00000000UL | (from[i].bits.page << 12));
			for (size_t j = 0; j < 512; ++j) {
				if (pdp_in[j].bits.present) {
					union PML * pd_in = (union PML*)(0xFFFFffff00000000UL | (pdp_in[j].bits.page << 12));
					for (size_t k = 0; k < 512; ++k) {
						if (pd_in[k].bits.present) {
							union PML * pt_in = (union PML*)(0xFFFFffff00000000UL | (pd_in[k].bits.page << 12));
							for (size_t l = 0; l < 512; ++l) {
								/* Calculate final address to skip SHM */
								uintptr_t address = ((i << (9 * 3 + 12)) | (j << (9*2 + 12)) | (k << (9 + 12)) | (l << 12));
								if (address < 0x200000000 || address > 0x400000000) continue;
								if (pt_in[l].bits.present) {
									if (pt_in[l].bits.user) {
										out++;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return out;
}

size_t mmu_total_memory(void) {
	return nframes * 4;
}

size_t mmu_used_memory(void) {
	size_t ret = 0;
	size_t i, j;
	for (i = 0; i < INDEX_FROM_BIT(nframes); ++i) {
		for (j = 0; j < 32; ++j) {
			uint32_t testFrame = (uint32_t)0x1 << j;
			if (frames[i] & testFrame) {
				ret++;
			}
		}
	}
	return ret * 4;
}

void mmu_free(union PML * from) {
	if (!from) {
		printf("can't clear NULL directory\n");
		return;
	}

	for (size_t i = 0; i < 256; ++i) {
		if (from[i].bits.present) {
			union PML * pdp_in = (union PML*)(0xFFFFffff00000000UL | (from[i].bits.page << 12));
			for (size_t j = 0; j < 512; ++j) {
				if (pdp_in[j].bits.present) {
					union PML * pd_in = (union PML*)(0xFFFFffff00000000UL | (pdp_in[j].bits.page << 12));
					for (size_t k = 0; k < 512; ++k) {
						if (pd_in[k].bits.present) {
							union PML * pt_in = (union PML*)(0xFFFFffff00000000UL | (pd_in[k].bits.page << 12));
							for (size_t l = 0; l < 512; ++l) {
								uintptr_t address = ((i << (9 * 3 + 12)) | (j << (9*2 + 12)) | (k << (9 + 12)) | (l << 12));
								if (address >= 0x200000000 && address <= 0x400000000) continue;
								if (pt_in[l].bits.present) {
									if (pt_in[l].bits.user) {
										mmu_frame_clear(pt_in[l].bits.page << 12);
									}
								}
							}
							mmu_frame_clear(pd_in[k].bits.page << 12);
						}
					}
					mmu_frame_clear(pdp_in[j].bits.page << 12);
				}
			}
			mmu_frame_clear(from[i].bits.page << 12);
		}
	}

	mmu_frame_clear((((uintptr_t)from) & 0xFFFFFFFF));
}

union PML * mmu_get_kernel_directory(void) {
	return (union PML*)((uintptr_t)&init_page_region[0] | 0xFFFFffff00000000UL);
}

void mmu_set_directory(union PML * new_pml) {
	if (!new_pml) new_pml = (union PML*)((uintptr_t)&init_page_region[0] | 0xFFFFffff00000000UL);
	current_pml = new_pml;

	asm volatile (
		"movq %0, %%cr3"
		: : "r"((uintptr_t)new_pml & 0xFFFFffff));
}

void mmu_invalidate(uintptr_t addr) {
	asm volatile (
		"invlpg (%0)"
		: : "r"(addr));
}

static char * heapStart = NULL;

/**
 * @brief Switch from the boot-time 1GiB-page identity map to 4KiB pages.
 */
void mmu_init(size_t memsize) {

	/* Map the high base PDP */
	init_page_region[0][511].raw = (uintptr_t)&high_base_pml | 0x03;
	init_page_region[0][510].raw = (uintptr_t)&heap_base_pml | 0x03;

	/* Identity map -4GB in the boot PML using 1GB pages */
	high_base_pml[508].raw = (uintptr_t)0x00000000 | 0x83;
	high_base_pml[509].raw = (uintptr_t)0x40000000 | 0x83;
	high_base_pml[510].raw = (uintptr_t)0x80000000 | 0x83;
	high_base_pml[511].raw = (uintptr_t)0xC0000000 | 0x83;

	/* Map low base PDP */
	low_base_pmls[0][0].raw = (uintptr_t)&low_base_pmls[1] | 0x07;

	/* Map 32MiB of low memory directly, this is where we're loaded. */
	for (int j = 0; j < 16; ++j) {
		low_base_pmls[1][j].raw = (uintptr_t)&low_base_pmls[2+j] | 0x03;
		for (int i = 0; i < 512; ++i) {
			low_base_pmls[2+j][i].raw = (uintptr_t)(0x200000 * j + 0x1000 * i) | 0x03;
		}
	}

	/* Unmap null */
	low_base_pmls[2][0].raw = 0;

	/* Now map our new low base */
	init_page_region[0][0].raw = (uintptr_t)&low_base_pmls[0] | 0x07;

	/* Use input from bootloader to initialize physical page frame allocator */
	nframes = (memsize / 0x1000);
	frames = malloc(INDEX_FROM_BIT(nframes * 8));
	memset(frames, 0, INDEX_FROM_BIT(nframes * 8));

	/* Mark the currently-in-use low memory pages as allocated, based on the current heap. */
	unsigned int i = 0;
	for (; i < ((uintptr_t)heapStart / 0x1000) / 32; i++) {
		frames[i] = (uint32_t)-1;
	}
	for (size_t j = i * 32 * 0x1000; j < (uintptr_t)heapStart; j++) {
		mmu_frame_set(j);
	}

	/* From here on out, kernel heap allocations are in high memory. */
	mmu_set_kernel_heap(0xFFFFff0000000000);

	/* And physical memory references, like page tables, are through the 4GiB window. */
	current_pml = (union PML*)((uintptr_t)current_pml | 0xFFFFffff00000000UL);
}

void * sbrk(size_t bytes) {
	if (!heapStart) {
		printf("Heap is not yet available, but sbrk() was called.\n");
		return NULL;
	}

	if (bytes & 0xFFF) {
		printf("Invalid sbrk() call detected.\n");
		while (1) {};
	}

	if (!bytes) {
		return heapStart;
	}

	spin_lock(kheap_lock);
	void * out = heapStart;
	if ((uintptr_t)heapStart >= 0x800000000) {
		for (uintptr_t p = (uintptr_t)out; p < (uintptr_t)out + bytes; p += 0x1000) {
			union PML * page = mmu_get_page(p, MMU_GET_MAKE);
			mmu_frame_allocate(page, MMU_FLAG_WRITABLE | MMU_FLAG_KERNEL);
			mmu_invalidate(p);
		}
	}

	heapStart += bytes;
	spin_unlock(kheap_lock);
	return out;
}

void mmu_set_kernel_heap(uintptr_t heap_start) {
	if (heap_start & 0xFFF) {
		heap_start += 0x1000 - (heap_start & 0xFFF);
	}
	heapStart = (char*)heap_start;
}
