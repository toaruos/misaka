/**
 * @file kernel/arch/x86_64/mmu.c
 * @brief Memory management facilities for x86-64
 */
#include <stdint.h>
#include <kernel/string.h>
#include <kernel/printf.h>
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
		/* TODO lock */
		uintptr_t index = mmu_first_frame();
		mmu_frame_set(index << 12);
		page->bits.size     = 0;
		page->bits.page     = index;
		page->bits.present  = 1;
		page->bits.writable = (flags & MMU_FLAG_WRITABLE) ? 1 : 0;
		page->bits.user     = (flags & MMU_FLAG_KERNEL)   ? 0 : 1;
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

void mmu_frame_free(union PML * page) {
	uint64_t frame;
	if (!(frame = page->bits.page)) {
		printf("error: attempted to free bad page?");
		while (1) {};
		return;
	}

	mmu_frame_clear(frame << 12);
	page->bits.page = 0;
}

/* Initial memory maps loaded by boostrap */
union PML init_page_region[2][512] __attribute__((aligned(0x1000))) = {0};

union PML high_base_pml[512] __attribute__((aligned(0x1000))) = {0};

/* Direct mapping of low memory */
union PML low_base_pmls[20][512] __attribute__((aligned(0x1000)))  = {0};
extern uint32_t * framebuffer;

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

	union PML * root = (union PML *)&init_page_region[0]; /* temporary */

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

	union PML * root = (union PML *)&init_page_region[0]; /* temporary */

	/* Get the PML4 entry for this address */
	if (!root[pml4_entry].bits.present) {
		if (!(flags & MMU_GET_MAKE)) return NULL;
		uintptr_t newPage = mmu_first_frame() << 12;
		mmu_frame_set(newPage);
		/* zero it */
		memset((void*)(0xFFFFffff00000000UL | newPage), 0, 4096);
		root[pml4_entry].raw = (newPage) | 0x07;
	}

	union PML * pdp = (union PML *)((uintptr_t)0xFFFFffff00000000UL | (root[pml4_entry].bits.page << 12));

	if (!pdp[pdp_entry].bits.present) {
		if (!(flags & MMU_GET_MAKE)) return NULL;
		uintptr_t newPage = mmu_first_frame() << 12;
		mmu_frame_set(newPage);
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
		uintptr_t newPage = mmu_first_frame() << 12;
		mmu_frame_set(newPage);
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

/**
 * @brief Switch from the boot-time 1GiB-page identity map to 4KiB pages.
 */
void mmu_init(void) {

	/* Map the high base PDP */
	init_page_region[0][511].raw = (uintptr_t)&high_base_pml | 0x03;

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

	/* Now adjust the framebuffer address so it is directly in the 4GiB identity map region */
	framebuffer = (uint32_t*)((uintptr_t)framebuffer | 0xFFFFffff00000000);

	/* Now map our new low base */
	init_page_region[0][0].raw = (uintptr_t)&low_base_pmls[0] | 0x07;

	/* Set up page allocation bitmap for 1GiB of pages FIXME use actual memory amount */
	nframes = (1024 * 256); /* XXX this is 1GiB */
	frames = malloc(INDEX_FROM_BIT(nframes * 8));
	memset(frames, 0, INDEX_FROM_BIT(nframes * 8));

	/* Mark 32MiB of low memory as unavailable */
	for (unsigned int i = 0; i < 256; ++i) {
		frames[i] = (uint32_t)-1;
	}

}
