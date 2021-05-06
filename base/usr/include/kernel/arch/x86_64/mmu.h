#pragma once
#include <stdint.h>
#include <kernel/arch/x86_64/pml.h>
#define MMU_FLAG_KERNEL    0x01
#define MMU_FLAG_WRITABLE  0x02

#define MMU_GET_MAKE 0x01


void mmu_frame_set(uintptr_t frame_addr);
void mmu_frame_clear(uintptr_t frame_addr);
int mmu_frame_test(uintptr_t frame_addr);
uintptr_t mmu_first_n_frames(int n);
uintptr_t mmu_first_frame(void);
void mmu_frame_allocate(union PML * page, unsigned int flags);
void mmu_frame_map_address(union PML * page, unsigned int flags, uintptr_t physAddr);
void mmu_frame_free(union PML * page);
uintptr_t mmu_map_to_physical(uintptr_t virtAddr);
union PML * mmu_get_page(uintptr_t virtAddr, int flags);
void mmu_set_directory(union PML * new_pml);
void mmu_free(union PML * from);
union PML * mmu_clone(union PML * from);
void mmu_init(void);
