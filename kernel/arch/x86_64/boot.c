#include <kernel/types.h>
#include <kernel/arch/x86_64/pml.h>

/* One for PML4, one for 1GB pages */
union PML init_page_region[2][512] __attribute__((aligned(0x1000))) = {0};
