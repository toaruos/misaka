#pragma once
#include <kernel/types.h>

size_t arch_cpu_mhz(void);

const char * arch_get_cmdline(void);
const char * arch_get_loader(void);

void arch_enter_critical(void);
void arch_exit_critical(void);

void arch_pause(void);
void arch_fatal(void);

void arch_set_tls_base(uintptr_t tlsbase);
long arch_reboot(void);
