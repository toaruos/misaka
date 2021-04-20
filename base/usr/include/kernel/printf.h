#pragma once

#include <kernel/types.h>

extern int printf(const char *fmt, ...);
extern size_t (*printf_output)(size_t, uint8_t *);
