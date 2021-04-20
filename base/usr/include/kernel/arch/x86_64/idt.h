#pragma once

#include <kernel/types.h>

typedef struct {
	uint16_t base_low;
	uint16_t sel;
	uint8_t zero;
	uint8_t flags;
	uint16_t base_high;
	uint32_t base_higher;
	uint32_t reserved;
} __attribute__((packed)) idt_entry_t;
