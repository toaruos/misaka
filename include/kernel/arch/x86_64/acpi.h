#ifndef _ARCH_X86_64_ACPI_H
#define _ARCH_X86_64_ACPI_H

#include <kernel/types.h>

struct rsdp_descriptor {
	char     signature[8];
	uint8_t  checksum;
	char     oemid[6];
	uint8_t  revision;
	uint32_t rsdt_address;
} __attribute__((packed));

struct rsdp_descriptor_20 {
	struct rsdp_descriptor base;

	uint32_t length;
	uint64_t xsdt_address;
	uint8_t  ext_checksum;
	uint8_t  _reserved[3];
} __attribute((packed));

struct acpi_sdt_header {
	char     signature[4];
	uint32_t length;
	uint8_t  revision;
	uint8_t  checksum;
	char     oemid[6];
	char     oem_tableid[8];
	uint32_t oem_revision;
	uint32_t creator_id;
	uint32_t creator_revision;
} __attribute__((packed));

struct rsdt {
	struct acpi_sdt_header header;
	uint32_t pointers[];
};

static inline int acpi_checksum(struct acpi_sdt_header * header) {
	uint8_t check = 0;
	for (size_t i = 0; i < header->length; ++i) {
		check += ((uint8_t *)header)[i];
	}
	return check == 0;
}

#endif /* _ARCH_X86_64_ACPI_H */
