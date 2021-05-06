#include <stdint.h>
#include <kernel/printf.h>
#include <kernel/arch/x86_64/acpi.h>

void acpi_initialize(void) {
	/* ACPI */
	uintptr_t scan;
	int good = 0;
	for (scan = 0x000E0000; scan < 0x00100000; scan += 16) {
		char * _scan = (char *)(scan | 0xFFFFFFFF00000000);
		if (_scan[0] == 'R' &&
			_scan[1] == 'S' &&
			_scan[2] == 'D' &&
			_scan[3] == ' ' &&
			_scan[4] == 'P' &&
			_scan[5] == 'T' &&
			_scan[6] == 'R') {
			good = 1;
			break;
		}
	}

	if (good) {
		struct rsdp_descriptor * rsdp = (struct rsdp_descriptor *)scan;
		printf("ACPI RSDP found at 0x%016lx; ", scan);
		printf("ACPI revision %d.0; ", rsdp->revision + 1);

		uint8_t check = 0;
		uint8_t * tmp;
		for (tmp = (uint8_t *)scan; (uintptr_t)tmp < scan + sizeof(struct rsdp_descriptor); tmp++) {
			check += *tmp;
		}
		if (check != 0) {
			printf("Bad checksum? %d\n", check);
		}

		printf("OEMID: %c%c%c%c%c%c; ",
				rsdp->oemid[0],
				rsdp->oemid[1],
				rsdp->oemid[2],
				rsdp->oemid[3],
				rsdp->oemid[4],
				rsdp->oemid[5]);

		printf("RSDT address: 0x%08x; ", rsdp->rsdt_address);

		struct rsdt * rsdt = (struct rsdt *)(uintptr_t)rsdp->rsdt_address;
		printf("RSDT length: %d; ", rsdt->header.length);
		printf("RSDT checksum %s\n", acpi_checksum((struct acpi_sdt_header *)rsdt) ? "passed" : "failed");
	}
}
