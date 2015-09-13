#include <types.h>
#include <string.h>
#include <symboltable.h>


/* Cannot use symboltable here because symbol_find is used during initialization
 * of IRQs and ISRs.
 */
void (* symbol_find(const char * name))(void) {
	kernel_symbol_t * k = (kernel_symbol_t *)&kernel_symbols_start;

	while ((uintptr_t)k < (uintptr_t)&kernel_symbols_end) {
		if (strcmp(k->name, name)) {
			k = (kernel_symbol_t *)((uintptr_t)k + sizeof *k + strlen(k->name) + 1);
			continue;
		}
		return (void (*)(void))k->addr;
	}

	return NULL;
}

