#include <kernel/string.h>

unsigned short * memsetw(unsigned short * dest, unsigned short val, int count) {
	int i = 0;
	for ( ; i < count; ++i ) {
		dest[i] = val;
	}
	return dest;
}

void * memcpy(void * restrict dest, const void * restrict src, size_t n) {
	asm volatile("rep movsb"
	            : "=c"((int){0})
	            : "D"(dest), "S"(src), "c"(n)
	            : "flags", "memory");
	return dest;
}


size_t strlen(const char * s) {
	const char * a = s;
	const size_t * w;
	for (; (uintptr_t)s % ALIGN; s++) {
		if (!*s) {
			return s-a;
		}
	}
	for (w = (const void *)s; !HASZERO(*w); w++);
	for (s = (const void *)w; *s; s++);
	return s-a;
}


int strcmp(const char * a, const char * b) {
	uint32_t i = 0;
	while (1) {
		if (a[i] < b[i]) {
			return -1;
		} else if (a[i] > b[i]) {
			return 1;
		} else {
			if (a[i] == '\0') {
				return 0;
			}
			++i;
		}
	}
}
