#ifndef _TYPES_H
#define _TYPES_H

#include <limits.h>
#include <stdint.h>

#define asm __asm__
#define volatile __volatile__

typedef unsigned long long size_t;

#define ALIGN (sizeof(size_t))

#define NULL ((void *)0UL)

#define ONES ((size_t)-1/UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX/2+1))
#define HASZERO(X) (((X)-ONES) & ~(X) & HIGHS)

#endif /* _TYPES_H */
