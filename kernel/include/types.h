#ifndef _TYPES_H
#define _TYPES_H

#include <limits.h>

#define asm __asm__
#define volatile __volatile__

typedef unsigned long long uint64_t;
typedef unsigned long uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

typedef unsigned long long size_t;
typedef uint64_t uintptr_t;

#define ALIGN (sizeof(size_t))

#define UINT64_MAX 0xFFFFFFFFFFFFFFFF
#define UINT32_MAX 0xFFFFFFFF

#define NULL 0

#define ONES ((size_t)-1/UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX/2+1))
#define HASZERO(X) (((X)-ONES) & ~(X) & HIGHS)

#endif /* _TYPES_H */
