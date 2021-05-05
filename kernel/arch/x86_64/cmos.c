/**
 * @file kernel/arch/x86_64/cmos.c
 * @author K. Lange
 * @brief Real-time clock.
 */

#include <kernel/printf.h>
#include <kernel/string.h>
#include <kernel/arch/x86_64/ports.h>
#include <sys/time.h>

#define from_bcd(val)  ((val / 16) * 10 + (val & 0xf))
#define CMOS_ADDRESS   0x70
#define CMOS_DATA      0x71

enum {
	CMOS_SECOND = 0,
	CMOS_MINUTE = 2,
	CMOS_HOUR = 4,
	CMOS_DAY = 7,
	CMOS_MONTH = 8,
	CMOS_YEAR = 9
};

static void cmos_dump(uint16_t * values) {
	for (uint16_t index = 0; index < 128; ++index) {
		outportb(CMOS_ADDRESS, index);
		values[index] = inportb(CMOS_DATA);
	}
}

static int is_update_in_progress(void) {
	outportb(CMOS_ADDRESS, 0x0a);
	return inportb(CMOS_DATA) & 0x80;
}

static uint32_t secs_of_years(int years) {
	uint32_t days = 0;
	years += 2000;
	while (years > 1969) {
		days += 365;
		if (years % 4 == 0) {
			if (years % 100 == 0) {
				if (years % 400 == 0) {
					days++;
				}
			} else {
				days++;
			}
		}
		years--;
	}
	return days * 86400;
}

static uint32_t secs_of_month(int months, int year) {
	year += 2000;

	uint32_t days = 0;
	switch(months) {
		case 11:
			days += 30; /* fallthrough */
		case 10:
			days += 31; /* fallthrough */
		case 9:
			days += 30; /* fallthrough */
		case 8:
			days += 31; /* fallthrough */
		case 7:
			days += 31; /* fallthrough */
		case 6:
			days += 30; /* fallthrough */
		case 5:
			days += 31; /* fallthrough */
		case 4:
			days += 30; /* fallthrough */
		case 3:
			days += 31; /* fallthrough */
		case 2:
			days += 28;
			if ((year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0))) {
				days++;
			} /* fallthrough */
		case 1:
			days += 31; /* fallthrough */
		default:
			break;
	}
	return days * 86400;
}

uint32_t read_cmos(void) {
	uint16_t values[128];
	uint16_t old_values[128];

	while (is_update_in_progress());
	cmos_dump(values);

	do {
		memcpy(old_values, values, 128);
		while (is_update_in_progress());
		cmos_dump(values);
	} while ((old_values[CMOS_SECOND] != values[CMOS_SECOND]) ||
		(old_values[CMOS_MINUTE] != values[CMOS_MINUTE]) ||
		(old_values[CMOS_HOUR] != values[CMOS_HOUR])     ||
		(old_values[CMOS_DAY] != values[CMOS_DAY])       ||
		(old_values[CMOS_MONTH] != values[CMOS_MONTH])   ||
		(old_values[CMOS_YEAR] != values[CMOS_YEAR]));

	/* Math Time */
	uint32_t time =
		secs_of_years(from_bcd(values[CMOS_YEAR]) - 1) +
		secs_of_month(from_bcd(values[CMOS_MONTH]) - 1,
		from_bcd(values[CMOS_YEAR])) +
		(from_bcd(values[CMOS_DAY]) - 1) * 86400 +
		(from_bcd(values[CMOS_HOUR])) * 3600 +
		(from_bcd(values[CMOS_MINUTE])) * 60 +
		from_bcd(values[CMOS_SECOND]) + 0;

	return time;
}

static uint64_t boot_time = 0;
static uint64_t timer_ticks = 0;
static uint64_t timer_subticks = 0;

static unsigned long tsc_mhz = 3500; /* XXX */

static inline uint64_t read_tsc(void) {
	uint32_t lo, hi;
	asm volatile ( "rdtsc" : "=a"(lo), "=d"(hi) );
	return ((uint64_t)hi << 32) | (uint64_t)lo;
}

void arch_clock_initialize(void) {
	boot_time = read_cmos();

	/* FIXME: This is a terrible fallback tsc calculator, it takes at least two seconds */
#if 0
	uint32_t a_cmos, b_cmos;
	while ((a_cmos = read_cmos()) == boot_time);
	uint64_t a_tsc  = read_tsc();
	while ((b_cmos = read_cmos()) == a_cmos);
	uint64_t b_tsc = read_tsc();

	tsc_mhz = (b_tsc - a_tsc) / 1000000;
#endif
}

int gettimeofday(struct timeval * t, void *z) {
	uint64_t tsc = read_tsc();

	timer_subticks = tsc / tsc_mhz;
	timer_ticks = timer_subticks / 1000000;
	timer_subticks = timer_subticks % 1000000;

	t->tv_sec = boot_time + timer_ticks;
	t->tv_usec = timer_subticks;
	return 0;
}

uint64_t now(void) {
	struct timeval t;
	gettimeofday(&t, NULL);
	return t.tv_sec;
}
