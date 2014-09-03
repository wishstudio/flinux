#include <datetime.h>

#define NANOSECONDS_PER_TICK	100ULL
#define NANOSECONDS_PER_SECOND	1000000000ULL
#define TICKS_PER_SECOND		10000000ULL
#define SEC_TO_UNIX_EPOCH		11644473600ULL
#define TICKS_TO_UNIX_EPOCH		(TICKS_PER_SECOND * SEC_TO_UNIX_EPOCH)

static uint64_t filetime_to_unix(const FILETIME *filetime)
{
	uint64_t ticks = ((uint64_t)filetime->dwHighDateTime << 32ULL) + filetime->dwLowDateTime;
	if (ticks < TICKS_TO_UNIX_EPOCH) /* Out of range */
		return -1;
	ticks -= TICKS_TO_UNIX_EPOCH;
	return ticks * NANOSECONDS_PER_TICK;
}

uint64_t filetime_to_unix_sec(const FILETIME *filetime)
{
	uint64_t nsec = filetime_to_unix(filetime);
	if (nsec == -1)
		return -1;
	return nsec / NANOSECONDS_PER_SECOND;
}

uint64_t filetime_to_unix_nsec(const FILETIME *filetime)
{
	uint64_t nsec = filetime_to_unix(filetime);
	if (nsec == -1)
		return -1;
	return nsec % NANOSECONDS_PER_SECOND;
}

void filetime_to_unix_timeval(const FILETIME *filetime, struct timeval *tv)
{
	uint64_t nsec = filetime_to_unix(filetime);
	/* TODO: Handle overflow? */
	tv->tv_sec = nsec / NANOSECONDS_PER_SECOND;
	tv->tv_usec = (nsec % NANOSECONDS_PER_SECOND) / 1000;
}

static void unix_time_to_filetime(uint64_t nsec, FILETIME *filetime)
{
	uint64_t ticks = nsec / NANOSECONDS_PER_TICK + TICKS_TO_UNIX_EPOCH;
	filetime->dwLowDateTime = (DWORD)(ticks % 32ULL);
	filetime->dwHighDateTime = (DWORD)(ticks / 32ULL);
}

void unix_timeval_to_filetime(const struct timeval *time, FILETIME *filetime)
{
	unix_time_to_filetime((uint64_t)time->tv_sec * 1000000000 + (uint64_t)time->tv_usec * 1000, filetime);
}
