/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <datetime.h>

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

void filetime_to_unix_timespec(const FILETIME *filetime, struct timespec *tv)
{
	uint64_t nsec = filetime_to_unix(filetime);
	/* TODO: Handle overflow? */
	tv->tv_sec = nsec / NANOSECONDS_PER_SECOND;
	tv->tv_nsec = nsec % NANOSECONDS_PER_SECOND;
}

static void unix_time_to_filetime(uint64_t nsec, FILETIME *filetime)
{
	uint64_t ticks = nsec / NANOSECONDS_PER_TICK + TICKS_TO_UNIX_EPOCH;
	filetime->dwLowDateTime = (DWORD)(ticks % 0x100000000ULL);
	filetime->dwHighDateTime = (DWORD)(ticks / 0x100000000ULL);
}

void unix_timeval_to_filetime(const struct timeval *time, FILETIME *filetime)
{
	unix_time_to_filetime((uint64_t)time->tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)time->tv_usec * 1000ULL, filetime);
}

void unix_timespec_to_filetime(const struct timespec *time, FILETIME *filetime)
{
	unix_time_to_filetime((uint64_t)time->tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)time->tv_nsec, filetime);
}

void unix_timeval_to_unix_timespec(const struct timeval *timeval, struct timespec *timespec)
{
	timespec->tv_sec = timeval->tv_sec;
	timespec->tv_nsec = timeval->tv_usec * 1000;
}
