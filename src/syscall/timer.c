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

#include <common/errno.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/timer.h>
#include <datetime.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ntdll.h>

DEFINE_SYSCALL(time, intptr_t *, c)
{
	log_info("time(%p)\n", c);
	if (c && !mm_check_write(c, sizeof(int)))
		return -EFAULT;
	FILETIME systime;
	GetSystemTimeAsFileTime(&systime);
	uint64_t t = filetime_to_unix_sec(&systime);
	if (c)
		*c = (intptr_t)t;
	return t;
}

DEFINE_SYSCALL(gettimeofday, struct timeval *, tv, struct timezone *, tz)
{
	log_info("gettimeofday(0x%p, 0x%p)\n", tv, tz);
	if (tz)
		log_error("warning: timezone is not NULL\n");
	if (tv)
	{
		/* TODO: Use GetSystemTimePreciseAsFileTime() on Windows 8 */
		FILETIME system_time;
		GetSystemTimeAsFileTime(&system_time);
		filetime_to_unix_timeval(&system_time, tv);
	}
	return 0;
}

DEFINE_SYSCALL(nanosleep, const struct timespec *, req, struct timespec *, rem)
{
	log_info("nanospeep(0x%p, 0x%p)\n", req, rem);
	if (!mm_check_read(req, sizeof(struct timespec)) || rem && !mm_check_write(rem, sizeof(struct timespec)))
		return -EFAULT;
	LARGE_INTEGER delay_interval;
	delay_interval.QuadPart = 0ULL - (((uint64_t)req->tv_sec * 1000000000ULL + req->tv_nsec) / 100ULL);
	NtDelayExecution(FALSE, &delay_interval);
	return 0;
}

DEFINE_SYSCALL(clock_gettime, int, clk_id, struct timespec *, tp)
{
	log_info("sys_clock_gettime(%d, 0x%p)\n", clk_id, tp);
	if (!mm_check_write(tp, sizeof(struct timespec)))
		return -EFAULT;
	switch (clk_id)
	{
	case CLOCK_REALTIME:
	{
		/* TODO: Use GetSystemTimePreciseAsFileTime() on Windows 8 */
		FILETIME system_time;
		GetSystemTimeAsFileTime(&system_time);
		filetime_to_unix_timespec(&system_time, tp);
		return 0;
	}
	case CLOCK_MONOTONIC:
	case CLOCK_MONOTONIC_COARSE:
	case CLOCK_MONOTONIC_RAW:
	{
		LARGE_INTEGER freq, counter;
		QueryPerformanceFrequency(&freq);
		QueryPerformanceCounter(&counter);
		uint64_t ns = (double)counter.QuadPart / (double)freq.QuadPart * NANOSECONDS_PER_SECOND;
		tp->tv_sec = ns / NANOSECONDS_PER_SECOND;
		tp->tv_nsec = ns % NANOSECONDS_PER_SECOND;
		return 0;
	}
	default:
		return -EINVAL;
	}
}

DEFINE_SYSCALL(clock_getres, int, clk_id, struct timespec *, res)
{
	log_info("clock_getres(%d, 0x%p)\n", clk_id, res);
	if (!mm_check_write(res, sizeof(struct timespec)))
		return -EFAULT;
	switch (clk_id)
	{
	case CLOCK_REALTIME:
	{
		ULONG coarse, fine, actual;
		NtQueryTimerResolution(&coarse, &fine, &actual);
		uint64_t ns = (uint64_t)actual * NANOSECONDS_PER_TICK;
		res->tv_sec = ns / NANOSECONDS_PER_SECOND;
		res->tv_nsec = ns % NANOSECONDS_PER_SECOND;
		return 0;
	}
	case CLOCK_MONOTONIC:
	case CLOCK_MONOTONIC_COARSE:
	case CLOCK_MONOTONIC_RAW:
	{
		LARGE_INTEGER freq;
		QueryPerformanceFrequency(&freq);
		uint64_t ns = (double)1. / (double)freq.QuadPart;
		if (ns == 0)
		{
			res->tv_sec = 0;
			res->tv_nsec = 1;
		}
		else
		{
			res->tv_sec = ns / NANOSECONDS_PER_SECOND;
			res->tv_nsec = ns % NANOSECONDS_PER_SECOND;
		}
		return 0;
	}
	default:
		return -EINVAL;
	}
}

DEFINE_SYSCALL(setitimer, int, which, const struct itimerval *, new_value, struct itimerval *, old_value)
{
	log_info("setitimer(%d, %p, %p)\n", which, new_value, old_value);
	log_error("setitimer() not implemented.\n");
	return 0;
}
