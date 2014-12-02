#include <syscall/mm.h>
#include <syscall/timer.h>
#include <datetime.h>
#include <errno.h>
#include <log.h>

#include <Windows.h>
#include <ntdll.h>

int sys_time(int *c)
{
	log_info("time(%p)\n", c);
	if (c && !mm_check_write(c, sizeof(int)))
		return -EFAULT;
	SYSTEMTIME systime;
	GetSystemTime(&systime);
	uint64_t t = (uint64_t)systime.wSecond + (uint64_t)systime.wMinute * 60
		+ (uint64_t)systime.wHour * 3600 + (uint64_t)systime.wDay * 86400
		+ ((uint64_t)systime.wYear - 70) * 31536000 + (((uint64_t)systime.wYear - 69) / 4) * 86400
		- (((uint64_t)systime.wYear - 1) / 100) * 86400 + (((uint64_t)systime.wYear + 299) / 400) * 86400;

	if (c)
		*c = (int)t;
	return t;
}

int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
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

int sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
	log_info("nanospeep(0x%p, 0x%p)\n", req, rem);
	if (!mm_check_read(req, sizeof(struct timespec)) || rem && !mm_check_write(rem, sizeof(struct timespec)))
		return -EFAULT;
	LARGE_INTEGER delay_interval;
	delay_interval.QuadPart = ((uint64_t)req->tv_sec * 1000000000ULL + req->tv_nsec) / 100ULL;
	NtDelayExecution(FALSE, &delay_interval);
	return 0;
}

int sys_clock_gettime(int clk_id, struct timespec *tp)
{
	log_debug("sys_clock_gettime(%d, 0x%p)\n", clk_id, tp);
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
	}
	default:
		return -EINVAL;
	}
	return 0;
}
