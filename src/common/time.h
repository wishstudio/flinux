#pragma once

struct timespec
{
	long tv_sec;
	long tv_nsec;
};

struct linux_timeval
{
	long tv_sec;		/* seconds */
	long tv_usec;		/* and microseconds */
};

struct timezone
{
	int tz_minuteswest;		/* minutes west of Greenwich */
	int tz_dsttime;			/* type of DST correction */
};

#define ITIMER_REAL				0
#define ITIMER_VIRTUAL			1
#define ITIMER_PROF				2

struct itimerval
{
	struct linux_timeval it_interval;	/* timer interval */
	struct linux_timeval it_value;		/* current value */
};

typedef int clockid_t;
typedef int timer_t;

#define CLOCK_REALTIME				0
#define CLOCK_MONOTONIC				1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW			4
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#define CLOCK_BOOTTIME				7
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9
#define CLOCK_SGI_CYCLE				10 /* Hardware specific */
#define CLOCK_TAI					11

#define MAX_CLOCKS					16
#define CLOCKS_MASK					(CLOCK_REALTIME | CLOCK_MONOTONIC)
#define CLOCKS_MONO					CLOCK_MONOTONIC
