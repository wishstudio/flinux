#pragma once

#include <common/types.h>
#include <common/time.h>

#define RLIMIT_CPU			0	/* CPU time in sec */
#define RLIMIT_FSIZE		1	/* Maximum filesize */
#define RLIMIT_DATA			2	/* max data size */
#define RLIMIT_STACK		3	/* max stack size */
#define RLIMIT_CORE			4	/* max core file size */
#define RLIMIT_RSS			5	/* max resident set size */
#define RLIMIT_NPROC		6	/* max number of processes */
#define RLIMIT_NOFILE		7	/* max number of open files */
#define RLIMIT_MEMLOCK		8	/* max locked-in-memory address space */
#define RLIMIT_AS			9	/* address space limit */
#define RLIMIT_LOCKS		10	/* maximum file locks held */
#define RLIMIT_SIGPENDING	11	/* max number of pending signals */
#define RLIMIT_MSGQUEUE		12	/* maximum bytes in POSIX mqueues */
#define RLIMIT_NICE			13	/* max nice prio allowed to raise to 0-39 for nice level 19 .. -20 */
#define RLIMIT_RTPRIO		14	/* maximum realtime priority */
#define RLIMIT_RTTIME		15	/* timeout for RT tasks in us */
#define RLIM_NLIMITS		16

#define RLIM_INFINITY		(~0UL)

struct rlimit {
	unsigned long rlim_cur;  /* Soft limit */
	unsigned long rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};

struct rlimit64 {
	uint64_t rlim_cur; /* Soft limit */
	uint64_t rlim_max; /* Hard limit (ceiling for rlim_cur */
};

/*
 * Definition of struct rusage taken from BSD 4.3 Reno
 *
 * We don't support all of these yet, but we might as well have them....
 * Otherwise, each time we add new items, programs which depend on this
 * structure will lose.  This reduces the chances of that happening.
 */
#define RUSAGE_SELF		0
#define RUSAGE_CHILDREN	(-1)
#define RUSAGE_BOTH		(-2)	/* sys_wait4() uses this */
#define RUSAGE_THREAD	1		/* only the calling thread */

struct rusage {
	struct linux_timeval ru_utime;	/* user time used */
	struct linux_timeval ru_stime;	/* system time used */
	intptr_t ru_maxrss;				/* maximum resident set size */
	intptr_t ru_ixrss;				/* integral shared memory size */
	intptr_t ru_idrss;				/* integral unshared data size */
	intptr_t ru_isrss;				/* integral unshared stack size */
	intptr_t ru_minflt;				/* page reclaims */
	intptr_t ru_majflt;				/* page faults */
	intptr_t ru_nswap;				/* swaps */
	intptr_t ru_inblock;			/* block input operations */
	intptr_t ru_oublock;			/* block output operations */
	intptr_t ru_msgsnd;				/* messages sent */
	intptr_t ru_msgrcv;				/* messages received */
	intptr_t ru_nsignals;			/* signals received */
	intptr_t ru_nvcsw;				/* voluntary context switches */
	intptr_t ru_nivcsw;				/* involuntary " */
};
