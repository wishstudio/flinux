#pragma once

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
