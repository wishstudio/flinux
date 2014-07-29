#pragma once

#include "types.h"

typedef unsigned long int sigset_t;

typedef union sigval
{
	int sival_int;
	void *sival_ptr;
} sigval_t;

struct siginfo_t
{
	int si_signo;		/* Signal number */
	int si_errno;		/* An errno value */
	int si_code;		/* Signal code */
	int si_trapno;		/* Trap number that caused hardware-generated signal (unused on most architectures) */
	pid_t si_pid;		/* Sending process ID */
	uid_t si_uid;		/* Real user ID of sending process */
	int si_status;		/* Exit value or signal */
	clock_t si_utime;	/* User time consumed */
	clock_t si_stime;	/* System time consumed */
	sigval_t si_value;	/* Signal value */
	int si_int;			/* POSIX.1b signal */
	void *si_ptr;		/* POSIX.1b signal */
	int si_overrun;		/* Timer overrun count; POSIX.1b timers */
	int si_timerid;		/* Timer ID; POSIX.1b timers */
	void *si_addr;		/* Memory location which caused fault */
	long si_band;		/* Band event (was int in glibc 2.3.2 and earlier) */
	int si_fd;			/* File descriptor */
	short si_addr_lsb;	/* Least significant bit of address (since Linux 2.6.32) */
};

struct sigaction
{
	void (*sa_handler)(int);
	void (*sa_sigaction)(int, struct siginfo_t *, void *);
	sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer)();
};

/* ISO C99 signals.  */
#define	SIGINT		2	/* Interactive attention signal.  */
#define	SIGILL		4	/* Illegal instruction.  */
#define	SIGABRT		6	/* Abnormal termination.  */
#define	SIGFPE		8	/* Erroneous arithmetic operation.  */
#define	SIGSEGV		11	/* Invalid access to storage.  */
#define	SIGTERM		15	/* Termination request.  */

/* Historical signals specified by POSIX. */
#define	SIGHUP		1	/* Hangup.  */
#define	SIGQUIT		3	/* Quit.  */
#define	SIGTRAP		5	/* Trace/breakpoint trap.  */
#define	SIGKILL		9	/* Killed.  */
#define SIGBUS		10	/* Bus error.  */
#define	SIGSYS		12	/* Bad system call.  */
#define	SIGPIPE		13	/* Broken pipe.  */
#define	SIGALRM		14	/* Alarm clock.  */

/* New(er) POSIX signals (1003.1-2008).  */
#define	SIGURG		16	/* High bandwidth data is available at a socket.  */
#define	SIGSTOP		17	/* Stopped (signal).  */
#define	SIGTSTP		18	/* Stopped.  */
#define	SIGCONT		19	/* Continued.  */
#define	SIGCHLD		20	/* Child terminated or stopped.  */
#define	SIGTTIN		21	/* Background read from control terminal.  */
#define	SIGTTOU		22	/* Background write to control terminal.  */
#define	SIGPOLL 	23	/* Pollable event occurred (System V).  */
#define	SIGIO		SIGPOLL	/* I/O now possible (4.2 BSD).  */
#define	SIGXCPU		24	/* CPU time limit exceeded.  */
#define	SIGXFSZ		25	/* File size limit exceeded.  */
#define	SIGVTALRM	26	/* Virtual timer expired.  */
#define	SIGPROF		27	/* Profiling timer expired.  */
#define	SIGUSR1		30	/* User-defined signal 1.  */
#define	SIGUSR2		31	/* User-defined signal 2.  */

#define	_NSIG		32
