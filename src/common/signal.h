#pragma once

#include <common/types.h>

#define	_NSIG		64
#define _NSIG_WORDS	(_NSIG / sizeof(unsigned long))

typedef uintptr_t old_sigset_t;
typedef uint64_t sigset_t;

#define sigaddset(set, sig)		*(set) |= (1ULL << (sig))
#define sigdelset(set, sig)		*(set) &= ~(1ULL << (sig))
#define sigemptyset(set)		*(set) = 0ULL
#define sigfillset(set)			*(set) = (uint64_t)-1
#define sigismember(set, sig)	(*(set) & (1ULL << (sig)))

typedef union sigval
{
	int sival_int;
	void *sival_ptr;
} sigval_t;

#define SI_MAX_SIZE		128
#ifdef _WIN64
#define SI_PAD_SIZE		((SI_MAX_SIZE / sizeof(int)) - 4)
#else
#define SI_PAD_SIZE		((SI_MAX_SIZE / sizeof(int)) - 3)
#endif

typedef struct siginfo {
	int si_signo; /* signal number */
	int si_errno; /* if non-zero, an errno value associated with this signal */
	int si_code; /* signal code */

	union {
		int _pad[SI_PAD_SIZE];

		/* kill() */
		struct {
			pid_t _pid;	/* sender's pid */
			uid_t _uid;	/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			int _tid;	/* timer id */
			int _overrun;		/* overrun count */
			sigval_t _sigval;	/* same as below */
		} _timer;

		/* POSIX.1b signals */
		struct {
			pid_t _pid;	/* sender's pid */
			uid_t _uid;	/* sender's uid */
			sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			pid_t _pid;	/* which child */
			uid_t _uid;	/* sender's uid */
			int _status;		/* exit code */
			clock_t _utime;
			clock_t _stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
		struct {
			void *_addr; /* faulting insn/memory ref. */
			short _addr_lsb; /* LSB of the reported address */
		} _sigfault;

		/* SIGPOLL */
		struct {
			intptr_t _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;

		/* SIGSYS */
		struct {
			void *_call_addr; /* calling user insn */
			int _syscall;	/* triggering system call number */
			unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
		} _sigsys;
	} _sifields;
} siginfo_t;

struct sigaction
{
	union
	{
		void (*sa_handler)(int);
		void (*sa_sigaction)(int, siginfo_t *, void *);
	};
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

#define SA_NOCLDSTOP	0x00000001u
#define SA_NOCLDWAIT	0x00000002u
#define SA_SIGINFO		0x00000004u
#define SA_ONSTACK		0x08000000u
#define SA_RESTART		0x10000000u
#define SA_NODEFER		0x40000000u
#define SA_RESETHAND	0x80000000u

#define SA_NOMASK		SA_NODEFER
#define SA_ONESHOT		SA_RESETHAND

#define SA_RESTORER		0x04000000

#define SIG_BLOCK		0
#define SIG_UNBLOCK		1
#define SIG_SETMASK		2

typedef void (*__sighandler_t)(int);
#define SIG_DFL			((__sighandler_t)0)		/* default signal handling */
#define SIG_IGN			((__sighandler_t)1)		/* ignore signal */
#define SIG_ERR			((__sighandler_t)-1)	/* error return from signal */

#define MINSIGSTKSZ     2048
#define SIGSTKSZ        8192

typedef struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
} stack_t;
