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

#define SIGHUP			1
#define SIGINT			2
#define SIGQUIT			3
#define SIGILL			4
#define SIGTRAP			5
#define SIGABRT			6
#define SIGIOT			6
#define SIGBUS			7
#define SIGFPE			8
#define SIGKILL			9
#define SIGUSR1			10
#define SIGSEGV			11
#define SIGUSR2			12
#define SIGPIPE			13
#define SIGALRM			14
#define SIGTERM			15
#define SIGSTKFLT		16
#define SIGCHLD			17
#define SIGCONT			18
#define SIGSTOP			19
#define SIGTSTP			20
#define SIGTTIN			21
#define SIGTTOU			22
#define SIGURG			23
#define SIGXCPU			24
#define SIGXFSZ			25
#define SIGVTALRM		26
#define SIGPROF			27
#define SIGWINCH		28
#define SIGIO			29
#define SIGPOLL			SIGIO
/*
#define SIGLOST			29
*/
#define SIGPWR			30
#define SIGSYS			31
#define SIGUNUSED		31

#define SIGRTMIN		32
#define SIGRTMAX		_NSIG

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
