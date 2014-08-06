#pragma once

/* Options for wait() */
#define WNOHANG			0x00000001
#define WUNTRACED		0x00000002
#define WSTOPPED		WUNTRACED
#define WEXITED			0x00000004
#define WCONTINUED		0x00000008
#define WNOWAIT			0x01000000		/* Don't reap, just poll status.  */


/* Status code returned by wait() */
/* Macros for constructing status values.  */
#define	W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
#define	W_STOPCODE(sig)			((sig) << 8 | 0x7f)
#define W_CONTINUED				0xffff
#define	WCOREFLAG				0x80

/* If WIFEXITED(STATUS), the low-order 8 bits of the status.  */
#define	WEXITSTATUS(status)		(((status) & 0xff00) >> 8)

/* If WIFSIGNALED(STATUS), the terminating signal.  */
#define	WTERMSIG(status)		((status) & 0x7f)

/* If WIFSTOPPED(STATUS), the signal that stopped the child.  */
#define	WSTOPSIG(status)		WEXITSTATUS(status)

/* Nonzero if STATUS indicates normal termination.  */
#define	WIFEXITED(status)		(WTERMSIG(status) == 0)

/* Nonzero if STATUS indicates termination by a signal.  */
#define WIFSIGNALED(status)		(((signed char) (((status) & 0x7f) + 1) >> 1) > 0)

/* Nonzero if STATUS indicates the child is stopped.  */
#define	WIFSTOPPED(status)		(((status) & 0xff) == 0x7f)

/* Nonzero if STATUS indicates the child continued after a stop. */
#define	WIFCONTINUED(status)	((status) == W_CONTINUED)

/* Nonzero if STATUS indicates the child dumped core.  */
#define	WCOREDUMP(status)		((status) & WCOREFLAG
