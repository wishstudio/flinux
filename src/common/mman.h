#pragma once

#define PROT_NONE		0
#define PROT_READ		1
#define PROT_WRITE		2
#define PROT_EXEC		4

#define MAP_FILE		0
#define MAP_SHARED		1
#define MAP_PRIVATE		2
#define MAP_TYPE		0xf
#define MAP_FIXED		0x10
#define MAP_ANONYMOUS	0x20
#define MAP_ANON		MAP_ANONYMOUS
#define MAP_32BIT		0x40

#define MAP_GROWSDOWN	0x0100	/* stack-like segment */
#define MAP_DENYWRITE	0x0800	/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000	/* mark it as an executable */
#define MAP_LOCKED		0x2000	/* pages are locked */
#define MAP_NORESERVE	0x4000	/* don't check for reservations */
#define MAP_POPULATE	0x8000	/* populate (prefault) pagetables */
#define MAP_NONBLOCK	0x10000	/* do not block on IO */
#define MAP_STACK		0x20000	/* give out an address that is best suited for process/thread stacks */
#define MAP_HUGETLB		0x40000	/* create a huge page mapping */

#define MAP_FAILED		((void *)-1)

/* Flags for msync. */
#define MS_ASYNC		1	 /* sync memory synchronously */
#define MS_INVALIDATE	2	 /* invalidate the caches */
#define MS_SYNC			4	 /* synchronous memory sync */

/* Flags for madvise. */
#define MADV_NORMAL			0		/* no further special treatment */
#define MADV_RANDOM			1		/* expect random page references */
#define MADV_SEQUENTIAL		2		/* expect sequential page references */
#define MADV_WILLNEED		3		/* will need these pages */
#define MADV_DONTNEED		4		/* don't need these pages */
#define MADV_REMOVE			9		/* remove these pages & resources */
#define MADV_DONTFORK		10		/* don't inherit across fork */
#define MADV_DOFORK			11		/* do inherit across fork */
#define MADV_MERGEABLE		12		/* KSM may merge identical pages */
#define MADV_UNMERGEABLE	13		/* KSM may not merge identical pages */
#define MADV_HUGEPAGE		14		/* Worth backing with hugepages */
#define MADV_NOHUGEPAGE		15		/* Not worth backing with hugepages */
#define MADV_DONTDUMP		16		/* Explicity exclude from the core dump, overrides the coredump filter bits */
#define MADV_DODUMP			17		/* Clear the MADV_DONTDUMP flag */

#define MADV_HWPOISON		100		/* poison a page for testing */
#define MADV_SOFT_OFFLINE	101		/* soft offline page for testing */
