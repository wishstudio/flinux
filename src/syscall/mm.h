#ifndef _SYSCALL_MM_H
#define _SYSCALL_MM_H

#include "types.h"

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

#define MAP_FAILED		((void *)-1)

/* Flags for msync. */
#define MS_ASYNC		1
#define MS_SYNC			2
#define MS_INVALIDATE	4

void mm_init();

void* mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);
int msync(void *addr, size_t len, int flags);
int mlock(const void *addr, size_t len);
int munlock(const void *addr, size_t len);

#endif
