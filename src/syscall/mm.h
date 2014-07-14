#ifndef _SYSCALL_MM_H
#define _SYSCALL_MM_H

#include <common/types.h>
#include <common/mman.h>

void mm_init();

void* mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);
int msync(void *addr, size_t len, int flags);
int mlock(const void *addr, size_t len);
int munlock(const void *addr, size_t len);

#endif
