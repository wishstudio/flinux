#ifndef _SYSCALL_MM_H
#define _SYSCALL_MM_H

#include <common/types.h>
#include <common/mman.h>

void mm_init();

void* sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int sys_munmap(void *addr, size_t len);
int sys_mprotect(void *addr, size_t len, int prot);
int sys_msync(void *addr, size_t len, int flags);
int sys_mlock(const void *addr, size_t len);
int sys_munlock(const void *addr, size_t len);

#endif
