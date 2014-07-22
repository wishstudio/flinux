#ifndef _SYSCALL_MM_H
#define _SYSCALL_MM_H

#include <common/types.h>
#include <common/mman.h>

#define PAGE_SIZE 0x00001000U

extern void *mm_brk;

void mm_init();
void mm_shutdown();

void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
void *sys_oldmmap(void *args);
void *sys_mmap2(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
int sys_munmap(void *addr, size_t len);
int sys_mprotect(void *addr, size_t len, int prot);
int sys_msync(void *addr, size_t len, int flags);
int sys_mlock(const void *addr, size_t len);
int sys_munlock(const void *addr, size_t len);

void *sys_brk(void *addr);

#endif
