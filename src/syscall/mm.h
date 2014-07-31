#pragma once

#include <common/types.h>
#include <common/mman.h>

#include <Windows.h>

/* Windows allocation granularity */
#define BLOCK_SIZE 0x00010000U

/* Page size */
#define PAGE_SIZE 0x00001000U

/* Base address of mm_data structure */
#define MM_DATA_BASE		0x07000000
/* Base address of mm_heap structure */
#define MM_HEAP_BASE		0x07800000
/* Base address of fork_info structure */
#define FORK_INFO_BASE		0x07FF0000

void mm_init();
void mm_shutdown();
void mm_update_brk(void *brk);

int mm_handle_page_fault(void *addr);
void mm_fork(HANDLE process);

void *mm_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset_pages);
int mm_munmap(void *addr, size_t len);

void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset_pages);
void *sys_oldmmap(void *args);
void *sys_mmap2(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
int sys_munmap(void *addr, size_t len);
int sys_mprotect(void *addr, size_t len, int prot);
int sys_msync(void *addr, size_t len, int flags);
int sys_mlock(const void *addr, size_t len);
int sys_munlock(const void *addr, size_t len);

void *sys_brk(void *addr);
