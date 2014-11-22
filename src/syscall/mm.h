#pragma once

#include <common/types.h>
#include <common/mman.h>

#include <Windows.h>

/* Windows allocation granularity */
#define BLOCK_SIZE 0x00010000U

/* Page size */
#define PAGE_SIZE 0x00001000U

/* Base address of mm_data structure */
#define MM_DATA_BASE		0x70000000
/* Base address of process_data structure */
#define PROCESS_DATA_BASE	0x70700000
/* Base address of mm_heap structure */
#define MM_HEAP_BASE		0x70800000
/* Base address of vfs_data structure */
#define VFS_DATA_BASE		0x70900000
/* Base address of tls_data structure */
#define TLS_DATA_BASE		0x70FD0000
/* Base address of executable startup data */
#define STARTUP_DATA_BASE	0x70FE0000
/* Base address of fork_info structure */
#define FORK_INFO_BASE		0x70FF0000
/* Low address of kernel heap */
#define ADDRESS_HEAP_LOW	0x71000000
/* High address of kernel heap */
#define ADDRESS_HEAP_HIGH	0x72000000

void mm_init();
void mm_reset();
void mm_shutdown();
void mm_update_brk(void *brk);

void mm_dump_stack_trace(PCONTEXT context);

int mm_handle_page_fault(void *addr);
int mm_fork(HANDLE process);

uint32_t mm_find_free_pages(uint32_t count_bytes);
struct file;
void *mm_mmap(void *addr, size_t len, int prot, int flags, struct file *f, off_t offset_pages);
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
