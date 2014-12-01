#pragma once

#include <common/types.h>
#include <common/mman.h>

#include <Windows.h>

/* Windows allocation granularity */
#ifdef _WIN64
#define BLOCK_SIZE 0x00010000ULL
#else
#define BLOCK_SIZE 0x00010000U
#endif

/* Page size */
#ifdef _WIN64
#define PAGE_SIZE 0x00001000ULL
#else
#define PAGE_SIZE 0x00001000U
#endif

#ifdef _WIN64

/* Base address of mm_data structure */
#define MM_DATA_BASE			0x0000000010000000ULL
/* Base address of section handles table */
#define MM_SECTION_HANDLE_BASE	0x0000000020000000ULL
/* Base address of process_data structure */
#define PROCESS_DATA_BASE		0x00000000EC000000ULL
/* Base address of mm_heap structure */
#define MM_HEAP_BASE			0x00000000ED000000ULL
/* Base address of vfs_data structure */
#define VFS_DATA_BASE			0x00000000EE000000ULL
/* Base address of tls_data structure */
#define TLS_DATA_BASE			0x00000000EFFD0000ULL
/* Base address of executable startup data */
#define STARTUP_DATA_BASE		0x00000000EFFE0000ULL
/* Base address of fork_info structure */
#define FORK_INFO_BASE			0x00000000EFFF0000ULL
/* Low address of kernel heap */
#define ADDRESS_HEAP_LOW		0x00000000F0000000ULL
/* High address of kernel heap */
#define ADDRESS_HEAP_HIGH		0x0000000100000000ULL

#else

/* Base address of mm_data structure */
#define MM_DATA_BASE			0x70000000U
/* Base address of section handles table */
#define MM_SECTION_HANDLE_BASE	0x70200000U
/* Base address of process_data structure */
#define PROCESS_DATA_BASE		0x70700000U
/* Base address of mm_heap structure */
#define MM_HEAP_BASE			0x70800000U
/* Base address of vfs_data structure */
#define VFS_DATA_BASE			0x70900000U
/* Base address of tls_data structure */
#define TLS_DATA_BASE			0x70FD0000U
/* Base address of executable startup data */
#define STARTUP_DATA_BASE		0x70FE0000U
/* Base address of fork_info structure */
#define FORK_INFO_BASE			0x70FF0000U
/* Low address of kernel heap */
#define ADDRESS_HEAP_LOW		0x71000000U
/* High address of kernel heap */
#define ADDRESS_HEAP_HIGH		0x72000000U

#endif

void mm_init();
void mm_reset();
void mm_shutdown();
void mm_update_brk(void *brk);

void mm_dump_stack_trace(PCONTEXT context);

/* Check if the memory region is compatible with desired access */
int mm_check_read(void *addr, size_t size);
int mm_check_read_string(const char *addr);
int mm_check_write(void *addr, size_t size);

int mm_handle_page_fault(void *addr);
int mm_fork(HANDLE process);

size_t mm_find_free_pages(size_t count_bytes);
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
