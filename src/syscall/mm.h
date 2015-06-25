/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <common/types.h>
#include <common/mman.h>

#define WIN32_LEAN_AND_MEAN
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

#define ALIGN_TO(x, a) ((uintptr_t)((x) + (a) - 1) & -(a))

#ifdef _WIN64

/* x64 Special: brk() base address */
#define MM_BRK_BASE				0x0000000300000000ULL

#endif

/* Internal flags for mm_mmap() */
#define INTERNAL_MAP_TOPDOWN		1	/* Allocate at highest possible address */
#define INTERNAL_MAP_NOOVERWRITE	2	/* Don't automatically overwrite existing mappings, report error in such case */
#define INTERNAL_MAP_NORESET		4	/* Don't unmap the memory region at mm_reset() */
#define INTERNAL_MAP_COPYONFORK		8	/* Make a real copy on forking instead of copying on write
										 * This will cause the memory region to be allocated via VirtualAlloc() */
#define INTERNAL_MAP_SHARED			16	/* A MAP_SHARED memory region */

void mm_init();
void mm_reset();
void mm_shutdown();
void mm_update_brk(void *brk);

void mm_dump_stack_trace(PCONTEXT context);
void mm_dump_windows_memory_mappings(HANDLE process);
void mm_dump_memory_mappings();

/* Check if the memory region is compatible with desired access */
int mm_check_read(const void *addr, size_t size);
int mm_check_read_string(const char *addr);
int mm_check_write(void *addr, size_t size);

int mm_handle_page_fault(void *addr);
int mm_fork(HANDLE process);
void mm_afterfork();

size_t mm_find_free_pages(size_t count_bytes);
struct file;
void *mm_mmap(void *addr, size_t len, int prot, int flags, int internal_flags, struct file *f, off_t offset_pages);
int mm_munmap(void *addr, size_t len);

/* Populate a memory region containing given address */
void mm_populate(void *addr);

/* Static allocation
 * Many subsystems need to use static storage which are automatically forked
 * Since mm only accepts allocation granularity at PAGE_SIZE, there could be much space lost
 * Instead of allocating pages by their own, we preallocate a sufficient block
 * and let the subsystems to allocate their static forkable memory at initialization and
 * on fork(). We keep the initialization order consistent thus they will always get the same
 * static address.
 *
 * TODO: This scheme is really ugly, any better ideas?
 */
#define MM_STATIC_ALLOC_SIZE	3 * BLOCK_SIZE	/* The total size */
void *mm_static_alloc(size_t size);

/* Static allocation for globally shared area
 * Currently the users of this API should make sure to work with zero initialization
 * Because they do not have any chance of manually initialize their shared data area
 */
#define MM_GLOBAL_SHARED_ALLOC_SIZE		3 * BLOCK_SIZE
void *mm_global_shared_alloc(size_t size);
