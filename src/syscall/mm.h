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

#ifdef _WIN64

/* Base address of mm_data structure */
#define MM_DATA_BASE			0x0000000020000000ULL
/* Base address of section handles table */
#define MM_SECTION_HANDLE_BASE	0x0000000030000000ULL
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

/* x64 Special: brk() base address */
#define MM_BRK_BASE				0x0000000300000000ULL

#else

/* Base address of mm_data structure */
#define MM_DATA_BASE			0x70000000U
/* Base address of section handles table */
#define MM_SECTION_HANDLE_BASE	0x70200000U
/* Base address of process_data structure */
#define PROCESS_DATA_BASE		0x70700000U
/* Base address of dbt_data structure */
#define DBT_DATA_BASE			0x70800000U
/* Base address of vfs_data structure */
#define VFS_DATA_BASE			0x70900000U
/* Base address of console_data structure */
#define CONSOLE_DATA_BASE		0x70FB0000U
/* Base address of mm_heap structure */
#define MM_HEAP_BASE			0x70FC0000U
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
/* Base address of dbt blocks table */
#define DBT_BLOCKS_BASE			0x72000000U
/* Size of dbt blocks table */
#define DBT_BLOCKS_SIZE			0x00800000U
/* Base address of dbt cache */
#define DBT_CACHE_BASE			0x72800000U
/* Size of dbt cache (8 MiB) */
#define DBT_CACHE_SIZE			0x00800000U

#endif

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

size_t mm_find_free_pages(size_t count_bytes);
struct file;
void *mm_mmap(void *addr, size_t len, int prot, int flags, struct file *f, off_t offset_pages);
int mm_munmap(void *addr, size_t len);
