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

#include <common/errno.h>
#include <dbt/x86.h>
#include <lib/rbtree.h>
#include <lib/slist.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/vfs.h>
#include <log.h>

#include <stdbool.h>
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <ntdll.h>

/* Linux mmap() allows mapping into 4kB page boundaries, while Windows only
 * allows 64kB boundaries (called allocation granularity), although both
 * systems use 4kB page size.
 *
 * This difference causes two main issues for mmap() implementation:
 * 1. Map non 64kB aligned starting address of a file
 *     It's impossible to use Windows file mapping functions. We have to
 *     read/write file content manually on mmap()/msync()/munmap() calls.
 *     This may be slow. But we can possibly implement demand paging to
 *     improve performance.
 *
 * 2. Use MAP_FIXED with non 64kB aligned address
 *     We can allocate full 64kB aligned memory blocks and do partial
 *     allocations inside them. Note it seems impossible to implement
 *     MAP_FIXED with MAP_SHARED or MAP_PRIVATE on non 64kB aligned address.
 */

/* Hard limits */
/* Maximum number of mmap()-ed areas */
#define MAX_MMAP_COUNT 65535

#ifdef _WIN64

/* Lower bound of the virtual address space */
#define ADDRESS_SPACE_LOW		0x0000000000000000ULL
/* Higher bound of the virtual address space */
#define ADDRESS_SPACE_HIGH		0x0001000000000000ULL
/* The lowest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_LOW	0x0000000200000000ULL
/* The highest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_HIGH	0x0001000000000000ULL

#else

/* Lower bound of the virtual address space */
#define ADDRESS_SPACE_LOW		0x00000000U
/* Higher bound of the virtual address space */
#define ADDRESS_SPACE_HIGH		0x80000000U
/* The lowest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_LOW	0x10000000U
/* The highest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_HIGH	0x70000000U

#endif

#define PAGES_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define BLOCK_COUNT ((ADDRESS_SPACE_HIGH - ADDRESS_SPACE_LOW) / BLOCK_SIZE)

#define SECTION_HANDLE_PER_TABLE (BLOCK_SIZE / sizeof(HANDLE))
#define SECTION_TABLE_PER_DIRECTORY (BLOCK_SIZE / sizeof(uint16_t))
#define SECTION_TABLE_COUNT (BLOCK_COUNT / SECTION_HANDLE_PER_TABLE)

#define GET_SECTION_TABLE(i) ((i) / SECTION_HANDLE_PER_TABLE)

/* Helper macros */
#define IS_ALIGNED(addr, alignment) ((size_t) (addr) % (size_t) (alignment) == 0)
#define ALIGN_TO_BLOCK(addr) (((size_t) addr + BLOCK_SIZE - 1) & (-BLOCK_SIZE))
#define ALIGN_TO_PAGE(addr) (((size_t) addr + PAGE_SIZE - 1) & (-PAGE_SIZE))
#define GET_BLOCK(addr) ((size_t) (addr) / BLOCK_SIZE)
#define GET_PAGE(addr) ((size_t) (addr) / PAGE_SIZE)
#define GET_PAGE_IN_BLOCK(page) ((page) % PAGES_PER_BLOCK)
#define GET_BLOCK_OF_PAGE(page) ((page) / PAGES_PER_BLOCK)
#define GET_FIRST_PAGE_OF_BLOCK(block)	((block) * PAGES_PER_BLOCK)
#define GET_LAST_PAGE_OF_BLOCK(block) ((block) * PAGES_PER_BLOCK + (PAGES_PER_BLOCK - 1))
#define GET_BLOCK_ADDRESS(block) (void *)((block) * BLOCK_SIZE)
#define GET_PAGE_ADDRESS(page) (void *)((page) * PAGE_SIZE)
/* Page offset in bytes from the start of its block */
#define GET_SIZE_OF_BLOCK_TO_PAGE(page) ((char*)GET_PAGE_ADDRESS(page) - (char*)GET_BLOCK_ADDRESS(GET_BLOCK_OF_PAGE(page)))
/* Bytes from the page's location to its block's next block */
#define GET_SIZE_OF_PAGE_TO_NEXT_BLOCK(page) ((char*)GET_BLOCK_ADDRESS(GET_BLOCK_OF_PAGE(page) + 1) - (char*)GET_PAGE_ADDRESS(page))

struct map_entry
{
	struct rb_node tree;
	union
	{
		struct slist free_list;
		struct
		{
			size_t start_page;
			size_t end_page;
			int prot, flags;
			struct file *f;
			off_t offset_pages;
		};
	};
};

static int map_entry_cmp(const struct rb_node *l, const struct rb_node *r)
{
	struct map_entry *left = rb_entry(l, struct map_entry, tree);
	struct map_entry *right = rb_entry(r, struct map_entry, tree);
	if (left->start_page == right->start_page)
		return 0;
	else if (left->start_page < right->start_page)
		return -1;
	else
		return 1;
}

struct mm_data
{
	/* RW lock for multi-threading protection */
	SRWLOCK rw_lock;

	/* Program break address, brk() will use this */
	void *brk;

	/* Used for mm_static_alloc() */
	void *static_alloc_begin, *static_alloc_end;

	/* Used for mm_global_shared_alloc() */
	HANDLE global_shared_section;
	void *global_shared_alloc_begin, *global_shared_alloc_end;

	/* Information for all existing mappings */
	struct rb_tree entry_tree;
	struct slist entry_free_list;
	struct map_entry entries[MAX_MMAP_COUNT];

	/* Section handle count for each table */
	uint16_t section_table_handle_count[SECTION_TABLE_COUNT];
} _mm;
static struct mm_data *const mm = &_mm;
static HANDLE *mm_section_handle;

static __forceinline HANDLE get_section_handle(size_t i)
{
	size_t t = GET_SECTION_TABLE(i);
	if (mm->section_table_handle_count[t])
		return mm_section_handle[i];
	else
		return NULL;
}

static __forceinline void add_section_handle(size_t i, HANDLE handle)
{
	size_t t = GET_SECTION_TABLE(i);
	if (mm->section_table_handle_count[t]++)
		mm_section_handle[i] = handle;
	else
	{
		VirtualAlloc(&mm_section_handle[t * SECTION_HANDLE_PER_TABLE], BLOCK_SIZE, MEM_COMMIT, PAGE_READWRITE);
		mm_section_handle[i] = handle;
	}
}

static __forceinline void replace_section_handle(size_t i, HANDLE handle)
{
	mm_section_handle[i] = handle;
}

static __forceinline void replace_section_handle_ex(HANDLE process, size_t i, HANDLE handle)
{
	SIZE_T written;
	WriteProcessMemory(process, &mm_section_handle[i], &handle, sizeof(HANDLE), &written);
}

static __forceinline void remove_section_handle(size_t i)
{
	mm_section_handle[i] = NULL;
	size_t t = GET_SECTION_TABLE(i);
	if (--mm->section_table_handle_count[t] == 0)
		VirtualFree(&mm_section_handle[t * SECTION_HANDLE_PER_TABLE], BLOCK_SIZE, MEM_DECOMMIT);
}

static struct map_entry *new_map_entry()
{
	if (slist_empty(&mm->entry_free_list))
		return NULL;
	struct map_entry *entry = slist_next_entry(&mm->entry_free_list, struct map_entry, free_list);
	slist_remove(&mm->entry_free_list, &entry->free_list);
	return entry;
}

static void free_map_entry(struct map_entry *entry)
{
	slist_add(&mm->entry_free_list, &entry->free_list);
}

static struct rb_node *start_node(size_t start_page)
{
	struct map_entry probe;
	probe.start_page = start_page;
	struct rb_node *node = rb_upper_bound(&mm->entry_tree, &probe.tree, map_entry_cmp);
	if (node)
		return node;
	return rb_lower_bound(&mm->entry_tree, &probe.tree, map_entry_cmp);
}

static struct map_entry *find_map_entry(void *addr)
{
	struct map_entry probe, *entry;
	size_t page = GET_PAGE(addr);
	probe.start_page = page;
	entry = rb_entry(rb_upper_bound(&mm->entry_tree, &probe.tree, map_entry_cmp), struct map_entry, tree);
	/* upper bound condition: block->start_page <= page */
	if (page <= entry->end_page)
		return entry;
	return NULL;
}

static void split_map_entry(struct map_entry *e, size_t last_page_of_first_entry)
{
	struct map_entry *ne = new_map_entry();
	ne->start_page = last_page_of_first_entry + 1;
	ne->end_page = e->end_page;
	if ((ne->f = e->f))
	{
		vfs_ref(ne->f);
		ne->offset_pages = e->offset_pages + (ne->start_page - e->start_page);
	}
	ne->prot = e->prot;
	ne->flags = e->flags;
	e->end_page = last_page_of_first_entry;
	rb_add(&mm->entry_tree, &ne->tree, map_entry_cmp);
}

static void free_map_entry_blocks(struct map_entry *e)
{
	if (e->flags & INTERNAL_MAP_VIRTUALALLOC)
	{
		VirtualFree(GET_PAGE_ADDRESS(e->start_page), 0, MEM_RELEASE);
		return;
	}
	if (e->f)
		vfs_release(e->f);
	struct rb_node *prev = rb_prev(&e->tree);
	struct rb_node *next = rb_next(&e->tree);
	size_t start_block = GET_BLOCK_OF_PAGE(e->start_page);
	size_t end_block = GET_BLOCK_OF_PAGE(e->end_page);

	/* The first block and last block may be shared with previous/next entry
	 * We should mark corresponding pages in such blocks as PAGE_NOACCESS instead of free them */
	if (prev && GET_BLOCK_OF_PAGE(rb_entry(prev, struct map_entry, tree)->end_page) == start_block)
	{
		/* First block is shared, just make it inaccessible */
		size_t last_page = GET_LAST_PAGE_OF_BLOCK(GET_BLOCK_OF_PAGE(e->start_page));
		last_page = min(last_page, e->end_page); /* The entry may occupy only a block */
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(e->start_page), (last_page - e->start_page + 1) * PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
		start_block++;
	}
	if (end_block >= start_block && next && GET_BLOCK_OF_PAGE(rb_entry(next, struct map_entry, tree)->start_page) == end_block)
	{
		/* Last block is shared, just make it inaccessible */
		DWORD oldProtect;
		VirtualProtect(GET_BLOCK_ADDRESS(end_block), GET_SIZE_OF_BLOCK_TO_PAGE(e->end_page + 1), PAGE_NOACCESS, &oldProtect);
		end_block--;
	}
	/* Unmap non-shared full blocks */
	for (size_t i = start_block; i <= end_block; i++)
	{
		HANDLE handle = get_section_handle(i);
		if (handle)
		{
			NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
			NtClose(handle);
			remove_section_handle(i);
		}
	}
}

static void map_global_shared_section()
{
	mm->global_shared_alloc_begin = MapViewOfFile(mm->global_shared_section,
		FILE_MAP_ALL_ACCESS, 0, 0, MM_GLOBAL_SHARED_ALLOC_SIZE);
	if (mm->global_shared_alloc_begin == NULL)
	{
		log_error("mm: Map global shared area failed, error code: %d.\n", GetLastError());
		process_exit(1, 0);
	}
	mm->global_shared_alloc_end = (char*)mm->global_shared_alloc_begin + MM_GLOBAL_SHARED_ALLOC_SIZE;
}

void mm_init()
{
	/* Initialize RW lock */
	InitializeSRWLock(&mm->rw_lock);
	/* Initialize mapping info freelist */
	rb_init(&mm->entry_tree);
	slist_init(&mm->entry_free_list);
	for (size_t i = 0; i + 1 < MAX_MMAP_COUNT; i++)
		slist_add(&mm->entry_free_list, &mm->entries[i].free_list);
	mm->brk = 0;
	/* Initialize section handle table */
	mm_section_handle = VirtualAlloc(NULL, BLOCK_COUNT * sizeof(HANDLE), MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
	/* Initialize static alloc */
	mm->static_alloc_begin = mm_mmap(NULL, MM_STATIC_ALLOC_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS,
		INTERNAL_MAP_TOPDOWN | INTERNAL_MAP_NORESET | INTERNAL_MAP_VIRTUALALLOC, NULL, 0);
	mm->static_alloc_end = (uint8_t*)mm->static_alloc_begin + MM_STATIC_ALLOC_SIZE;
	/* Initialize global shared alloc */
	LPCWSTR section_name = L"flinux_global_shared";
	LARGE_INTEGER size;
	size.QuadPart = MM_GLOBAL_SHARED_ALLOC_SIZE;
	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.bInheritHandle = TRUE;
	attr.lpSecurityDescriptor = NULL;
	mm->global_shared_section = CreateFileMappingW(INVALID_HANDLE_VALUE, &attr, PAGE_READWRITE,
		size.HighPart, size.LowPart, section_name);
	if (mm->global_shared_section == NULL)
	{
		log_error("mm: Create global shared area failed, error code: %d.\n", GetLastError());
		process_exit(1, 0);
	}
	map_global_shared_section();
}

void mm_reset()
{
	/* Release all user memory */
	size_t last_block = 0;
	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur;)
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		size_t start_block = GET_BLOCK_OF_PAGE(e->start_page);
		size_t end_block = GET_BLOCK_OF_PAGE(e->end_page);
		if (e->flags & INTERNAL_MAP_NORESET)
		{
			cur = rb_next(cur);
			continue;
		}

		if (start_block == last_block)
			start_block++;
		for (size_t i = start_block; i <= end_block; i++)
		{
			HANDLE handle = get_section_handle(i);
			if (handle)
			{
				NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
				NtClose(handle);
				remove_section_handle(i);
			}
		}
		last_block = end_block;

		if (e->f)
			vfs_release(e->f);
		free_map_entry(e);
		struct rb_node *next = rb_next(cur);
		rb_remove(&mm->entry_tree, cur);
		cur = next;
	}
	mm->brk = 0;
}

void mm_shutdown()
{
	for (size_t i = 0; i < BLOCK_COUNT; i++)
	{
		HANDLE handle = get_section_handle(i);
		if (handle)
		{
			NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
			NtClose(handle);
			remove_section_handle(i);
		}
	}
	VirtualFree(mm_section_handle, 0, MEM_RELEASE);
}

void *mm_static_alloc(size_t size)
{
	if ((uint8_t*)mm->static_alloc_begin + size > mm->static_alloc_end)
	{
		log_error("mm_static_alloc(): Overlarge static block size, remain: %p, requested: %p\n",
			(uint8_t*)mm->static_alloc_end - (uint8_t*)mm->static_alloc_begin, size);
		log_error("Please enlarge MM_STATIC_ALLOC_SIZE manually.\n");
		__debugbreak();
	}
	void *ret = mm->static_alloc_begin;
	mm->static_alloc_begin = (void*)ALIGN_TO((uint8_t*)mm->static_alloc_begin + size, 16);
	return ret;
}

void *mm_global_shared_alloc(size_t size)
{
	if ((uint8_t*)mm->global_shared_alloc_begin + size > mm->global_shared_alloc_end)
	{
		log_error("mm_global_shared_alloc(): Overlarge static block size, remain: %p, requested: %p\n",
			(uint8_t*)mm->global_shared_alloc_end - (uint8_t*)mm->global_shared_alloc_begin, size);
		log_error("Please enlarge MM_GLOBAL_SHARED_ALLOC_SIZE manually.\n");
		__debugbreak();
	}
	void *ret = mm->global_shared_alloc_begin;
	mm->global_shared_alloc_begin = (void*)ALIGN_TO((uint8_t*)mm->global_shared_alloc_begin + size, 16);
	return ret;
}

void mm_update_brk(void *brk)
{
	/* Seems glibc does not like unaligned initial brk */
#ifdef _WIN64
	mm->brk = MM_BRK_BASE;
#else
	mm->brk = (void*)max((size_t)mm->brk, ALIGN_TO_PAGE(brk));
#endif
}

/* Find 'count' consecutive free pages, return 0 if not found */
static size_t find_free_pages(size_t count, bool block_align)
{
	size_t last = GET_PAGE(ADDRESS_ALLOCATION_LOW);
	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (e->start_page >= last && e->start_page - last >= count)
			return last;
		else if (e->end_page >= last)
		{
			last = e->end_page + 1;
			/* Make sure not collide with block aligned entries */
			if (block_align || BLOCK_ALIGNED(e->flags))
				last = (last + PAGES_PER_BLOCK - 1) & -PAGES_PER_BLOCK;
		}
		if (last >= GET_PAGE(ADDRESS_ALLOCATION_HIGH))
			return 0;
	}
	if (GET_PAGE(ADDRESS_ALLOCATION_HIGH) > last && GET_PAGE(ADDRESS_ALLOCATION_HIGH) - last >= count)
		return last;
	else
		return 0;
}

/* Find 'count' consecutive free pages at the highest possible address with, return 0 if not found */
static size_t find_free_pages_topdown(size_t count, bool block_align)
{
	size_t last = GET_PAGE(ADDRESS_ALLOCATION_HIGH);
	for (struct rb_node *cur = rb_last(&mm->entry_tree); cur; cur = rb_prev(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		size_t end_page = e->end_page;
		/* MAP_SHARED entries always occupy entire blocks */
		if (e->flags & INTERNAL_MAP_SHARED)
			end_page = (end_page & -PAGES_PER_BLOCK) + (PAGES_PER_BLOCK - 1);
		if (e->end_page < last && e->end_page + count < last)
			return last - count;
		else if (e->start_page < last)
		{
			last = e->start_page;
			if (block_align)
				last &= -PAGES_PER_BLOCK;
		}
		if (last <= GET_PAGE(ADDRESS_ALLOCATION_LOW))
			return 0;
	}
	if (GET_PAGE(ADDRESS_ALLOCATION_LOW) < last && GET_PAGE(ADDRESS_ALLOCATION_LOW) + count < last)
		return last - count;
	else
		return 0;
}

size_t mm_find_free_pages(size_t count_bytes)
{
	return find_free_pages(GET_PAGE(ALIGN_TO_PAGE(count_bytes)), false);
}

static DWORD prot_linux2win(int prot)
{
	if ((prot & PROT_EXEC) && (prot & PROT_WRITE))
		return PAGE_EXECUTE_READWRITE;
	else if ((prot & PROT_EXEC) && (prot & PROT_READ))
		return PAGE_EXECUTE_READ;
	else if ((prot & PROT_EXEC))
		return PAGE_EXECUTE; /* Unsupported for file mapping */
	else if (prot & PROT_WRITE)
		return PAGE_READWRITE;
	else if (prot & PROT_READ)
		return PAGE_READONLY;
	else
		return PAGE_NOACCESS;
}

void mm_dump_windows_memory_mappings(HANDLE process)
{
	log_info("Windows memory mappings...\n");
	char *addr = 0;
	do
	{
		MEMORY_BASIC_INFORMATION info;
		VirtualQueryEx(process, addr, &info, sizeof(info));
		if (info.State != MEM_FREE)
		{
			char filename[1024];
			char *access;
			switch (info.Protect & 0xFF)
			{
			case PAGE_NOACCESS: access = "---"; break;
			case PAGE_READONLY: access = "R--"; break;
			case PAGE_READWRITE: access = "RW-"; break;
			case PAGE_WRITECOPY: access = "RC-"; break;
			case PAGE_EXECUTE: access = "--X"; break;
			case PAGE_EXECUTE_READ: access = "R-X"; break;
			case PAGE_EXECUTE_READWRITE: access = "RWX"; break;
			case PAGE_EXECUTE_WRITECOPY: access = "RCX"; break;
			default:
				if (info.State == MEM_RESERVE)
					access = "res";
				else
					access = "???";
			}
			if (GetMappedFileNameA(process, addr, filename, sizeof(filename)))
				log_info("0x%p - 0x%p [%s] <--- %s\n", info.BaseAddress, (size_t)info.BaseAddress + info.RegionSize, access, filename);
			else
				log_info("0x%p - 0x%p [%s]\n", info.BaseAddress, (size_t)info.BaseAddress + info.RegionSize, access);
		}
		addr += info.RegionSize;
#ifdef _WIN64
	} while ((size_t)addr < 0x00007FFFFFFF0000ULL);
#else
	} while ((size_t)addr < 0x7FFF0000U);
#endif
}

void mm_dump_memory_mappings()
{
	AcquireSRWLockShared(&mm->rw_lock);
	log_info("Current memory mappings...\n");
	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		log_info("0x%p - 0x%p: PROT: %d\n", GET_PAGE_ADDRESS(e->start_page), GET_PAGE_ADDRESS(e->end_page), e->prot);
	}
	ReleaseSRWLockShared(&mm->rw_lock);
}

static void map_entry_range(struct map_entry *e, size_t start_page, size_t end_page)
{
	if (e->f)
	{
		size_t desired_size = (end_page - start_page + 1) * PAGE_SIZE;
		size_t r = e->f->op_vtable->pread(e->f, GET_PAGE_ADDRESS(start_page), desired_size,
			(loff_t)(e->offset_pages + start_page - e->start_page) * PAGE_SIZE);
		if (r < desired_size)
		{
			size_t remain = desired_size - r;
			RtlSecureZeroMemory((char*)GET_PAGE_ADDRESS(end_page + 1) - remain, remain);
		}
	}
	else
		RtlSecureZeroMemory(GET_PAGE_ADDRESS(start_page), (end_page - start_page + 1) * PAGE_SIZE);
}

static int mm_change_protection(HANDLE process, size_t start_page, size_t end_page, int prot)
{
	DWORD protection = prot_linux2win(prot);
	size_t start_block = GET_BLOCK_OF_PAGE(start_page);
	size_t end_block = GET_BLOCK_OF_PAGE(end_page);
	for (size_t i = start_block; i <= end_block; i++)
	{
		HANDLE handle = get_section_handle(i);
		if (handle)
		{
			size_t range_start = max(GET_FIRST_PAGE_OF_BLOCK(i), start_page);
			size_t range_end = min(GET_LAST_PAGE_OF_BLOCK(i), end_page);
			DWORD oldProtect;
			if (!VirtualProtectEx(process, GET_PAGE_ADDRESS(range_start), PAGE_SIZE * (range_end - range_start + 1), protection, &oldProtect))
			{
				log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d\n", GET_PAGE_ADDRESS(range_start),
					PAGE_SIZE * (range_end - range_start + 1), GetLastError());
				mm_dump_windows_memory_mappings(process);
				return 0;
			}
		}
	}
	return 1;
}

void mm_dump_stack_trace(PCONTEXT context)
{
	log_info("Stack trace:\n");
#ifdef _WIN64
	size_t sp = context->Rsp;
	log_info("RSP: 0x%p\n", sp);
#else
	size_t sp = context->Esp;
	log_info("ESP: 0x%p\n", sp);
#endif
	for (size_t i = sp & ~15; i < ((sp + 256) & ~15); i += 16)
	{
		log_raw("%p ", i);
		for (size_t j = i; j < i + 16 && j < ((sp + 256) & ~15); j++)
			log_raw("%02x ", *(unsigned char *)j);
		log_raw("\n");
	}
}

static int allocate_block(size_t i)
{
	OBJECT_ATTRIBUTES attr;
	attr.Length = sizeof(OBJECT_ATTRIBUTES);
	attr.RootDirectory = NULL;
	attr.ObjectName = NULL;
	attr.Attributes = OBJ_INHERIT;
	attr.SecurityDescriptor = NULL;
	attr.SecurityQualityOfService = NULL;
	LARGE_INTEGER max_size;
	max_size.QuadPart = BLOCK_SIZE;
	NTSTATUS status;
	HANDLE handle;

	/* Allocate section */
	status = NtCreateSection(&handle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, &attr, &max_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		log_error("NtCreateSection() failed. Status: %x\n", status);
		return 0;
	}

	/* Map section */
	PVOID base_addr = GET_BLOCK_ADDRESS(i);
	SIZE_T view_size = BLOCK_SIZE;
	status = NtMapViewOfSection(handle, NtCurrentProcess(), &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		log_error("NtMapViewOfSection() failed. Address: %p, Status: %x\n", base_addr, status);
		NtClose(handle);
		mm_dump_windows_memory_mappings(NtCurrentProcess());
		return 0;
	}
	add_section_handle(i, handle);
	return 1;
}

static HANDLE duplicate_section(HANDLE source, void *source_addr)
{
	HANDLE dest;
	PVOID dest_addr = NULL;
	OBJECT_ATTRIBUTES attr;
	attr.Length = sizeof(OBJECT_ATTRIBUTES);
	attr.RootDirectory = NULL;
	attr.ObjectName = NULL;
	attr.Attributes = OBJ_INHERIT;
	attr.SecurityDescriptor = NULL;
	attr.SecurityQualityOfService = NULL;
	LARGE_INTEGER max_size;
	max_size.QuadPart = BLOCK_SIZE;
	SIZE_T view_size = BLOCK_SIZE;
	NTSTATUS status;

	status = NtCreateSection(&dest, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, &attr, &max_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		log_error("NtCreateSection() failed, status: %x\n", status);
		return NULL;
	}
	
	status = NtMapViewOfSection(dest, NtCurrentProcess(), &dest_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		log_error("NtMapViewOfSection() failed, status: %x\n", status);
		return NULL;
	}
	/* Mark source block entirely readable. TODO: Find a better way */
	DWORD oldProtect;
	if (!VirtualProtect(source_addr, BLOCK_SIZE, PAGE_EXECUTE_READ, &oldProtect))
	{
		log_error("VirtualProtect(0x%p) failed, error code: %d\n", source_addr, GetLastError());
		return NULL;
	}
	CopyMemory(dest_addr, source_addr, BLOCK_SIZE);
	status = NtUnmapViewOfSection(NtCurrentProcess(), dest_addr);
	if (!NT_SUCCESS(status))
	{
		log_error("NtUnmapViewOfSection() failed, status: %x\n", status);
		return NULL;
	}
	return dest;
}

static int take_block_ownership(size_t block)
{
	HANDLE handle = get_section_handle(block);
	if (!handle)
	{
		log_error("Block %p not mapped.\n", block);
		return 0;
	}
	/* Query information about the section object which the page within */
	OBJECT_BASIC_INFORMATION info;
	NTSTATUS status;
	status = NtQueryObject(handle, ObjectBasicInformation, &info, sizeof(OBJECT_BASIC_INFORMATION), NULL);
	if (!NT_SUCCESS(status))
	{
		log_error("NtQueryObject() on block %p failed, status: 0x%x.\n", block, status);
		return 0;
	}
	if (info.HandleCount == 1)
	{
		log_info("We're the only owner.\n");
		return 1;
	}
	
	/* We are not the only one holding the section, duplicate it */
	log_info("Duplicating section %p...\n", block);
	HANDLE new_section;
	if (!(new_section = duplicate_section(handle, GET_BLOCK_ADDRESS(block))))
	{
		log_error("Duplicating section failed.\n");
		return 0;
	}
	log_info("Duplicating section succeeded. Remapping...\n");
	status = NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(block));
	if (!NT_SUCCESS(status))
	{
		log_error("Unmapping failed, status: %x\n", status);
		return 0;
	}
	status = NtClose(handle);
	if (!NT_SUCCESS(status))
	{
		log_error("NtClose() failed, status: %x\n", status);
		return 0;
	}
	PVOID base_addr = GET_BLOCK_ADDRESS(block);
	SIZE_T view_size = BLOCK_SIZE;
	status = NtMapViewOfSection(new_section, NtCurrentProcess(), &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		log_error("Remapping failed, status: %x\n", status);
		return 0;
	}
	replace_section_handle(block, new_section);
	return 1;
}

static int handle_cow_page_fault(void *addr)
{
	struct map_entry *entry = find_map_entry(addr);
	if (entry == NULL)
	{
		log_warning("No corresponding map entry found.\n");
		return 0;
	}
	if ((entry->prot & PROT_WRITE) == 0)
	{
		log_warning("Address %p (page %p) not writable.\n", addr, GET_PAGE(addr));
		return 0;
	}
	size_t block = GET_BLOCK(addr);

	if (!take_block_ownership(block))
		return 0;

	/* We're the only owner of the section now, change page protection flags */
	size_t start_page = GET_FIRST_PAGE_OF_BLOCK(block);
	size_t end_page = GET_LAST_PAGE_OF_BLOCK(block);
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (end_page < e->start_page)
			break;
		else
		{
			size_t range_start = max(start_page, e->start_page);
			size_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			DWORD oldProtect;
			if (!VirtualProtect(GET_PAGE_ADDRESS(range_start), PAGE_SIZE * (range_end - range_start + 1), prot_linux2win(e->prot), &oldProtect))
			{
				log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d.\n", GET_PAGE_ADDRESS(range_start),
					PAGE_SIZE * (range_end - range_start + 1), GetLastError());
				return 0;
			}
		}
	}
	log_info("CoW section %p successfully duplicated.\n", block);
	return 1;
}

static int handle_on_demand_page_fault(void *addr)
{
	size_t block = GET_BLOCK(addr);
	size_t page = GET_PAGE(addr);
	/* Map all map entries in the block */
	size_t start_page = GET_FIRST_PAGE_OF_BLOCK(block);
	size_t end_page = GET_LAST_PAGE_OF_BLOCK(block);
	struct map_entry *p, *e;
	int found = 0;
	allocate_block(block);
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (end_page < e->start_page)
			break;
		else
		{
			size_t range_start = max(start_page, e->start_page);
			size_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			if (page >= range_start && page <= range_end)
				found = 1;
			map_entry_range(e, range_start, range_end);
			if (e->prot != PROT_READ | PROT_WRITE | PROT_EXEC)
			{
				DWORD oldProtect;
				VirtualProtect(GET_PAGE_ADDRESS(range_start), (range_end - range_start + 1) * PAGE_SIZE, prot_linux2win(e->prot), &oldProtect);
			}
		}
	}
	/* TODO: Mark unmapped pages as PAGE_NOACCESS */
	if (!found)
		log_error("Block 0x%p not mapped.\n", GET_BLOCK(addr));
	else
		log_info("On demand block 0x%p loaded.\n", GET_BLOCK(addr));
	return found;
}

int mm_handle_page_fault(void *addr)
{
	log_info("Handling page fault at address %p (page %p)\n", addr, GET_PAGE(addr));
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH)
	{
		log_warning("Address %p outside of valid usermode address space.\n", addr);
		return 0;
	}
	AcquireSRWLockExclusive(&mm->rw_lock);
	int r;
	if (get_section_handle(GET_BLOCK(addr)))
		r = handle_cow_page_fault(addr);
	else
		r = handle_on_demand_page_fault(addr);
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return r;
}

int mm_fork(HANDLE process)
{
	AcquireSRWLockShared(&mm->rw_lock);
	/* Copy mm_data struct */
	if (!WriteProcessMemory(process, mm, mm, sizeof(struct mm_data), NULL))
	{
		log_error("mm_fork(): Write mm_data structure failed, error code: %d\n", GetLastError());
		return 0;
	}
	/* Copy section handle tables */
	HANDLE *forked_section_handle = VirtualAllocEx(process, NULL, BLOCK_COUNT * sizeof(HANDLE), MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
	WriteProcessMemory(process, &mm_section_handle, &forked_section_handle, sizeof(HANDLE *), NULL);
	for (size_t i = 0; i < SECTION_TABLE_COUNT; i++)
		if (mm->section_table_handle_count[i])
		{
			size_t j = i * SECTION_HANDLE_PER_TABLE;
			if (!VirtualAllocEx(process, &forked_section_handle[j], BLOCK_SIZE, MEM_COMMIT, PAGE_READWRITE))
			{
				log_error("mm_fork(): Allocate section table 0x%p failed, error code: %d\n", i, GetLastError());
				return 0;
			}
			if (!WriteProcessMemory(process, &forked_section_handle[j], &mm_section_handle[j], BLOCK_SIZE, NULL))
			{
				log_error("mm_fork(): Write section table 0x%p failed, error code: %d\n", i, GetLastError());
				return 0;
			}
		}
	size_t last_block = 0;
	size_t mapped_section_count = 0;
	size_t copied_section_count = 0;
	log_info("Mapping and changing memory protection...\n");
	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		/* Map section */
		size_t start_block = GET_BLOCK_OF_PAGE(e->start_page);
		size_t end_block = GET_BLOCK_OF_PAGE(e->end_page);
		if (start_block == last_block)
			start_block++;
		if (e->flags & INTERNAL_MAP_VIRTUALALLOC)
		{
			/* Memory region allocated via VirtualAlloc() */
			if (!VirtualAllocEx(process, GET_BLOCK_ADDRESS(start_block), (end_block - start_block + 1) * BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, prot_linux2win(e->prot)))
			{
				log_error("VirtualAllocEx() failed, error code: %d\n", GetLastError());
				mm_dump_windows_memory_mappings(process);
				return 0;
			}
			/* VirtualAlloc()-ed memory blocks are special, they can only be operated as a whole.
			 * They are never splitted and their protection flags are not stored in e->prot.
			 * Instead use VirtualQuery() to find out protection flags for each part of the memory block.
			 */
			/* Copy memory content to child process */
			size_t current = e->start_page;
			while (current <= e->end_page)
			{
				MEMORY_BASIC_INFORMATION info;
				if (!VirtualQuery(GET_PAGE_ADDRESS(current), &info, sizeof(info)))
				{
					log_error("VirtualQuery(%p) failed, error code: %d\n", current, GetLastError());
					mm_dump_memory_mappings();
					mm_dump_windows_memory_mappings(GetCurrentProcess());
					return 0;
				}
				size_t start_page = current;
				size_t end_page = min(e->end_page, GET_PAGE((size_t)info.BaseAddress + info.RegionSize));
				//assert(info.State == MEM_COMMIT && info.Type == MEM_PRIVATE);
				if (info.Protect == PAGE_NOACCESS || info.Protect == 0)
				{
					// FIXME: How to handle this case?
					log_warning("FIXME: PAGE_NOACCESS page ignored for copying. Range: [%p, %p)\n",
						GET_PAGE_ADDRESS(start_page), GET_PAGE_ADDRESS(end_page + 1));
				}
				else
				{
					/* TODO: Check unhandled/invalid protections */
					SIZE_T written;
					if (!WriteProcessMemory(process, GET_PAGE_ADDRESS(e->start_page), GET_PAGE_ADDRESS(e->start_page),
						(e->end_page - e->start_page + 1) * PAGE_SIZE, &written))
					{
						log_error("WriteProcessMemory() failed, error code: %d\n", GetLastError());
						mm_dump_windows_memory_mappings(process);
						return 0;
					}
				}
				/* Change memory protection */
				DWORD old;
				if (!VirtualProtectEx(process, GET_PAGE_ADDRESS(start_page), (end_page - start_page + 1) * PAGE_SIZE,
					info.Protect, &old))
				{
					log_error("VirtualProtectEx() failed, error code: %d\n", GetLastError());
					mm_dump_windows_memory_mappings(process);
					return 0;
				}
				current = end_page + 1;
			}
			continue;
		}
		for (size_t i = start_block; i <= end_block; i++)
		{
			HANDLE handle = get_section_handle(i);
			if (handle)
			{
				PVOID base_addr = GET_BLOCK_ADDRESS(i);
				SIZE_T view_size = BLOCK_SIZE;
				NTSTATUS status;
				if (e->flags & INTERNAL_MAP_COPYONFORK)
				{
					/* Use DUPLICATE_CLOSE_SOURCE to close section handle in child process */
					HANDLE dummy;
					if (!DuplicateHandle(process, handle, GetCurrentProcess(), &dummy, 0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
					{
						log_error("DuplicateHandle() failed, error code: %d\n", GetLastError());
						mm_dump_windows_memory_mappings(process);
						return 0;
					}
					/* Close the dummy duplicated handle */
					CloseHandle(dummy);
					/* Copy section memory */
					HANDLE duplicated_section = duplicate_section(handle, base_addr);
					/* Map section object to child */
					status = NtMapViewOfSection(duplicated_section, process, &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
					if (!NT_SUCCESS(status))
					{
						log_error("mm_fork(): Map failed: %p, status code: %x\n", base_addr, status);
						mm_dump_windows_memory_mappings(process);
						return 0;
					}
					/* Duplicate section handle to child */
					HANDLE child_handle;
					if (!DuplicateHandle(GetCurrentProcess(), handle, process, &child_handle, 0, TRUE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
					{
						log_error("DuplicateHandle() to child failed, error code: %d\n", GetLastError());
						mm_dump_windows_memory_mappings(process);
						return 0;
					}
					/* Copy section handle to child */
					replace_section_handle_ex(process, i, duplicated_section);
					copied_section_count++;
				}
				else
				{
					status = NtMapViewOfSection(handle, process, &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
					if (!NT_SUCCESS(status))
					{
						log_error("mm_fork(): Map failed: %p, status code: %x\n", base_addr, status);
						mm_dump_windows_memory_mappings(process);
						return 0;
					}
					mapped_section_count++;
				}
			}
		}
		last_block = end_block;
		/* Disable write permission on current process */
		if (!(e->flags & INTERNAL_MAP_SHARED) && (e->prot & PROT_WRITE) > 0)
		{
			if (!mm_change_protection(process, e->start_page, e->end_page, e->prot & ~PROT_WRITE))
				return 0;
			if (!mm_change_protection(GetCurrentProcess(), e->start_page, e->end_page, e->prot & ~PROT_WRITE))
				return 0;
		}
		else
		{
			if (!mm_change_protection(process, e->start_page, e->end_page, e->prot))
				return 0;
		}
	}
	log_info("Section object statistics: %d mapped CoW, %d copied.\n", mapped_section_count, copied_section_count);
	return 1;
}

void mm_afterfork_parent()
{
	ReleaseSRWLockShared(&mm->rw_lock);
}

void mm_afterfork_child()
{
	InitializeSRWLock(&mm->rw_lock);
	mm->static_alloc_begin = (uint8_t *)mm->static_alloc_end - MM_STATIC_ALLOC_SIZE;
	/* Remap global shared area */
	/* TODO: Move this to mm_fork(), since parent may already be terminated at this point */
	map_global_shared_section();
}

static void *mmap_internal(void *addr, size_t length, int prot, int flags, int internal_flags, struct file *f, off_t offset_pages)
{
	if (length == 0)
		return (void*)-L_EINVAL;
	length = ALIGN_TO_PAGE(length);
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < ADDRESS_SPACE_LOW || (size_t)addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < (size_t)addr)
		return (void*)-L_EINVAL;
	if ((flags & MAP_ANONYMOUS) && f != NULL)
	{
		log_error("MAP_ANONYMOUS with file descriptor.\n");
		return (void*)-L_EINVAL;
	}
	if (!(flags & MAP_ANONYMOUS) && f == NULL)
	{
		log_error("MAP_FILE with bad file descriptor.\n");
		return (void*)-L_EBADF;
	}
	if ((internal_flags & INTERNAL_MAP_VIRTUALALLOC) &&
		(!IS_ALIGNED(addr, BLOCK_SIZE) || !IS_ALIGNED(length, BLOCK_SIZE)))
	{
		log_error("INTERNAL_MAP_VIRTUALALLOC memory regions must be aligned on entire blocks.\n");
		return (void*)-L_EINVAL;
	}
	if ((flags & MAP_SHARED))
	{
		/* Translate to internal flag, which will be recorded in entry->flags */
		internal_flags |= INTERNAL_MAP_SHARED;
		/* Allocate memory immediately */
		flags |= MAP_POPULATE;
	}
	if ((flags & MAP_STACK))
	{
		/* Windows shows strange behaviour when the stack is on a shared section object */
		/* For example, it sometimes crashes when returning from a blocking system call */
		/* To avoid this, we always use VirtualAlloc() for holding stacks */
		internal_flags |= INTERNAL_MAP_VIRTUALALLOC;
	}

	bool block_align = BLOCK_ALIGNED(internal_flags);
	if ((flags & MAP_FIXED))
	{
		if (block_align && !IS_ALIGNED(addr, BLOCK_SIZE))
		{
			log_error("Non-64kB aligned MAP_FIXED address with the suppied flag is unsupported.\n");
			return (void*)-L_ENOMEM;
		}
		if (!IS_ALIGNED(addr, PAGE_SIZE))
		{
			log_warning("Not page-aligned addr with MAP_FIXED.\n");
			return (void*)-L_EINVAL;
		}
		if (!IS_ALIGNED(addr, BLOCK_SIZE))
		{
			/* For block unaligned fixed allocation, ensure it does not collide with block aligned memory regions */
			/* Get the previous node whose start_page should be less than or equal to current page minus one */
			struct rb_node *prev_node = start_node(GET_PAGE(addr) - 1);
			if (prev_node) /* If previous node exists... */
			{
				struct map_entry *prev_entry = rb_entry(prev_node, struct map_entry, tree);
				if (BLOCK_ALIGNED(prev_entry->flags) && GET_BLOCK_OF_PAGE(prev_entry->end_page) == GET_BLOCK(addr))
				{
					log_error("MAP_FIXED addr collides with an existing MAP_SHARED memory region.\n");
					return (void*)-L_ENOMEM;
				}
			}
		}
	}
	else /* MAP_FIXED */
	{
		size_t alloc_page;
		if (internal_flags & INTERNAL_MAP_TOPDOWN)
			alloc_page = find_free_pages_topdown(GET_PAGE(ALIGN_TO_PAGE(length)), block_align);
		else
			alloc_page = find_free_pages(GET_PAGE(ALIGN_TO_PAGE(length)), block_align);
		if (!alloc_page)
		{
			log_error("Cannot find free pages.\n");
			return (void*)-L_ENOMEM;
		}

		addr = GET_PAGE_ADDRESS(alloc_page);
	}

	size_t start_page = GET_PAGE(addr);
	size_t end_page = GET_PAGE((size_t)addr + length - 1);
	size_t start_block = GET_BLOCK(addr);
	size_t end_block = GET_BLOCK((size_t)addr + length - 1);

	/*
	 * If address are fixed, unmap conflicting pages,
	 * Otherwise the pages are found by find_free_pages() thus are guaranteed free.
	 */
	if ((flags & MAP_FIXED))
	{
		if (internal_flags & INTERNAL_MAP_NOOVERWRITE)
		{
			/* The caller does not want to overwrite existing pages
			 * Check whether it is possible before doing anything
			 */
			for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
			{
				struct map_entry *e = rb_entry(cur, struct map_entry, tree);
				if (end_page < e->start_page)
					break;
				else if (start_page <= e->end_page && e->start_page <= end_page)
					return (void*)-L_ENOMEM;
			}
		}
		else
		{
			static int munmap_internal(void *addr, size_t length);
			munmap_internal(addr, length);
		}
	}

	/* Set up all kinds of flags */
	struct map_entry *entry = new_map_entry();
	entry->start_page = start_page;
	entry->end_page = end_page;
	entry->f = f;
	entry->offset_pages = offset_pages;
	entry->prot = prot;
	if (f)
		vfs_ref(f);
	entry->flags = 0;
	if (internal_flags & INTERNAL_MAP_NORESET)
		entry->flags |= INTERNAL_MAP_NORESET;
	if (internal_flags & INTERNAL_MAP_VIRTUALALLOC)
		entry->flags |= INTERNAL_MAP_VIRTUALALLOC;
	if (internal_flags & INTERNAL_MAP_COPYONFORK)
		entry->flags |= INTERNAL_MAP_COPYONFORK;

	rb_add(&mm->entry_tree, &entry->tree, map_entry_cmp);

	if (internal_flags & INTERNAL_MAP_VIRTUALALLOC)
	{
		/* Allocate the memory now */
		if (!VirtualAlloc(GET_PAGE_ADDRESS(start_page), (end_page - start_page + 1) * PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, prot_linux2win(prot)))
		{
			log_error("VirtualAlloc(%p, %p) failed, error code: %d\n", GET_PAGE_ADDRESS(start_page),
				(end_page - start_page + 1) * PAGE_SIZE, GetLastError());
			mm_dump_windows_memory_mappings(GetCurrentProcess());
			return (void*)-L_ENOMEM;
		}
	}

	/* If the first or last block is already allocated, we have to set up proper content in it
	   For other blocks we map them on demand */
	if (get_section_handle(start_block))
	{
		if (!take_block_ownership(start_block))
		{
			log_error("Taking ownership of block %p failed.\n", start_block);
			return (void*)-L_ENOMEM;
		}
		size_t last_page = GET_LAST_PAGE_OF_BLOCK(start_block);
		last_page = min(last_page, end_page);
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(start_page), (last_page - start_page + 1) * PAGE_SIZE, prot_linux2win(prot | PROT_WRITE), &oldProtect);
		map_entry_range(entry, start_page, last_page);
		if ((prot & PROT_WRITE) == 0)
			VirtualProtect(GET_PAGE_ADDRESS(start_page), (last_page - start_page + 1) * PAGE_SIZE, prot_linux2win(prot), &oldProtect);
		start_block++;
	}
	if (end_block >= start_block && get_section_handle(end_block))
	{
		if (!take_block_ownership(end_block))
		{
			log_error("Taking ownership of block %p failed.\n", start_block);
			return (void*)-L_ENOMEM;
		}
		size_t first_page = GET_FIRST_PAGE_OF_BLOCK(end_block);
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(first_page), (end_page - first_page + 1) * PAGE_SIZE, prot_linux2win(prot | PROT_WRITE), &oldProtect);
		map_entry_range(entry, first_page, end_page);
		if ((prot & PROT_WRITE) == 0)
			VirtualProtect(GET_PAGE_ADDRESS(first_page), (end_page - first_page + 1) * PAGE_SIZE, prot_linux2win(prot), &oldProtect);
		end_block--;
	}
	if ((flags & MAP_POPULATE) && start_block < end_block)
	{
		for (size_t i = start_block; i <= end_block; i++)
			allocate_block(i);
		map_entry_range(entry, GET_FIRST_PAGE_OF_BLOCK(start_block), GET_LAST_PAGE_OF_BLOCK(end_block));
		mm_change_protection(GetCurrentProcess(), GET_FIRST_PAGE_OF_BLOCK(start_block), GET_LAST_PAGE_OF_BLOCK(end_block), prot);
	}
	log_info("Allocated memory: [%p, %p)\n", addr, (size_t)addr + length);
	return addr;
}

static int munmap_internal(void *addr, size_t length)
{
	/* TODO: We should mark NOACCESS for munmap()-ed but not VirtualFree()-ed pages */
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -L_EINVAL;
	length = ALIGN_TO_PAGE(length);
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < ADDRESS_SPACE_LOW || (size_t)addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < (size_t)addr)
	{
		return -L_EINVAL;
	}

	size_t start_page = GET_PAGE(addr);
	size_t end_page = GET_PAGE((size_t)addr + length - 1);
	for (struct rb_node *cur = start_node(start_page); cur;)
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (end_page < e->start_page)
			break;
		else
		{
			size_t range_start = max(start_page, e->start_page);
			size_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
			{
				cur = rb_next(cur);
				continue;
			}
			if (range_start == e->start_page && range_end == e->end_page)
			{
				/* That's good, the current entry is fully overlapped */
				if (e->prot & PROT_EXEC)
				{
					/* Notify dbt subsystem the executable pages has been lost */
					dbt_code_changed((size_t)GET_PAGE_ADDRESS(e->start_page), (e->end_page - e->start_page + 1) * PAGE_SIZE);
				}
				struct rb_node *next = rb_next(cur);
				free_map_entry_blocks(e);
				rb_remove(&mm->entry_tree, cur);
				free_map_entry(e);
				cur = next;
			}
			else
			{
				/* Not so good, part of current entry is overlapped */
				if (range_start == e->start_page)
				{
					split_map_entry(e, range_end);
					struct rb_node *next = rb_next(cur);
					free_map_entry_blocks(e);
					rb_remove(&mm->entry_tree, cur);
					free_map_entry(e);
					cur = next;
				}
				else
				{
					split_map_entry(e, range_start - 1);
					/* The current entry is unrelated, we just skip to next entry (which we just generated) */
					cur = rb_next(cur);
				}
			}
		}
	}
	return 0;
}

void *mm_mmap(void *addr, size_t length, int prot, int flags, int internal_flags, struct file *f, off_t offset_pages)
{
	AcquireSRWLockExclusive(&mm->rw_lock);
	void *r = mmap_internal(addr, length, prot, flags, internal_flags, f, offset_pages);
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return r;
}

int mm_munmap(void *addr, size_t length)
{
	AcquireSRWLockExclusive(&mm->rw_lock);
	int r = munmap_internal(addr, length);
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return r;
}

DEFINE_SYSCALL(mmap, void *, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset)
{
	/* TODO: We should mark NOACCESS for VirtualAlloc()-ed but currently unused pages */
	log_info("mmap(%p, %p, %x, %x, %d, %p)\n", addr, length, prot, flags, fd, offset);
	/* TODO: Initialize mapped area to zero */
	if (!IS_ALIGNED(offset, PAGE_SIZE))
		return -L_EINVAL;
	struct file *f = vfs_get(fd);
	intptr_t r = (intptr_t)mm_mmap(addr, length, prot, flags, 0, f, offset / PAGE_SIZE);
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(oldmmap, void *, _args)
{
	log_info("oldmmap(%p)\n", _args);
	struct oldmmap_args_t
	{
		void *addr;
		unsigned long len;
		unsigned long prot;
		unsigned long flags;
		unsigned long fd;
		unsigned long offset;
	};
	struct oldmmap_args_t *args = _args;
	return sys_mmap(args->addr, args->len, args->prot, args->flags, args->fd, args->offset);
}

DEFINE_SYSCALL(mmap2, void *, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset)
{
	log_info("mmap2(%p, %p, %x, %x, %d, %p)\n", addr, length, prot, flags, fd, offset);
	struct file *f = vfs_get(fd);
	intptr_t r = (intptr_t)mm_mmap(addr, length, prot, flags, 0, f, offset);
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(munmap, void *, addr, size_t, length)
{
	log_info("munmap(%p, %p)\n", addr, length);
	return mm_munmap(addr, length);
}

DEFINE_SYSCALL(mprotect, void *, addr, size_t, length, int, prot)
{
	log_info("mprotect(%p, %p, %x)\n", addr, length, prot);
	int r = 0;
	AcquireSRWLockExclusive(&mm->rw_lock);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
	{
		r = -L_EINVAL;
		goto out;
	}
	length = ALIGN_TO_PAGE(length);
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < ADDRESS_SPACE_LOW || (size_t)addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < (size_t)addr)
	{
		r = -L_EINVAL;
		goto out;
	}
	/* Validate all pages are mapped */
	size_t start_page = GET_PAGE(addr);
	size_t end_page = GET_PAGE((size_t)addr + length - 1);
	size_t last_page = start_page - 1;
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (e->start_page > end_page)
			break;
		else if (e->end_page >= start_page)
		{
			if (e->start_page == last_page + 1)
				last_page = e->end_page;
			else
				break;
		}
	}
	if (last_page < end_page)
	{
		r = -L_ENOMEM;
		goto out;
	}

	/* Change protection flags */
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (end_page < e->start_page)
			break;
		else
		{
			size_t range_start = max(start_page, e->start_page);
			size_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			/* Do not split VirtualAlloc()-ed memory regions, so we can deal with the entire entry at mm_fork() */
			if ((e->flags & INTERNAL_MAP_VIRTUALALLOC))
				continue;
			if ((range_start == e->start_page && range_end == e->end_page))
			{
				/* That's good, the current entry is fully overlapped */
				e->prot = prot;
			}
			else
			{
				/* Not so good, part of current entry is overlapped, we need to split the entry */
				if (range_start == e->start_page)
				{
					split_map_entry(e, range_end);
					e->prot = prot;
				}
				else
				{
					split_map_entry(e, range_start - 1);
					/* The current entry is unrelated, we just skip to next entry (which we just generated) */
				}
			}
		}
	}
	if (!mm_change_protection(GetCurrentProcess(), start_page, end_page, prot & ~PROT_WRITE))
	{
		/* We remove the write protection in case the pages are already shared */
		r = -L_ENOMEM; /* TODO */
		goto out;
	}

out:
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return r;
}

DEFINE_SYSCALL(msync, void *, addr, size_t, len, int, flags)
{
	log_info("msync(0x%p, 0x%p, %d)\n", addr, len, flags);
	log_error("msync() not implemented.\n");
	return -L_ENOSYS;
}

static int mm_populate_internal(const void *addr, size_t len)
{
	size_t start_page = GET_PAGE(addr);
	size_t end_page = GET_PAGE((size_t)addr + len);
	size_t num_blocks = 0;
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (e->start_page > end_page)
			break;
		else
		{
			size_t range_start = max(start_page, e->start_page);
			size_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;

			size_t start_block = GET_BLOCK_OF_PAGE(range_start);
			size_t end_block = GET_BLOCK_OF_PAGE(range_end);
			/* TODO: Optimization: batch operation on continuous blocks */
			for (size_t i = start_block; i <= end_block; i++)
				if (get_section_handle(i))
					continue;
				else
				{
					if (!allocate_block(i))
						return -L_ENOMEM;
					num_blocks++;
					size_t first_page = max(range_start, GET_FIRST_PAGE_OF_BLOCK(i));
					size_t last_page = min(range_end, GET_LAST_PAGE_OF_BLOCK(i));
					map_entry_range(e, first_page, last_page);
					if (e->prot != PROT_READ | PROT_WRITE | PROT_EXEC)
					{
						DWORD oldProtect;
						VirtualProtect(GET_PAGE_ADDRESS(first_page), (last_page - first_page + 1) * PAGE_SIZE, prot_linux2win(e->prot), &oldProtect);
					}
				}
		}
	}
	log_info("Populated memory blocks: %d\n", num_blocks);
	/* TODO: Mark unused pages as NOACCESS */
	return 0;
}

void mm_populate(void *addr)
{
	AcquireSRWLockExclusive(&mm->rw_lock);
	size_t page = GET_PAGE(addr);
	struct rb_node *cur = start_node(page);
	struct map_entry *e = rb_entry(cur, struct map_entry, tree);
	if (e->start_page <= page && page <= e->end_page)
		mm_populate_internal(GET_PAGE_ADDRESS(e->start_page), (e->end_page - e->start_page + 1) * PAGE_SIZE);
	ReleaseSRWLockExclusive(&mm->rw_lock);
}

DEFINE_SYSCALL(mlock, const void *, addr, size_t, len)
{
	log_info("mlock(0x%p, 0x%p)\n", addr, len);
	int r = 0;
	AcquireSRWLockExclusive(&mm->rw_lock);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
	{
		r = -L_EINVAL;
		goto out;
	}

	/* All on demand page must be properly loaded or the locking operation will fail */
	r = mm_populate_internal(addr, len);
	if (!r)
		goto out;

	/* The actual locking */
	/* TODO: Automatically enlarge working set size for arbitrary sized mlock() call */
	if (!VirtualLock((LPVOID)addr, len))
	{
		log_warning("VirtualLock() failed, error code: %d\n", GetLastError());
		r = -L_ENOMEM;
		goto out;
	}
	ReleaseSRWLockExclusive(&mm->rw_lock);

out:
	return r;
}

DEFINE_SYSCALL(munlock, const void *, addr, size_t, len)
{
	log_info("munlock(0x%p, 0x%p)\n", addr, len);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -L_EINVAL;
	if (!VirtualUnlock((LPVOID)addr, len))
	{
		log_warning("VirtualUnlock() failed, error code: %d\n", GetLastError());
		return -L_ENOMEM;
	}
	return 0;
}

DEFINE_SYSCALL(mremap, void *, old_address, size_t, old_size, size_t, new_size, int, flags, void *, new_address)
{
	log_info("mremap(old_address=%p, old_size=%p, new_size=%p, flags=%x, new_address=%p)\n", old_address, old_size, new_size, flags, new_address);
	log_error("mremap() not implemented.\n");
	return -L_ENOSYS;
}

DEFINE_SYSCALL(madvise, void *, addr, size_t, length, int, advise)
{
	log_info("madvise(%p, %p, %x)\n", addr, length, advise);
	/* Notes behaviour-changing advices, other non-critical advises are ignored for now */
	if (advise & MADV_DONTFORK)
		log_error("MADV_DONTFORK not supported.\n");
	return 0;
}

DEFINE_SYSCALL(brk, void *, addr)
{
	log_info("brk(%p)\n", addr);
	log_info("Last brk: %p\n", mm->brk);
	AcquireSRWLockExclusive(&mm->rw_lock);
	size_t brk = ALIGN_TO_PAGE(mm->brk);
	addr = (void*)ALIGN_TO_PAGE(addr);
	if (addr > 0 && addr < mm->brk)
	{
		if (munmap_internal(addr, (size_t)brk - (size_t)addr) < 0)
		{
			log_error("Shrink brk failed.\n");
			goto out;
		}
		mm->brk = addr;
	}
	else if (addr > mm->brk)
	{
		int r = (int)mmap_internal((void *)brk, (size_t)addr - (size_t)brk, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, INTERNAL_MAP_NOOVERWRITE, NULL, 0);
		if (r < 0)
		{
			log_error("Enlarge brk failed.\n");
			goto out;
		}
		mm->brk = addr;
	}
out:
	ReleaseSRWLockExclusive(&mm->rw_lock);
	log_info("New brk: %p\n", mm->brk);
	return (intptr_t)mm->brk;
}
