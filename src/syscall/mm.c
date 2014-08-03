#include "mm.h"
#include "errno.h"
#include "../log.h"

#include <stdint.h>
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

/* Overall memory layout
 *
 * FFFFFFFF ------------------------------
 * ...        Win32 kernel address space
 * 80000000 ------------------------------
 * ...                win32 dlls
 * 75000000 ------------------------------
 * ...
 * ...          Application code/data
 * ...
 * 03000000 ------------------------------
 * ...        Foreign Linux kernel data
 * 02000000 ------------------------------
 * ...        Foreign Linux kernel code
 * 00000000 ------------------------------
 *
 *
 * Foreign Linux kernel data memory layout
 *
 * 03000000 ------------------------------
 *                fork_info structure
 * 02FF0000 ------------------------------
 *               TLS trampoline buffer
 * 02FE0000 ------------------------------
 *                vfs_data structure
 * 02900000 ------------------------------
 *              mm_heap_data structure
 * 02800000 ------------------------------
 *        process_data structure(unmappable)
 * 02700000 ------------------------------
 *           mm_data structure(unmappable)
 * 02000000 ------------------------------
 */

/* Hard limits */
/* Maximum number of mmap()-ed areas */
#define MAX_MMAP_COUNT 65535

/* OS-specific constants */
/* Lower bound of the virtual address space */
#define ADDRESS_SPACE_LOW 0x00000000U
/* Higher bound of the virtual address space */
#define ADDRESS_SPACE_HIGH 0x80000000U
/* The lowest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_LOW 0x03000000U
/* The highest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_HIGH 0x80000000U

#define BLOCK_COUNT 0x00010000U
#define PAGE_COUNT 0x00100000U
#define PAGES_PER_BLOCK 16

/* Helper macros */
#define IS_ALIGNED(addr, alignment) ((size_t) (addr) % (size_t) (alignment) == 0)
#define ALIGN_TO_BLOCK(addr) (((size_t) addr + BLOCK_SIZE - 1) & 0xFFFF0000)
#define ALIGN_TO_PAGE(addr) (((size_t) addr + PAGE_SIZE - 1) & 0xFFFFF000)
#define GET_BLOCK(addr) ((size_t) (addr) / BLOCK_SIZE)
#define GET_PAGE(addr) ((size_t) (addr) / PAGE_SIZE)
#define GET_PAGE_IN_BLOCK(page) ((page) % PAGES_PER_BLOCK)
#define GET_BLOCK_OF_PAGE(page) ((page) / PAGES_PER_BLOCK)
#define GET_FIRST_PAGE_OF_BLOCK(block)	((block) * PAGES_PER_BLOCK)
#define GET_BLOCK_ADDRESS(block) (void *)((block) * BLOCK_SIZE)
#define GET_PAGE_ADDRESS(page) (void *)((page) * PAGE_SIZE)

struct map_entry
{
	uint32_t start_page;
	uint32_t end_page;
	struct map_entry *next;
};

struct mm_data
{
	/* Program break address, brk() will use this */
	void *brk;

	/* Information for all existing mappings */
	struct map_entry *map_list, *map_free_list;
	struct map_entry map_entries[MAX_MMAP_COUNT];

	/* Section object handle of a block */
	HANDLE block_section_handle[BLOCK_COUNT];
	/* Number of allocated pages inside a allocation region */
	uint8_t block_page_count[BLOCK_COUNT];

	/* Protection flags for a given page */
	uint8_t page_prot[PAGE_COUNT];
};
static struct mm_data *const mm = MM_DATA_BASE;

void mm_init()
{
	VirtualAlloc(MM_DATA_BASE, sizeof(struct mm_data), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	/* Initialize mapping info freelist */
	for (uint16_t i = 0; i + 1 < MAX_MMAP_COUNT; i++)
		mm->map_entries[i].next = &mm->map_entries[i + 1];
	mm->map_list = NULL;
	mm->map_free_list = &mm->map_entries[0];
	mm->map_entries[MAX_MMAP_COUNT - 1].next = NULL;
}

void mm_shutdown()
{
}

void mm_update_brk(void *brk)
{
	mm->brk = max(mm->brk, brk);
}

static struct map_entry *new_map_entry()
{
	if (mm->map_free_list)
	{
		struct map_entry *entry = mm->map_free_list;
		mm->map_free_list = mm->map_free_list->next;
		return entry;
	}
	return NULL;
}

static void free_map_entry(struct map_entry *entry)
{
	entry->next = mm->map_free_list;
	mm->map_free_list = entry;
}

/* Determine if range [start_page, end_page] of pages are all free */
static int is_pages_free(uint32_t start_page, uint32_t end_page)
{
	for (struct map_entry *e = mm->map_list; e; e = e->next)
		if (e->start_page > end_page)
			return 1;
		else if (e->start_page >= start_page || e->end_page >= start_page)
			return 0;
	return 1;
}

/* Find 'count' consecutive free pages, return 0 if not found */
static uint32_t find_free_pages(uint32_t count)
{
	uint32_t last = GET_PAGE(ADDRESS_ALLOCATION_LOW);
	for (struct map_entry *e = mm->map_list; e; e = e->next)
		if (e->start_page >= GET_PAGE(ADDRESS_ALLOCATION_LOW))
			if (e->start_page - last >= count)
				return last;
			else
				last = e->end_page + 1;
	if (GET_PAGE(ADDRESS_ALLOCATION_HIGH) - last >= count)
		return last;
	else
		return 0;
}

/* Find map entry of given address, also return the preceding entry (NULL if first) */
static int find_entry(void *addr, struct map_entry **entry, struct map_entry **pred)
{
	uint32_t page = GET_PAGE(addr);
	struct map_entry *p = NULL;
	for (struct map_entry *e = mm->map_list; e; p = e, e = e->next)
		if (page > e->end_page)
			return 0;
		else if (page >= e->start_page && page <= e->end_page)
		{
			*entry = e;
			*pred = p;
			return 1;
		}
	return 0;
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

static void dump_virtual_memory(HANDLE process)
{
	char *addr = 0;
	do
	{
		MEMORY_BASIC_INFORMATION info;
		VirtualQueryEx(process, addr, &info, sizeof(info));
		if (info.State != MEM_FREE)
		{
			char filename[1024];
			if (GetMappedFileNameA(process, addr, filename, sizeof(filename)))
				log_debug("0x%08x - 0x%08x <--- %s\n", info.BaseAddress, (uint32_t)info.BaseAddress + info.RegionSize, filename);
			else
				log_debug("0x%08x - 0x%08x\n", info.BaseAddress, (uint32_t)info.BaseAddress + info.RegionSize);
		}
		addr += info.RegionSize;
	} while ((uint32_t)addr < 0x7FFF0000);
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
	if (status != STATUS_SUCCESS)
		return NULL;
	
	NtMapViewOfSection(dest, NtCurrentProcess(), &dest_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);
	CopyMemory(dest_addr, source_addr, BLOCK_SIZE);
	NtUnmapViewOfSection(NtCurrentProcess(), dest_addr);
	return dest;
}

int mm_handle_page_fault(void *addr)
{
	log_debug("Handling page fault at address %x (page %x)\n", addr, GET_PAGE(addr));
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH)
	{
		log_debug("Address %x outside of valid usermode address space.\n", addr);
		return 0;
	}
	if (mm->page_prot[GET_PAGE(addr)] & PROT_WRITE == 0)
	{
		log_debug("Address %x (page %x) not writtable.\n", addr, GET_PAGE(addr));
		return 0;
	}
	uint16_t block = GET_BLOCK(addr);
	if (mm->block_section_handle[block] == NULL)
	{
		log_debug("Address %x (page %x) not mapped.\n", addr, GET_PAGE(addr));
		return 0;
	}
	/* Query information about the section object which the page within */
	OBJECT_BASIC_INFORMATION info;
	NTSTATUS status;
	status = NtQueryObject(mm->block_section_handle[block], ObjectBasicInformation, &info, sizeof(OBJECT_BASIC_INFORMATION), NULL);
	if (status != STATUS_SUCCESS)
	{
		log_debug("NtQueryObject() on section %x failed.\n", block);
		return 0;
	}
	if (info.HandleCount > 1)
	{
		/* We are not the only one holding the section, duplicate it */
		log_debug("Duplicating section %x...\n", block);
		HANDLE section;
		if (!(section = duplicate_section(mm->block_section_handle[block], GET_BLOCK_ADDRESS(block))))
		{
			log_debug("Duplicating section failed.");
			return 0;
		}
		else
			log_debug("Duplicating section succeeded. Remapping...");
		NtClose(mm->block_section_handle[block]);
		mm->block_section_handle[block] = section;
		PVOID base_addr = GET_BLOCK_ADDRESS(block);
		SIZE_T view_size = BLOCK_SIZE;
		NtMapViewOfSection(section, NtCurrentProcess(), &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	}
	/* We're the only owner of the section now, change page protection flags */
	for (uint16_t i = 0; i < PAGES_PER_BLOCK; i++)
	{
		uint16_t page = GET_FIRST_PAGE_OF_BLOCK(block) + i;
		VirtualProtect(GET_PAGE_ADDRESS(page), PAGE_SIZE, prot_linux2win(mm->page_prot[page]), NULL);
	}
	return 1;
}

int mm_fork(HANDLE process)
{
	/* Copy mm_data struct */
	if (!VirtualAllocEx(process, MM_DATA_BASE, sizeof(struct mm_data), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
	{
		log_debug("mm_fork(): Allocate mm_data structure failed, error code: %d\n", GetLastError());
		return 0;
	}
	if (!WriteProcessMemory(process, MM_DATA_BASE, mm, sizeof(struct mm_data), NULL))
	{
		log_debug("mm_fork(): Write mm_data structure failed, error code: %d\n", GetLastError());
		return 0;
	}
	/* Map sections */
	for (uint32_t i = 0; i < BLOCK_COUNT; i++)
		if (mm->block_section_handle[i])
		{
			PVOID base_addr = GET_BLOCK_ADDRESS(i);
			SIZE_T view_size = BLOCK_SIZE;
			NTSTATUS status;
			status = NtMapViewOfSection(mm->block_section_handle[i], process, &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
			if (status != STATUS_SUCCESS)
			{
				log_debug("mm_fork(): Map failed: %x, status code: %x\n", base_addr, status);
				dump_virtual_memory(process);
				return 0;
			}
		}
	/* Disable write permission on pages */
	for (uint32_t i = 0; i < MAX_MMAP_COUNT; i++)
		if (mm->map_entries[i].start_page != 0)
			for (uint32_t j = mm->map_entries[i].start_page; j <= mm->map_entries[i].end_page; j++)
			{
				VirtualProtectEx(process, GET_PAGE_ADDRESS(j), PAGE_SIZE, prot_linux2win(mm->page_prot[j] & ~PROT_WRITE), NULL);
				VirtualProtect(GET_PAGE_ADDRESS(j), PAGE_SIZE, prot_linux2win(mm->page_prot[j] & ~PROT_WRITE), NULL);
			}
	return 1;
}

void *mm_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset_pages)
{
	/* TODO: errno */
	if (length == 0)
		return NULL;
	length = ALIGN_TO_PAGE(length);
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < ADDRESS_SPACE_LOW || (size_t)addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < (size_t)addr)
		return NULL;
	if (flags & MAP_SHARED)
		return NULL;
	if (!(flags & MAP_ANONYMOUS))
		return NULL;
	if (!(flags & MAP_FIXED))
	{
		uint32_t alloc_page = find_free_pages(GET_PAGE(ALIGN_TO_PAGE(length)));
		if (!alloc_page)
			return NULL;

		addr = GET_PAGE_ADDRESS(alloc_page);
	}
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return NULL;
	if (flags & MAP_ANONYMOUS)
	{
		uint32_t start_page = GET_PAGE(addr);
		uint32_t end_page = GET_PAGE((size_t)addr + length - 1);
		uint16_t start_block = GET_BLOCK(addr);
		uint16_t end_block = GET_BLOCK((size_t)addr + length - 1);

		/* If address are given, test whether all pages are free.
		 * Otherwise the pages are found by find_free_pages() thus are guaranteed free.
		 */
		if ((flags & MAP_FIXED) && !is_pages_free(start_page, end_page))
			return NULL;

		/* Allocate and map missing section objects */
		for (uint16_t i = start_block; i <= end_block; i++)
		{
			if (mm->block_page_count[i] == 0)
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
				if (status != STATUS_SUCCESS)
				{
					log_debug("NtCreateSection() failed. Status: %x\n", status);
					goto ROLLBACK;
				}

				/* Map section */
				PVOID base_addr = GET_BLOCK_ADDRESS(i);
				SIZE_T view_size = BLOCK_SIZE;
				status = NtMapViewOfSection(handle, NtCurrentProcess(), &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, prot_linux2win(prot));
				if (status != STATUS_SUCCESS)
				{
					log_debug("NtMapViewOfSection() failed. Address: %x, Status: %x\n", base_addr, status);
					NtClose(handle);
					dump_virtual_memory(NtCurrentProcess());
					goto ROLLBACK;
				}
				mm->block_section_handle[i] = handle;
				continue;

			ROLLBACK:
				/* Roll back */
				for (uint16_t j = start_block; j < i; j++)
				{
					if (mm->block_page_count[j] == 0)
					{
						NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(j));
						NtClose(mm->block_section_handle[j]);
						mm->block_section_handle[j] = NULL;
					}
				}
				return NULL;
			}
		}

		/* Set up all kinds of flags */
		struct map_entry *entry = new_map_entry();
		entry->start_page = start_page;
		entry->end_page = end_page;
		if (!mm->map_list || mm->map_list->start_page > end_page)
		{
			if (mm->map_list)
				entry->next = mm->map_list->next;
			mm->map_list = entry;
		}
		else
		{
			for (struct map_entry *e = mm->map_list; e; e = e->next)
				if (!e->next || e->next->start_page > end_page)
				{
					entry->next = e->next;
					e->next = entry;
					break;
				}
		}
		for (uint32_t i = start_page; i <= end_page; i++)
		{
			mm->page_prot[i] = prot;
			mm->block_page_count[GET_BLOCK_OF_PAGE(i)]++; /* TODO: Optimization */
		}
		return addr;
	}
	return NULL;
}

int mm_munmap(void *addr, size_t length)
{
	/* TODO: We should mark NOACCESS for munmap()-ed but not VirtualFree()-ed pages */
	/* TODO: We currently only support unmap full pages */
	/* TODO: errno */
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -1;
	length = ALIGN_TO_PAGE(length);
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < ADDRESS_SPACE_LOW || (size_t)addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < (size_t)addr)
	{
		return -1;
	}

	struct map_entry *entry, *pred;
	if (!find_entry(addr, &entry, &pred))
	{
		return 0;
	}
	uint32_t start_page = entry->start_page;
	uint32_t end_page = entry->end_page;
	/* Don't allow partial free */
	if (GET_PAGE((size_t)addr + length - 1) != end_page)
	{
		return -1;
	}
	/* Remove entry from entry list */
	if (pred == NULL)
		mm->map_list = entry->next;
	else
		pred->next = entry->next;
	/* Add entry to free list */
	free_map_entry(entry);
	for (uint32_t i = start_page; i <= end_page; i++)
		mm->block_page_count[GET_BLOCK_OF_PAGE(i)]--; /* TODO: Optimization */
	/* Free unused memory allocations */
	uint16_t start_block = GET_BLOCK_OF_PAGE(start_page);
	uint16_t end_block = GET_BLOCK_OF_PAGE(end_page);
	for (uint16_t i = start_block; i <= end_block; i++)
	{
		if (mm->block_page_count[i] == 0)
		{
			NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
			NtClose(mm->block_section_handle[i]);
			mm->block_section_handle[i] = NULL;
		}
	}
	return 0;
}

void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	/* TODO: We should mark NOACCESS for VirtualAlloc()-ed but currently unused pages */
	log_debug("mmap(%x, %x, %x, %x, %d, %x)\n", addr, length, prot, flags, fd, offset);
	/* TODO: Initialize mapped area to zero */
	/* TODO: errno */
	if (!IS_ALIGNED(offset, PAGE_SIZE))
		return NULL;
	return mm_mmap(addr, length, prot, flags, fd, offset / PAGE_SIZE);
}

void *sys_oldmmap(void *_args)
{
	log_debug("oldmmap(%x)\n", _args);
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

void *sys_mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	log_debug("mmap2(%x, %x, %x, %x, %d, %x)\n", addr, length, prot, flags, fd, offset);
	return mm_mmap(addr, length, prot, flags, fd, offset);
}

int sys_munmap(void *addr, size_t length)
{
	log_debug("munmap(%x, %x)\n", addr, length);
	return mm_munmap(addr, length);
}

int sys_mprotect(void *addr, size_t len, int prot)
{
	/* TODO */
}

int sys_msync(void *addr, size_t len, int flags)
{
	/* TODO */
}

int sys_mlock(const void *addr, size_t len)
{
	/* TODO */
}

int sys_munlock(const void *addr, size_t len)
{
	/* TODO */
}

void *sys_brk(void *addr)
{
	log_debug("brk(%x)\n", addr);
	log_debug("Last brk: %x\n", mm->brk);
	addr = ALIGN_TO_PAGE(addr);
	/* TODO: Handle brk shrink */
	if (addr > mm->brk)
	{
		if (!sys_mmap(mm->brk, (uint32_t)addr - (uint32_t)mm->brk, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
			return -1;
		mm->brk = addr;
	}
	log_debug("New brk: %x\n", mm->brk);
	return mm->brk;
}
