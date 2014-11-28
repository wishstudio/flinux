#include <common/errno.h>
#include <core/forward_list.h>
#include <syscall/mm.h>
#include <syscall/vfs.h>
#include <log.h>

#include <stdint.h>
#include <ntdll.h>
#include <Windows.h>
#include <Psapi.h>

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

/* Overall memory layout (x86)
 *
 * FFFFFFFF ------------------------------
 * ...        Win32 kernel address space
 * ...         (unused if 4gt enabled)
 * 80000000 ------------------------------
 * ...                win32 dlls
 * 72000000 ------------------------------
 * ...        Foreign Linux kernel data
 * 70000000 ------------------------------
 * ...
 * ...          Application code/data
 * ...
 * 04000000 ------------------------------
 * ...            Win32 system heaps
 * ...        Foreign Linux kernel code
 * 00000000 ------------------------------
 *
 *
 * Foreign Linux kernel data memory layout
 *
 * 72000000 ------------------------------
 *                    kernel heap
 * 71000000 ------------------------------
 *                fork_info structure
 * 70FF0000 ------------------------------
 *             startup (argv, env) data
 * 70FE0000 ------------------------------
 *                tls_data structure
 * 70FD0000 ------------------------------
 *                vfs_data structure
 * 70900000 ------------------------------
 *              mm_heap_data structure
 * 70800000 ------------------------------
 *        process_data structure(unmappable)
 * 70700000 ------------------------------
 *           mm_data structure(unmappable)
 * 70000000 ------------------------------
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
#define ADDRESS_ALLOCATION_LOW 0x04000000U
/* The highest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_HIGH 0x70000000U

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
#define GET_LAST_PAGE_OF_BLOCK(block) ((block) * PAGES_PER_BLOCK + (PAGES_PER_BLOCK - 1))
#define GET_BLOCK_ADDRESS(block) (void *)((block) * BLOCK_SIZE)
#define GET_PAGE_ADDRESS(page) (void *)((page) * PAGE_SIZE)
/* Page offset in bytes from the start of its block */
#define GET_SIZE_OF_BLOCK_TO_PAGE(page) ((char*)GET_BLOCK_ADDRESS(GET_BLOCK_OF_PAGE(page)) - (char*)GET_PAGE_ADDRESS(page))
/* Bytes from the page's location to its block's next block */
#define GET_SIZE_OF_PAGE_TO_NEXT_BLOCK(page) ((char*)GET_PAGE_ADDRESS(page) - (char*)GET_BLOCK_ADDRESS(GET_BLOCK_OF_PAGE(page)))

struct map_entry
{
	FORWARD_LIST_NODE(struct map_entry);
	uint32_t start_page;
	uint32_t end_page;
	int prot;
	struct file *f;
	off_t offset_pages;
};

struct mm_data
{
	/* Program break address, brk() will use this */
	void *brk;

	/* Information for all existing mappings */
	FORWARD_LIST(struct map_entry) map_list, map_free_list;
	struct map_entry map_entries[MAX_MMAP_COUNT];

	/* Section object handle of a block */
	HANDLE block_section_handle[BLOCK_COUNT];
};
static struct mm_data *const mm = MM_DATA_BASE;

static struct map_entry *new_map_entry()
{
	if (forward_list_empty(&mm->map_free_list))
		return NULL;
	struct map_entry *entry = forward_list_next(&mm->map_free_list);
	forward_list_remove(&mm->map_free_list, entry);
	return entry;
}

static void free_map_entry(struct map_entry *entry)
{
	forward_list_add(&mm->map_free_list, entry);
}

static struct map_entry *find_map_entry(void *addr)
{
	struct map_entry *p, *e;
	forward_list_iterate(&mm->map_list, p, e)
		if (addr < GET_PAGE_ADDRESS(e->start_page))
			return NULL;
		else if (addr < GET_PAGE_ADDRESS(e->end_page + 1))
			return e;
	return NULL;
}

static void split_map_entry(struct map_entry *e, uint32_t last_page_of_first_entry)
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
	e->end_page = last_page_of_first_entry;
	forward_list_add(e, ne);
}

static void free_map_entry_blocks(struct map_entry *p, struct map_entry *e)
{
	if (e->f)
		vfs_release(e->f);
	struct map_entry *n = forward_list_next(e);
	uint32_t start_block = GET_BLOCK_OF_PAGE(e->start_page);
	uint32_t end_block = GET_BLOCK_OF_PAGE(e->end_page);
	if (p != &mm->map_list && GET_BLOCK_OF_PAGE(p->end_page) == start_block)
	{
		/* First block is still in use, make it inaccessible */
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(e->start_page), GET_SIZE_OF_PAGE_TO_NEXT_BLOCK(e->start_page), PAGE_NOACCESS, &oldProtect);
		start_block++;
	}
	if (n != NULL && GET_BLOCK_OF_PAGE(n->start_page) == end_block)
	{
		/* Last block is still in use, make it inaccessible */
		DWORD oldProtect;
		VirtualProtect(GET_BLOCK_ADDRESS(end_block), GET_SIZE_OF_BLOCK_TO_PAGE(e->end_page + 1), PAGE_NOACCESS, &oldProtect);
		end_block--;
	}
	/* Unmap other full blocks */
	for (uint32_t i = start_block; i <= end_block; i++)
		if (mm->block_section_handle[i])
		{
			NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
			NtClose(mm->block_section_handle[i]);
			mm->block_section_handle[i] = 0;
		}
}

void mm_init()
{
	VirtualAlloc(MM_DATA_BASE, sizeof(struct mm_data), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	/* Initialize mapping info freelist */
	forward_list_init(&mm->map_list);
	forward_list_init(&mm->map_free_list);
	for (uint32_t i = 0; i + 1 < MAX_MMAP_COUNT; i++)
		forward_list_add(&mm->map_free_list, &mm->map_entries[i]);
	mm->brk = 0;
}

void mm_reset()
{
	/* Release all user memory */
	for (uint32_t i = GET_BLOCK(ADDRESS_ALLOCATION_LOW); i < GET_BLOCK(ADDRESS_ALLOCATION_HIGH); i++)
		if (mm->block_section_handle[i])
		{
			NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
			NtClose(mm->block_section_handle[i]);
			mm->block_section_handle[i] = NULL;
		}
	struct map_entry *p, *e;
	forward_list_iterate_safe(&mm->map_list, p, e)
		if (e->start_page >= GET_PAGE(ADDRESS_ALLOCATION_LOW) && e->end_page < GET_PAGE(ADDRESS_ALLOCATION_HIGH))
		{
			if (e->f)
				vfs_release(e->f);
			forward_list_remove(p, e);
			free_map_entry(e);
		}
	mm->brk = 0;
}

void mm_shutdown()
{
	for (uint32_t i = 0; i < BLOCK_COUNT; i++)
		if (mm->block_section_handle[i])
		{
			NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
			NtClose(mm->block_section_handle[i]);
		}
	VirtualFree(mm, 0, MEM_RELEASE);
}

void mm_update_brk(void *brk)
{
	mm->brk = max(mm->brk, brk);
}

/* Find 'count' consecutive free pages in address range [low, high), return 0 if not found */
static uint32_t find_free_pages(uint32_t count, uint32_t low, uint32_t high)
{
	uint32_t last = GET_PAGE(low);
	struct map_entry *p, *e;
	forward_list_iterate(&mm->map_list, p, e)
		if (e->start_page >= GET_PAGE(low))
			if (e->start_page - last >= count)
				return last;
			else
				last = e->end_page + 1;
	if (GET_PAGE(high) - last >= count)
		return last;
	else
		return 0;
}

uint32_t mm_find_free_pages(uint32_t count_bytes)
{
	return find_free_pages(GET_PAGE(ALIGN_TO_PAGE(count_bytes)), ADDRESS_ALLOCATION_LOW, ADDRESS_ALLOCATION_HIGH);
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

void dump_virtual_memory(HANDLE process)
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
				log_info("0x%08x - 0x%08x <--- %s\n", info.BaseAddress, (uint32_t)info.BaseAddress + info.RegionSize, filename);
			else
				log_info("0x%08x - 0x%08x\n", info.BaseAddress, (uint32_t)info.BaseAddress + info.RegionSize);
		}
		addr += info.RegionSize;
	} while ((uint32_t)addr < 0x7FFF0000);
}

static void map_entry_range(struct map_entry *e, uint32_t start_page, uint32_t end_page)
{
	if (e->f)
	{
		size_t desired_size = (end_page - start_page + 1) * PAGE_SIZE;
		size_t r = e->f->op_vtable->pread(e->f, GET_PAGE_ADDRESS(start_page), desired_size,
			(e->offset_pages + start_page - e->start_page) * PAGE_SIZE);
		if (r < desired_size)
		{
			size_t remain = desired_size - r;
			RtlSecureZeroMemory((char*)GET_PAGE_ADDRESS(end_page) - remain, remain);
		}
	}
	else
		RtlSecureZeroMemory(GET_PAGE_ADDRESS(start_page), (end_page - start_page + 1) * PAGE_SIZE);
}

static int mm_change_protection(HANDLE process, uint32_t start_page, uint32_t end_page, int prot)
{
	DWORD protection = prot_linux2win(prot);
	uint32_t start_block = GET_BLOCK_OF_PAGE(start_page);
	uint32_t end_block = GET_BLOCK_OF_PAGE(end_page);
	for (uint32_t i = start_block; i <= end_block; i++)
		if (mm->block_section_handle[i])
		{
			uint32_t range_start = max(GET_FIRST_PAGE_OF_BLOCK(i), start_page);
			uint32_t range_end = min(GET_LAST_PAGE_OF_BLOCK(i), end_page);
			DWORD oldProtect;
			if (!VirtualProtectEx(process, GET_PAGE_ADDRESS(range_start), PAGE_SIZE * (range_end - range_start + 1), protection, &oldProtect))
			{
				log_error("VirtualProtect(0x%x, 0x%x) failed, error code: %d\n", GET_PAGE_ADDRESS(range_start),
					PAGE_SIZE * (range_end - range_start + 1), GetLastError());
				dump_virtual_memory(process);
				return 0;
			}
		}
	return 1;
}

void mm_dump_stack_trace(PCONTEXT context)
{
	log_info("Stack trace:\n");
#ifdef _WIN64
	size_t sp = context->Rsp;
	log_info("RSP: 0x%x\n", sp);
#else
	size_t sp = context->Esp;
	log_info("ESP: 0x%x\n", sp);
#endif
	for (size_t i = sp & ~15; i < ((sp + 256) & ~15); i += 16)
	{
		log_raw("%08x ", i);
		for (size_t j = i; j < i + 16 && j < ((sp + 256) & ~15); j++)
			log_raw("%02x ", *(unsigned char *)j);
		log_raw("\n");
	}
}

static int allocate_block(uint32_t i)
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
		log_error("NtCreateSection() failed. Status: %x\n", status);
		return 0;
	}

	/* Map section */
	PVOID base_addr = GET_BLOCK_ADDRESS(i);
	SIZE_T view_size = BLOCK_SIZE;
	status = NtMapViewOfSection(handle, NtCurrentProcess(), &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (status != STATUS_SUCCESS)
	{
		log_error("NtMapViewOfSection() failed. Address: %x, Status: %x\n", base_addr, status);
		NtClose(handle);
		dump_virtual_memory(NtCurrentProcess());
		return 0;
	}
	mm->block_section_handle[i] = handle;
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
	if (status != STATUS_SUCCESS)
	{
		log_error("NtCreateSection() failed, status: %x\n", status);
		return NULL;
	}
	
	status = NtMapViewOfSection(dest, NtCurrentProcess(), &dest_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);
	if (status != STATUS_SUCCESS)
	{
		log_error("NtMapViewOfSection() failed, status: %x\n", status);
		return NULL;
	}
	/* Mark source block entirely readable. TODO: Find a better way */
	DWORD oldProtect;
	if (!VirtualProtect(source_addr, BLOCK_SIZE, PAGE_EXECUTE_READ, &oldProtect))
	{
		log_error("VirtualProtect(0x%x) failed, error code: %d\n", source_addr, GetLastError());
		return NULL;
	}
	CopyMemory(dest_addr, source_addr, BLOCK_SIZE);
	status = NtUnmapViewOfSection(NtCurrentProcess(), dest_addr);
	if (status != STATUS_SUCCESS)
	{
		log_error("NtUnmapViewOfSection() failed, status: %x\n", status);
		return NULL;
	}
	return dest;
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
		log_warning("Address %x (page %x) not writable.\n", addr, GET_PAGE(addr));
		return 0;
	}
	uint16_t block = GET_BLOCK(addr);
	if (mm->block_section_handle[block] == NULL)
	{
		log_warning("Address %x (page %x) not mapped.\n", addr, GET_PAGE(addr));
		return 0;
	}
	/* Query information about the section object which the page within */
	OBJECT_BASIC_INFORMATION info;
	NTSTATUS status;
	status = NtQueryObject(mm->block_section_handle[block], ObjectBasicInformation, &info, sizeof(OBJECT_BASIC_INFORMATION), NULL);
	if (status != STATUS_SUCCESS)
	{
		log_error("NtQueryObject() on block %x failed.\n", block);
		return 0;
	}
	if (info.HandleCount == 1)
		log_info("We're the only owner, simply change protection flags.\n");
	else
	{
		/* We are not the only one holding the section, duplicate it */
		log_info("Duplicating section %x...\n", block);
		HANDLE section;
		if (!(section = duplicate_section(mm->block_section_handle[block], GET_BLOCK_ADDRESS(block))))
		{
			log_error("Duplicating section failed.\n");
			return 0;
		}
		log_info("Duplicating section succeeded. Remapping...\n");
		status = NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(block));
		if (status != STATUS_SUCCESS)
		{
			log_error("Unmapping failed, status: %x\n", status);
			return 0;
		}
		status = NtClose(mm->block_section_handle[block]);
		if (status != STATUS_SUCCESS)
		{
			log_error("NtClose() failed, status: %x\n", status);
			return 0;
		}
		mm->block_section_handle[block] = section;
		PVOID base_addr = GET_BLOCK_ADDRESS(block);
		SIZE_T view_size = BLOCK_SIZE;
		status = NtMapViewOfSection(section, NtCurrentProcess(), &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
		if (status != STATUS_SUCCESS)
		{
			log_error("Remapping failed, status: %x\n", status);
			return 0;
		}
	}
	/* We're the only owner of the section now, change page protection flags */
	uint32_t start_page = GET_FIRST_PAGE_OF_BLOCK(block);
	uint32_t end_page = GET_LAST_PAGE_OF_BLOCK(block);
	struct map_entry *p, *e;
	forward_list_iterate(&mm->map_list, p, e)
		if (end_page < e->start_page)
			break;
		else
		{
			uint32_t range_start = max(start_page, e->start_page);
			uint32_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			DWORD oldProtect;
			if (!VirtualProtect(GET_PAGE_ADDRESS(range_start), PAGE_SIZE * (range_end - range_start + 1), prot_linux2win(e->prot), &oldProtect))
			{
				log_error("VirtualProtect(0x%x, 0x%x) failed, error code: %d.\n", GET_PAGE_ADDRESS(range_start),
					PAGE_SIZE * (range_end - range_start + 1), GetLastError());
				return 0;
			}
		}
	return 1;
}

static int handle_on_demand_page_fault(void *addr)
{
	uint32_t block = GET_BLOCK(addr);
	uint32_t page = GET_PAGE(addr);
	/* Map all map entries in the block */
	uint32_t start_page = GET_FIRST_PAGE_OF_BLOCK(block);
	uint32_t end_page = GET_LAST_PAGE_OF_BLOCK(block);
	struct map_entry *p, *e;
	int found = 0;
	allocate_block(block);
	forward_list_iterate(&mm->map_list, p, e)
		if (end_page < e->start_page)
			break;
		else
		{
			uint32_t range_start = max(start_page, e->start_page);
			uint32_t range_end = min(end_page, e->end_page);
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
	/* TODO: Mark unmapped pages as PAGE_NOACCESS */
	if (!found)
		log_error("Page 0x%x not mapped.\n", GET_PAGE(addr));
	else
		log_info("On demand page 0x%x loaded.\n", GET_PAGE(addr));
	return found;
}

int mm_handle_page_fault(void *addr)
{
	log_info("Handling page fault at address %x (page %x)\n", addr, GET_PAGE(addr));
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH)
	{
		log_warning("Address %x outside of valid usermode address space.\n", addr);
		return 0;
	}
	if (mm->block_section_handle[GET_BLOCK(addr)])
		return handle_cow_page_fault(addr);
	else
		return handle_on_demand_page_fault(addr);
}

int mm_fork(HANDLE process)
{
	/* Copy mm_data struct */
	if (!VirtualAllocEx(process, MM_DATA_BASE, sizeof(struct mm_data), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
	{
		log_error("mm_fork(): Allocate mm_data structure failed, error code: %d\n", GetLastError());
		return 0;
	}
	if (!WriteProcessMemory(process, MM_DATA_BASE, mm, sizeof(struct mm_data), NULL))
	{
		log_error("mm_fork(): Write mm_data structure failed, error code: %d\n", GetLastError());
		return 0;
	}
	uint32_t last_block = 0;
	uint32_t section_object_count = 0;
	struct map_entry *p, *e;
	log_info("Mapping and changing memory protection...\n");
	forward_list_iterate(&mm->map_list, p, e)
	{
		/* Map section */
		uint32_t start_block = GET_BLOCK_OF_PAGE(e->start_page);
		uint32_t end_block = GET_BLOCK_OF_PAGE(e->end_page);
		if (start_block == last_block)
			start_block++;
		for (uint32_t i = start_block; i <= end_block; i++)
			if (mm->block_section_handle[i])
			{
				PVOID base_addr = GET_BLOCK_ADDRESS(i);
				SIZE_T view_size = BLOCK_SIZE;
				NTSTATUS status;
				status = NtMapViewOfSection(mm->block_section_handle[i], process, &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
				if (status != STATUS_SUCCESS)
				{
					log_error("mm_fork(): Map failed: %x, status code: %x\n", base_addr, status);
					dump_virtual_memory(process);
					return 0;
				}
				section_object_count++;
			}
		last_block = end_block;
		/* Disable write permission */
		if ((e->prot & PROT_WRITE) > 0)
		{
			if (!mm_change_protection(process, e->start_page, e->end_page, e->prot & ~PROT_WRITE))
				return 0;
			if (!mm_change_protection(GetCurrentProcess(), e->start_page, e->end_page, e->prot & ~PROT_WRITE))
				return 0;
		}
	}
	log_info("Total section objects: %d\n", section_object_count);
	return 1;
}

void *mm_mmap(void *addr, size_t length, int prot, int flags, struct file *f, off_t offset_pages)
{
	if (length == 0)
		return -EINVAL;
	length = ALIGN_TO_PAGE(length);
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < ADDRESS_SPACE_LOW || (size_t)addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < (size_t)addr)
		return -EINVAL;
	if (flags & MAP_SHARED)
	{
		log_warning("MAP_SHARED is not supported yet.\n");
		return -EINVAL;
	}
	if ((flags & MAP_ANONYMOUS) && f != NULL)
	{
		log_warning("MAP_ANONYMOUS with file descriptor.\n");
		return -EINVAL;
	}
	if (!(flags & MAP_ANONYMOUS) && f == NULL)
	{
		log_warning("MAP_FILE with bad file descriptor.\n");
		return -EBADF;
	}
	if (!(flags & MAP_FIXED))
	{
		uint32_t alloc_page;
		if (flags & __MAP_HEAP)
			alloc_page = find_free_pages(GET_PAGE(ALIGN_TO_PAGE(length)), ADDRESS_HEAP_LOW, ADDRESS_HEAP_HIGH);
		else
			alloc_page = find_free_pages(GET_PAGE(ALIGN_TO_PAGE(length)), ADDRESS_ALLOCATION_LOW, ADDRESS_ALLOCATION_HIGH);
		if (!alloc_page)
		{
			log_error("Cannot find free pages.\n");
			return -ENOMEM;
		}

		addr = GET_PAGE_ADDRESS(alloc_page);
	}
	if ((flags & MAP_FIXED) && !IS_ALIGNED(addr, PAGE_SIZE))
	{
		log_warning("Not aligned addr with MAP_FIXED.\n");
		return -EINVAL;
	}

	uint32_t start_page = GET_PAGE(addr);
	uint32_t end_page = GET_PAGE((size_t)addr + length - 1);
	uint16_t start_block = GET_BLOCK(addr);
	uint16_t end_block = GET_BLOCK((size_t)addr + length - 1);

	/*
	If address are fixed, unmap conflicting pages,
	Otherwise the pages are found by find_free_pages() thus are guaranteed free.
	*/
	if ((flags & MAP_FIXED))
		mm_munmap(addr, length);

	/* Set up all kinds of flags */
	struct map_entry *entry = new_map_entry();
	entry->start_page = start_page;
	entry->end_page = end_page;
	entry->f = f;
	entry->offset_pages = offset_pages;
	entry->prot = prot;
	if (f)
		vfs_ref(f);

	if (forward_list_empty(&mm->map_list))
		forward_list_add(&mm->map_list, entry);
	else
	{
		struct map_entry *p, *e;
		/* No need to use forward_list_safe since we will break immediately after node insertion */
		forward_list_iterate(&mm->map_list, p, e)
		{
			if (e->start_page > end_page)
			{
				forward_list_add(p, entry);
				break;
			}
			else if (forward_list_next(e) == NULL)
			{
				forward_list_add(e, entry);
				break;
			}
		}
	}

	/* If the first or last block is already allocated, we have to set up proper content in it
	   For other blocks we map them on demand */
	if (mm->block_section_handle[start_block])
	{
		uint32_t last_page = GET_LAST_PAGE_OF_BLOCK(start_block);
		last_page = min(last_page, end_page);
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(start_page), (last_page - start_page + 1) * PAGE_SIZE, prot_linux2win(prot | PROT_WRITE), &oldProtect);
		map_entry_range(entry, start_page, last_page);
		if ((prot & PROT_WRITE) == 0)
			VirtualProtect(GET_PAGE_ADDRESS(start_page), (last_page - start_page + 1) * PAGE_SIZE, prot_linux2win(prot), &oldProtect);
	}
	if (end_block > start_block && mm->block_section_handle[end_block])
	{
		uint32_t first_page = GET_FIRST_PAGE_OF_BLOCK(end_block);
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(first_page), (end_page - first_page + 1) * PAGE_SIZE, prot_linux2win(prot | PROT_WRITE), &oldProtect);
		map_entry_range(entry, first_page, end_page);
		if ((prot & PROT_WRITE) == 0)
			VirtualProtect(GET_PAGE_ADDRESS(first_page), (end_page - first_page + 1) * PAGE_SIZE, prot_linux2win(prot), &oldProtect);
	}
	log_info("Allocated memory: [%x, %x)\n", addr, (uint32_t)addr + length);
	return addr;
}

int mm_munmap(void *addr, size_t length)
{
	/* TODO: We should mark NOACCESS for munmap()-ed but not VirtualFree()-ed pages */
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -EINVAL;
	length = ALIGN_TO_PAGE(length);
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < ADDRESS_SPACE_LOW || (size_t)addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < (size_t)addr)
	{
		return -EINVAL;
	}

	uint32_t start_page = GET_PAGE(addr);
	uint32_t end_page = GET_PAGE((size_t)addr + length - 1);
	struct map_entry *p, *e;
	forward_list_iterate_safe(&mm->map_list, p, e)
		if (end_page < e->start_page)
			break;
		else
		{
			uint32_t range_start = max(start_page, e->start_page);
			uint32_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			if (range_start == e->start_page && range_end == e->end_page)
			{
				/* That's good, the current entry is fully overlapped */
				if (e->f)
					vfs_release(e->f);
				free_map_entry_blocks(p, e);
				forward_list_remove(p, e);
				free_map_entry(e);
			}
			else
			{
				/* Not so good, part of current entry is overlapped */
				if (range_start == e->start_page)
				{
					split_map_entry(e, range_end);
					free_map_entry_blocks(p, e);
					forward_list_remove(p, e);
					free_map_entry(e);
				}
				else
				{
					split_map_entry(e, range_start - 1);
					/* The current entry is unrelated, we just skip to next entry (which we just generated) */
				}
			}
		}
	return 0;
}

void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	/* TODO: We should mark NOACCESS for VirtualAlloc()-ed but currently unused pages */
	log_info("mmap(%x, %x, %x, %x, %d, %x)\n", addr, length, prot, flags, fd, offset);
	/* TODO: Initialize mapped area to zero */
	if (!IS_ALIGNED(offset, PAGE_SIZE))
		return -EINVAL;
	return mm_mmap(addr, length, prot, flags, vfs_get(fd), offset / PAGE_SIZE);
}

void *sys_oldmmap(void *_args)
{
	log_info("oldmmap(%x)\n", _args);
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
	log_info("mmap2(%x, %x, %x, %x, %d, %x)\n", addr, length, prot, flags, fd, offset);
	return mm_mmap(addr, length, prot, flags, vfs_get(fd), offset);
}

int sys_munmap(void *addr, size_t length)
{
	log_info("munmap(%x, %x)\n", addr, length);
	return mm_munmap(addr, length);
}

int sys_mprotect(void *addr, size_t length, int prot)
{
	log_info("mprotect(%x, %x, %x)\n", addr, length, prot);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -EINVAL;
	length = ALIGN_TO_PAGE(length);
	if ((size_t)addr < ADDRESS_SPACE_LOW || (size_t)addr >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < ADDRESS_SPACE_LOW || (size_t)addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t)addr + length < (size_t)addr)
	{
		return -EINVAL;
	}
	/* Validate all pages are mapped */
	uint32_t start_page = GET_PAGE(addr);
	uint32_t end_page = GET_PAGE((uint32_t)addr + length - 1);
	uint32_t last_page = start_page - 1;
	struct map_entry *p, *e;
	forward_list_iterate(&mm->map_list, p, e)
		if (e->start_page > end_page)
			break;
		else if (e->end_page >= start_page)
		{
			if (e->start_page == last_page + 1)
				last_page = e->end_page;
			else
				break;
		}
	if (last_page < end_page)
		return -ENOMEM;
	;
	/* Change protection flags */
	forward_list_iterate_safe(&mm->map_list, p, e)
		if (end_page < e->start_page)
			break;
		else
		{
			uint32_t range_start = max(start_page, e->start_page);
			uint32_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			if (range_start == e->start_page && range_end == e->end_page)
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
	if (!mm_change_protection(GetCurrentProcess(), start_page, end_page, prot & ~PROT_WRITE))
		/* We remove the write protection in case the pages are already shared */
		return -ENOMEM; /* TODO */
	return 0;
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
	log_info("brk(%x)\n", addr);
	log_info("Last brk: %x\n", mm->brk);
	uint32_t brk = ALIGN_TO_PAGE(mm->brk);
	addr = ALIGN_TO_PAGE(addr);
	/* TODO: Handle brk shrink */
	if (addr > mm->brk)
	{
		if (sys_mmap(brk, (uint32_t)addr - (uint32_t)brk, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) < 0)
		{
			log_error("Enlarge brk failed.\n");
			return -ENOMEM;
		}
		mm->brk = addr;
	}
	log_info("New brk: %x\n", mm->brk);
	return mm->brk;
}
