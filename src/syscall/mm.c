#include <common/errno.h>
#include <core/forward_list.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/vfs.h>
#include <log.h>

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

/* Overall memory layout (x86)
 *
 * FFFFFFFF ------------------------------
 * ...        Win32 kernel address space
 * ...         (unused if 4gt enabled)
 * 80000000 ------------------------------
 * ...                win32 dlls
 * 73000000 ------------------------------
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
 * Foreign Linux kernel data memory layout (x86), u for unmappable
 *
 * 73000000 ------------------------------
 *                 dbt code cache (u)
 * 72800000 ------------------------------
 *                dbt blocks table (u)
 * 72000000 ------------------------------
 *                    kernel heap
 * 71000000 ------------------------------
 *                fork_info structure
 * 70FF0000 ------------------------------
 *             startup (argv, env) data
 * 70FE0000 ------------------------------
 *                tls_data structure
 * 70FD0000 ------------------------------
 *              mm_heap_data structure
 * 70FC0000 ------------------------------
 *              console_data structure
 * 70FB0000 ------------------------------
 *                vfs_data structure
 * 70900000 ------------------------------
 *               dbt_data structure (u)
 * 70800000 ------------------------------
 *             process_data structure (u)
 * 70700000 ------------------------------
 *                 section handles (u)
 * 70200000 ------------------------------
 *                mm_data structure (u)
 * 70000000 ------------------------------
 */

/* Overall memory layout (x64)
 * TODO: This hasn't been updated for a long time since the introduction of DBT.
 * Need redesign once we want to support x64 again.
 *
 * FFFFFFFF FFFFFFFF ------------------------------
 * ...                 Win32 kernel address space
 * FFFF8000 00000000 ------------------------------
 * ...                         (unusable)
 * 00007FFF FFFFFFFF ------------------------------
 *                             Win32 dlls
 * 00007FF0 00000000 ------------------------------
 *                      (unused in Foreign Linux)
 *                    we reduce the available address space to limit the size of section handles store
 * 00001000 00000000 ------------------------------
 * ...                   Application code/data
 * 00000003 00000000 ------------------------------  <-- brk base (x64 special to avoid collisions in low address)
 * ...                   Application code/data
 * 00000002 00000000 ------------------------------
 * ...                 Foreign Linux kernel code
 * 00000001 00000000 ------------------------------
 * ...                 Foreign Linux kernel data
 * 00000000 20000000 ------------------------------
 * ...                     Win32 system heaps
 * 00000000 10400000 ------------------------------
 * ...                      Application code
 * 00000000 00400000 ------------------------------
 *                         Win32 system heaps
 * 00000000 00000000 ------------------------------
 *
 *
 * Foreign Linux kernel data memory layout (x64), u for unmappable
 *
 * 00000001 00000000 ------------------------------
 *                             kernel heap
 * 00000000 F0000000 ------------------------------
 *                         fork_info structure
 * 00000000 EFFF0000 ------------------------------
 *                      startup (argv, env) data
 * 00000000 EFFE0000 ------------------------------
 *                         tls_data structure
 * 00000000 EFFD0000 ------------------------------
 *                         vfs_data structure
 * 00000000 EE000000 ------------------------------
 *                        mm_heap_data structure
 * 00000000 ED000000 ------------------------------
 *                      process_data structure (u)
 * 00000000 EC000000 ------------------------------
 *                         section handles (u)
 * 00000000 30000000 ------------------------------
 *                        mm_data structure (u)
 * 00000000 20000000 ------------------------------
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
/* The lowest address of reserved kernel data */
#define ADDRESS_RESERVED_LOW	0x0000000020000000ULL
/* The highest address of reserved kernel data */
#define ADDRESS_RESERVED_HIGH	0x0000000100000000ULL

#else

/* Lower bound of the virtual address space */
#define ADDRESS_SPACE_LOW		0x00000000U
/* Higher bound of the virtual address space */
#define ADDRESS_SPACE_HIGH		0x80000000U
/* The lowest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_LOW	0x04000000U
/* The highest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_HIGH	0x70000000U
/* The lowest address of reserved kernel data */
#define ADDRESS_RESERVED_LOW	0x70000000U
/* The highest address of reserved kernel data */
#define ADDRESS_RESERVED_HIGH	0x72000000U

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
	FORWARD_LIST_NODE(struct map_entry);
	size_t start_page;
	size_t end_page;
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

	/* Section handle count for each table */
	uint16_t section_table_handle_count[SECTION_TABLE_COUNT];
};
static struct mm_data *const mm = MM_DATA_BASE;
static HANDLE *mm_section_handle = MM_SECTION_HANDLE_BASE;

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
		VirtualAlloc(&mm_section_handle[t * SECTION_HANDLE_PER_TABLE], BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		mm_section_handle[i] = handle;
	}
}

static __forceinline void replace_section_handle(size_t i, HANDLE handle)
{
	mm_section_handle[i] = handle;
}

static __forceinline void remove_section_handle(size_t i)
{
	mm_section_handle[i] = NULL;
	size_t t = GET_SECTION_TABLE(i);
	if (--mm->section_table_handle_count[t] == 0)
		VirtualFree(&mm_section_handle[t * SECTION_HANDLE_PER_TABLE], BLOCK_SIZE, MEM_RELEASE);
}

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
	e->end_page = last_page_of_first_entry;
	forward_list_add(e, ne);
}

static void free_map_entry_blocks(struct map_entry *p, struct map_entry *e)
{
	if (e->f)
		vfs_release(e->f);
	struct map_entry *n = forward_list_next(e);
	size_t start_block = GET_BLOCK_OF_PAGE(e->start_page);
	size_t end_block = GET_BLOCK_OF_PAGE(e->end_page);
	if (p != &mm->map_list && GET_BLOCK_OF_PAGE(p->end_page) == start_block)
	{
		/* First block is still in use, make it inaccessible */
		size_t last_page = GET_LAST_PAGE_OF_BLOCK(GET_BLOCK_OF_PAGE(e->start_page));
		if (n && GET_BLOCK_OF_PAGE(n->start_page) == start_block)
			last_page = n->start_page - 1;
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(e->start_page), (last_page - e->start_page + 1) * PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
		start_block++;
	}
	if (end_block >= start_block && n && GET_BLOCK_OF_PAGE(n->start_page) == end_block)
	{
		/* Last block is still in use, make it inaccessible */
		DWORD oldProtect;
		VirtualProtect(GET_BLOCK_ADDRESS(end_block), GET_SIZE_OF_BLOCK_TO_PAGE(e->end_page + 1), PAGE_NOACCESS, &oldProtect);
		end_block--;
	}
	/* Unmap other full blocks */
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

void mm_init()
{
	VirtualAlloc(MM_DATA_BASE, sizeof(struct mm_data), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	/* Initialize mapping info freelist */
	forward_list_init(&mm->map_list);
	forward_list_init(&mm->map_free_list);
	for (size_t i = 0; i + 1 < MAX_MMAP_COUNT; i++)
		forward_list_add(&mm->map_free_list, &mm->map_entries[i]);
	mm->brk = 0;
}

void mm_reset()
{
	/* Release all user memory */
	size_t last_block = 0;
	size_t reserved_start = GET_BLOCK(ADDRESS_RESERVED_LOW);
	size_t reserved_end = GET_BLOCK(ADDRESS_RESERVED_HIGH) - 1;
	struct map_entry *p, *e;
	forward_list_iterate_safe(&mm->map_list, p, e)
	{
		size_t start_block = GET_BLOCK_OF_PAGE(e->start_page);
		size_t end_block = GET_BLOCK_OF_PAGE(e->end_page);
		if (reserved_start <= start_block && start_block <= reserved_end)
			continue;
		if (reserved_start <= end_block && end_block <= reserved_end)
			continue;

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
		forward_list_remove(p, e);
		free_map_entry(e);
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
	VirtualFree(mm, 0, MEM_RELEASE);
}

void mm_update_brk(void *brk)
{
	/* Seems glibc does not like unaligned initial brk */
#ifdef _WIN64
	mm->brk = MM_BRK_BASE;
#else
	mm->brk = max(mm->brk, ALIGN_TO_PAGE(brk));
#endif
}

/* Find 'count' consecutive free pages in address range [low, high), return 0 if not found */
static size_t find_free_pages(size_t count, size_t low, size_t high)
{
	size_t last = GET_PAGE(low);
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

size_t mm_find_free_pages(size_t count_bytes)
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
	struct map_entry *p, *e;
	log_info("Current memory mappings...\n");
	forward_list_iterate(&mm->map_list, p, e)
		log_info("0x%p - 0x%p: PROT: %d\n", GET_PAGE_ADDRESS(e->start_page), GET_PAGE_ADDRESS(e->end_page), e->prot);
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
		log_error("VirtualProtect(0x%p) failed, error code: %d\n", source_addr, GetLastError());
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
	if (status != STATUS_SUCCESS)
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
	if (status != STATUS_SUCCESS)
	{
		log_error("Unmapping failed, status: %x\n", status);
		return 0;
	}
	status = NtClose(handle);
	if (status != STATUS_SUCCESS)
	{
		log_error("NtClose() failed, status: %x\n", status);
		return 0;
	}
	PVOID base_addr = GET_BLOCK_ADDRESS(block);
	SIZE_T view_size = BLOCK_SIZE;
	status = NtMapViewOfSection(new_section, NtCurrentProcess(), &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (status != STATUS_SUCCESS)
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
	struct map_entry *p, *e;
	forward_list_iterate(&mm->map_list, p, e)
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
	forward_list_iterate(&mm->map_list, p, e)
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
	if (get_section_handle(GET_BLOCK(addr)))
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
	/* Copy section handle tables */
	for (size_t i = 0; i < SECTION_TABLE_COUNT; i++)
		if (mm->section_table_handle_count[i])
		{
			size_t offset = i * BLOCK_SIZE;
			if (!VirtualAllocEx(process, MM_SECTION_HANDLE_BASE + offset, BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
			{
				log_error("mm_fork(): Allocate section table 0x%p failed, error code: %d\n", i, GetLastError());
				return 0;
			}
			if (!WriteProcessMemory(process, MM_SECTION_HANDLE_BASE + offset, MM_SECTION_HANDLE_BASE + offset, BLOCK_SIZE, NULL))
			{
				log_error("mm_fork(): Write section table 0x%p failed, error code: %d\n", i, GetLastError());
				return 0;
			}
		}
	size_t last_block = 0;
	size_t section_object_count = 0;
	struct map_entry *p, *e;
	log_info("Mapping and changing memory protection...\n");
	forward_list_iterate(&mm->map_list, p, e)
	{
		/* Map section */
		size_t start_block = GET_BLOCK_OF_PAGE(e->start_page);
		size_t end_block = GET_BLOCK_OF_PAGE(e->end_page);
		if (start_block == last_block)
			start_block++;
		for (size_t i = start_block; i <= end_block; i++)
		{
			HANDLE handle = get_section_handle(i);
			if (handle)
			{
				PVOID base_addr = GET_BLOCK_ADDRESS(i);
				SIZE_T view_size = BLOCK_SIZE;
				NTSTATUS status;
				status = NtMapViewOfSection(handle, process, &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
				if (status != STATUS_SUCCESS)
				{
					log_error("mm_fork(): Map failed: %p, status code: %x\n", base_addr, status);
					mm_dump_windows_memory_mappings(process);
					return 0;
				}
				section_object_count++;
			}
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
		log_error("MAP_SHARED is not supported yet.\n");
		if (prot & PROT_WRITE)
			return -EINVAL;
		log_info("No write permission requested, ignoring MAP_SHARED.\n");
	}
	if ((flags & MAP_ANONYMOUS) && f != NULL)
	{
		log_error("MAP_ANONYMOUS with file descriptor.\n");
		return -EINVAL;
	}
	if (!(flags & MAP_ANONYMOUS) && f == NULL)
	{
		log_error("MAP_FILE with bad file descriptor.\n");
		return -EBADF;
	}
	if (!(flags & MAP_FIXED))
	{
		size_t alloc_page;
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

	size_t start_page = GET_PAGE(addr);
	size_t end_page = GET_PAGE((size_t)addr + length - 1);
	size_t start_block = GET_BLOCK(addr);
	size_t end_block = GET_BLOCK((size_t)addr + length - 1);

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
	if (get_section_handle(start_block))
	{
		if (!take_block_ownership(start_block))
		{
			log_error("Taking ownership of block %p failed.\n", start_block);
			return -ENOMEM;
		}
		size_t last_page = GET_LAST_PAGE_OF_BLOCK(start_block);
		last_page = min(last_page, end_page);
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(start_page), (last_page - start_page + 1) * PAGE_SIZE, prot_linux2win(prot | PROT_WRITE), &oldProtect);
		map_entry_range(entry, start_page, last_page);
		if ((prot & PROT_WRITE) == 0)
			VirtualProtect(GET_PAGE_ADDRESS(start_page), (last_page - start_page + 1) * PAGE_SIZE, prot_linux2win(prot), &oldProtect);
	}
	if (end_block > start_block && get_section_handle(end_block))
	{
		if (!take_block_ownership(end_block))
		{
			log_error("Taking ownership of block %p failed.\n", start_block);
			return -ENOMEM;
		}
		size_t first_page = GET_FIRST_PAGE_OF_BLOCK(end_block);
		DWORD oldProtect;
		VirtualProtect(GET_PAGE_ADDRESS(first_page), (end_page - first_page + 1) * PAGE_SIZE, prot_linux2win(prot | PROT_WRITE), &oldProtect);
		map_entry_range(entry, first_page, end_page);
		if ((prot & PROT_WRITE) == 0)
			VirtualProtect(GET_PAGE_ADDRESS(first_page), (end_page - first_page + 1) * PAGE_SIZE, prot_linux2win(prot), &oldProtect);
	}
	log_info("Allocated memory: [%p, %p)\n", addr, (size_t)addr + length);
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

	size_t start_page = GET_PAGE(addr);
	size_t end_page = GET_PAGE((size_t)addr + length - 1);
	struct map_entry *p, *e;
	forward_list_iterate_safe(&mm->map_list, p, e)
		if (end_page < e->start_page)
			break;
		else
		{
			size_t range_start = max(start_page, e->start_page);
			size_t range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			if (range_start == e->start_page && range_end == e->end_page)
			{
				/* That's good, the current entry is fully overlapped */
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

DEFINE_SYSCALL(mmap, void *, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset)
{
	/* TODO: We should mark NOACCESS for VirtualAlloc()-ed but currently unused pages */
	log_info("mmap(%p, %p, %x, %x, %d, %p)\n", addr, length, prot, flags, fd, offset);
	/* TODO: Initialize mapped area to zero */
	if (!IS_ALIGNED(offset, PAGE_SIZE))
		return -EINVAL;
	return mm_mmap(addr, length, prot, flags, vfs_get(fd), offset / PAGE_SIZE);
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
	return mm_mmap(addr, length, prot, flags, vfs_get(fd), offset);
}

DEFINE_SYSCALL(munmap, void *, addr, size_t, length)
{
	log_info("munmap(%p, %p)\n", addr, length);
	return mm_munmap(addr, length);
}

DEFINE_SYSCALL(mprotect, void *, addr, size_t, length, int, prot)
{
	log_info("mprotect(%p, %p, %x)\n", addr, length, prot);
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
	size_t start_page = GET_PAGE(addr);
	size_t end_page = GET_PAGE((size_t)addr + length - 1);
	size_t last_page = start_page - 1;
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
			size_t range_start = max(start_page, e->start_page);
			size_t range_end = min(end_page, e->end_page);
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

DEFINE_SYSCALL(msync, void *, addr, size_t, len, int, flags)
{
	log_info("msync(0x%p, 0x%p, %d)\n", addr, len, flags);
	log_error("msync() not implemented.\n");
	return -ENOSYS;
}

DEFINE_SYSCALL(mlock, const void *, addr, size_t, len)
{
	log_info("mlock(0x%p, 0x%p)\n", addr, len);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -EINVAL;

	/* All on demand page must be properly loaded or the locking operation will fail */
	size_t start_page = GET_PAGE(addr);
	size_t end_page = GET_PAGE((size_t)addr + len);
	struct map_entry *p, *e;
	forward_list_iterate(&mm->map_list, p, e)
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
						return -ENOMEM;
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
	/* TODO: Mark unused pages as NOACCESS */

	/* The actual locking */
	/* TODO: Automatically enlarge working set size for arbitrary sized mlock() call */
	if (!VirtualLock(addr, len))
	{
		log_warning("VirtualLock() failed, error code: %d\n", GetLastError());
		return -ENOMEM;
	}
	return 0;
}

DEFINE_SYSCALL(munlock, const void *, addr, size_t, len)
{
	log_info("munlock(0x%p, 0x%p)\n", addr, len);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -EINVAL;
	if (!VirtualUnlock(addr, len))
	{
		log_warning("VirtualUnlock() failed, error code: %d\n", GetLastError());
		return -ENOMEM;
	}
	return 0;
}

DEFINE_SYSCALL(mremap, void *, old_address, size_t, old_size, size_t, new_size, int, flags, void *, new_address)
{
	log_info("mremap(old_address=%p, old_size=%p, new_size=%p, flags=%x, new_address=%p)\n", old_address, old_size, new_size, flags, new_address);
	log_error("mremap() not implemented.\n");
	return -ENOSYS;
}

DEFINE_SYSCALL(brk, void *, addr)
{
	log_info("brk(%p)\n", addr);
	log_info("Last brk: %p\n", mm->brk);
	size_t brk = ALIGN_TO_PAGE(mm->brk);
	addr = ALIGN_TO_PAGE(addr);
	if (addr > 0 && addr < mm->brk)
	{
		if (sys_munmap(brk, addr, (size_t)brk - (size_t)addr) < 0)
		{
			log_error("Shrink brk failed.\n");
			return -ENOMEM;
		}
		mm->brk = addr;
	}
	else if (addr > mm->brk)
	{
		if (sys_mmap(brk, (size_t)addr - (size_t)brk, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) < 0)
		{
			log_error("Enlarge brk failed.\n");
			return -ENOMEM;
		}
		mm->brk = addr;
	}
	log_info("New brk: %p\n", mm->brk);
	return mm->brk;
}
