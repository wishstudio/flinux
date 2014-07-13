#include "mm.h"
#include "errno.h"

#include <stdint.h>
#include <Windows.h>

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

/* OS-specific constants */
/* Lower bound of the virtual address space */
#define ADDRESS_SPACE_LOW 0x00000000U
/* Higher bound of the virtual address space */
#define ADDRESS_SPACE_HIGH 0x80000000U
/* Windows allocation granularity we have to follow */
#define BLOCK_SIZE 0x00010000U
/* Linux page size we want to mimic */
#define PAGE_SIZE 0x00001000U

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
#define GET_BLOCK_ADDRESS(block) (void *)((block) * BLOCK_SIZE)
#define GET_PAGE_ADDRESS(page) (void *)((page) * PAGE_SIZE)

/* Information for all existing mappings */
struct map_info
{
	union
	{
		struct {
			uint32_t start_page;
			uint32_t end_page;
		};
		uint16_t next;
	};
} map_entries[MAX_MMAP_COUNT];
uint16_t map_free_head;

/* Start block of an VirtualAlloc() allocation region,
 * Note only the first and the last block need this information.
 */
uint16_t block_alloc_start[BLOCK_COUNT];
/* Number of allocated pages inside a block */
uint8_t block_alloc_pages[BLOCK_COUNT];

/* Mapping info entry for a given page */
uint16_t page_map_entry[PAGE_COUNT];

void mm_init()
{
	/* Initialize mapping info freelist */
	for (uint16_t i = 1; i + 1 < MAX_MMAP_COUNT; i++)
		map_entries[i].next = i + 1;
	map_free_head = 1; /* Entry 0 is unused */
	map_entries[MAX_MMAP_COUNT - 1].next = 0;
}

static uint16_t new_map_entry()
{
	if (map_free_head)
	{
		uint16_t entry = map_free_head;
		map_free_head = map_entries[map_free_head].next;
		return entry;
	}
	return 0;
}

static void free_map_entry(uint16_t entry)
{
	map_entries[entry].next = map_free_head;
	map_free_head = entry;
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

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	/* TODO: errno */
	if (!IS_ALIGNED(offset, PAGE_SIZE))
		return NULL;
	if (length == 0)
		return NULL;
	length = ALIGN_TO_PAGE(length);
	if ((size_t) addr < ADDRESS_SPACE_LOW || (size_t) addr >= ADDRESS_SPACE_HIGH
		|| (size_t) addr + length < ADDRESS_SPACE_LOW || (size_t) addr + length >= ADDRESS_SPACE_HIGH
		|| (size_t) addr + length < (size_t) addr)
		return NULL;
	if (flags & MAP_FIXED)
	{
		if (!IS_ALIGNED(addr, PAGE_SIZE))
			return NULL;
		if ((flags & MAP_SHARED) || (flags & MAP_PRIVATE))
			return NULL;
		if (flags & MAP_ANONYMOUS)
		{
			uint32_t start_page = GET_PAGE(addr);
			uint32_t end_page = GET_PAGE((size_t)addr + length - 1);
			uint16_t start_block = GET_BLOCK(addr);
			uint16_t end_block = GET_BLOCK((size_t)addr + length - 1);

			/* Determine VirtualAlloc() range */
			uint16_t start_alloc_block, end_alloc_block;
			if (block_alloc_start[start_block] == 0)
				start_alloc_block = start_block;
			else
				start_alloc_block = start_block + 1;
			if (block_alloc_start[end_block] == 0)
				end_alloc_block = end_block;
			else
				end_alloc_block = end_block - 1;

			/* Test whether all pages are free */
			for (uint32_t i = start_page; i <= end_page; i++)
				if (page_map_entry[i])
					return NULL;

			/* Allocate missing memory blocks */
			if (start_alloc_block <= end_alloc_block)
			{
				if (!VirtualAlloc(GET_BLOCK_ADDRESS(start_alloc_block),
					(end_alloc_block - start_alloc_block + 1) * BLOCK_SIZE,
					MEM_COMMIT | MEM_RESERVE,
					prot_linux2win(prot)))
					return NULL;
				block_alloc_start[start_alloc_block] = start_alloc_block;
				block_alloc_start[end_alloc_block] = start_alloc_block;
			}

			/* Set up all kinds of flags */
			uint16_t entry = new_map_entry();
			map_entries[entry].start_page = start_page;
			map_entries[entry].end_page = end_page;
			for (uint32_t i = start_page; i <= end_page; i++)
			{
				page_map_entry[i] = entry;
				block_alloc_pages[GET_BLOCK_OF_PAGE(i)]++; /* TODO: Optimization */
			}
			return addr;
		}
	}
	return NULL;
}

int munmap(void *addr, size_t length)
{
	/* TODO */
}

int mprotect(void *addr, size_t len, int prot)
{
	/* TODO */
}

int msync(void *addr, size_t len, int flags)
{
	/* TODO */
}

int mlock(const void *addr, size_t len)
{
	/* TODO */
}

int munlock(const void *addr, size_t len)
{
	/* TODO */
}
