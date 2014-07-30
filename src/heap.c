#include "heap.h"
#include "syscall/mm.h"
#include "log.h"

#include <stdlib.h>

/* Fast kernel heap management for Foreign Linux
 *
 * We set up a memory pool for each power-of-two size.
 * When allocating memory, we use the minimum sized pool which fit.
 * A pool is a chained list of bucket, each of a memory block size (64kB), at 
 * each bucket there is a header structure storing the status of the bucket.
 */

struct bucket
{
	int ref_cnt;
	void *first_free;
	struct bucket *next_bucket;
};

struct pool
{
	int objsize;
	struct bucket *first;
};

#define POOL_COUNT	9
struct heap_data
{
	struct pool pools[POOL_COUNT];
};

static struct heap_data *const heap = MM_HEAP_BASE;

void heap_init()
{
	mm_mmap(MM_HEAP_BASE, sizeof(struct heap_data), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	heap->pools[0].objsize = 16;   heap->pools[0].first = NULL;
	heap->pools[1].objsize = 32;   heap->pools[0].first = NULL;
	heap->pools[2].objsize = 64;   heap->pools[0].first = NULL;
	heap->pools[3].objsize = 128;  heap->pools[0].first = NULL;
	heap->pools[4].objsize = 256;  heap->pools[0].first = NULL;
	heap->pools[5].objsize = 512;  heap->pools[0].first = NULL;
	heap->pools[6].objsize = 1024; heap->pools[0].first = NULL;
	heap->pools[7].objsize = 2048; heap->pools[0].first = NULL;
	heap->pools[8].objsize = 4096; heap->pools[0].first = NULL;
}

void heap_shutdown()
{
}

static struct bucket *alloc_bucket(int objsize)
{
	struct bucket *b = mm_mmap(0, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	b->ref_cnt = 0;
	b->next_bucket = NULL;

	/* Set up the chain of free objects */
	char *c = (char *)b + objsize;
	b->first_free = c;
	while (c + objsize < (char *)b + BLOCK_SIZE)
	{
		*(char **)c = c + objsize;
		c += objsize;
	}
	*(char **)c = NULL;
	return b;
}

void *kmalloc(int size)
{
	/* Find pool */
	int p = -1;
	for (int i = 0; i < POOL_COUNT; i++)
		if (size <= heap->pools[i].objsize)
		{
			p = i;
			break;
		}
	if (p == -1)
	{
		log_debug("kmalloc(%d): size too large.\n", size);
		return NULL;
	}
	
	/* Find a bucket with a free object slot */
	if (!heap->pools[p].first)
		heap->pools[p].first = alloc_bucket(heap->pools[p].objsize);

	struct bucket *current = heap->pools[p].first;
	for (;;)
	{
		if (!current)
		{
			log_debug("kmalloc(%d): out of memory\n", size);
			return NULL;
		}

		/* Current bucket has a free object, return it */
		if (current->first_free)
		{
			void *c = current->first_free;
			current->first_free = *(void**)c;
			current->ref_cnt++;
			return c;
		}

		/* Next bucket does not exist, allocate one */
		if (!current->next_bucket)
			current->next_bucket = alloc_bucket(heap->pools[p].objsize);

		/* Move to next bucket */
		current = current->next_bucket;
	}
}

void kfree(void *mem, int size)
{
	/* Find memory bucket */
	void *bucket_addr = (uint32_t) mem & 0xFFFF0000;

	/* Find pool */
	int p = -1;
	for (int i = 0; i < POOL_COUNT; i++)
		if (size <= heap->pools[i].objsize)
		{
			p = i;
			break;
		}
	if (p == -1)
	{
		log_debug("kfree(): Invalid size: %x\n", mem);
		return;
	}

	/* Loop over the chain to find the corresponding bucket */
	struct bucket *previous = NULL;
	struct bucket *current = heap->pools[p].first;
	while (current)
	{
		if (current != bucket_addr)
		{
			previous = current;
			current = current->next_bucket;
			continue;
		}

		*(void **)mem = current->first_free;
		current->first_free = mem;
		current->ref_cnt--;

		if (!current->ref_cnt)
		{
			/* Bucket empty, free it */
			if (!previous)
				heap->pools[p].first = current->next_bucket;
			else
				previous->next_bucket = current->next_bucket;
			mm_munmap(current, BLOCK_SIZE);
		}
	}
	log_debug("kfree(): Invalid memory pointer or size: (%x, %d)\n", mem, size);
}
