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

#include <syscall/mm.h>
#include <heap.h>
#include <log.h>

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

#define POOL_COUNT	11
struct heap_data
{
	struct pool pools[POOL_COUNT];
};

static struct heap_data *heap;

void heap_init()
{
	log_info("heap subsystem initializating...\n");
	heap = mm_static_alloc(sizeof(struct heap_data));
	heap->pools[0].objsize = 16;		heap->pools[0].first = NULL;
	heap->pools[1].objsize = 32;		heap->pools[1].first = NULL;
	heap->pools[2].objsize = 64;		heap->pools[2].first = NULL;
	heap->pools[3].objsize = 128;		heap->pools[3].first = NULL;
	heap->pools[4].objsize = 256;		heap->pools[4].first = NULL;
	heap->pools[5].objsize = 512;		heap->pools[5].first = NULL;
	heap->pools[6].objsize = 1024;		heap->pools[6].first = NULL;
	heap->pools[7].objsize = 2048;		heap->pools[7].first = NULL;
	heap->pools[8].objsize = 4096;		heap->pools[8].first = NULL;
	heap->pools[9].objsize = 8192;		heap->pools[9].first = NULL;
	heap->pools[10].objsize = 16384;	heap->pools[10].first = NULL;
	log_info("heap subsystem initialized.\n");
}

void heap_shutdown()
{
}

void heap_afterfork()
{
	heap = mm_static_alloc(sizeof(struct heap_data));
}

#define ALIGN(x, align) (((x) + ((align) - 1)) & -(align))
static struct bucket *alloc_bucket(int objsize)
{
	struct bucket *b = mm_mmap(0, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
		INTERNAL_MAP_TOPDOWN | INTERNAL_MAP_NORESET, NULL, 0);
	b->ref_cnt = 0;
	b->next_bucket = NULL;

	/* Set up the chain of free objects */
	char *c = (char *)b + ALIGN(sizeof(struct bucket), sizeof(void *)); /* Align to machine word size */
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
		log_error("kmalloc(%d): size too large.\n", size);
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
			log_error("kmalloc(%d): out of memory\n", size);
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
	void *bucket_addr = (void *)((size_t) mem & (-PAGE_SIZE));

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
		log_error("kfree(): Invalid size: %x\n", mem);
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
		return;
	}
	log_error("kfree(): Invalid memory pointer or size: (%x, %d)\n", mem, size);
}
