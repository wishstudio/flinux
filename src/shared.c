/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2015 Xiangyan Sun <wishstudio@gmail.com>
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
#include <flags.h>
#include <log.h>
#include <shared.h>

#include <ntdll.h>

#define SHARED_HEAP_POOL_COUNT	1024
#define SHARED_HEAP_POOL_SIZE	BLOCK_SIZE

struct shared_heap_pool_header
{
	volatile int initialized;
	void *volatile first_free;
};

struct shared_heap_pool_desc
{
	/* Use volatile for automatic release semantic and avoids compiler reordering */
	volatile int obj_size;
	volatile int ref_count;
	volatile int next_pool_id;
};

struct shared_heap_data
{
	struct shared_heap_pool_desc pools[SHARED_HEAP_POOL_COUNT];
};

struct shared_heap_mapped_pool_desc
{
	HANDLE handle;
	struct shared_heap_pool_header *addr;
};

/* This structure stores per process local descriptor of shared data region */
struct shared_data
{
	SRWLOCK rw_lock;
	HANDLE object_directory;

	/* For shared_alloc() */
	HANDLE shared_section;
	void *shared_alloc_begin, *shared_alloc_current, *shared_alloc_end;

	/* For kmalloc_shared() */
	HANDLE shared_heap_mutex;
	struct shared_heap_data *shared_heap;
	struct shared_heap_mapped_pool_desc shared_heap_mapped_pools[SHARED_HEAP_POOL_COUNT];
};

static struct shared_data *shared;

HANDLE shared_get_object_directory()
{
	return shared->object_directory;
}

static void shared_create_object_directory()
{
	/* Convert session id to wide string */
	WCHAR id[MAX_SESSION_ID_LEN];
	for (int i = 0; i < MAX_SESSION_ID_LEN; i++)
		id[i] = cmdline_flags->global_session_id[i];

	UNICODE_STRING name;
	WCHAR name_buf[64];
	RtlInitEmptyUnicodeString(&name, name_buf, sizeof(name_buf));
	RtlAppendUnicodeToString(&name, L"\\BaseNamedObjects\\flinux-");
	RtlAppendUnicodeToString(&name, id);
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &name, OBJ_INHERIT | OBJ_OPENIF, NULL, NULL);
	NTSTATUS status;
	status = NtCreateDirectoryObject(&shared->object_directory, DIRECTORY_ALL_ACCESS, &oa);
	if (!NT_SUCCESS(status))
	{
		log_error("NtCreateDirectoryObject() failed, status: %x", status);
		NtTerminateProcess(NtCurrentProcess(), 1);
	}
}

void shared_init()
{
	shared = (struct shared_data *)mm_static_alloc(sizeof(struct shared_data));
	shared_create_object_directory();
	InitializeSRWLock(&shared->rw_lock);

	log_info("Session ID: %s", cmdline_flags->global_session_id);
	log_info("Initialize global shared region...");
	/* Generate shared section name */
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"shared");

	NTSTATUS status;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &name, OBJ_INHERIT | OBJ_OPENIF, shared->object_directory, NULL);
	LARGE_INTEGER size;
	size.QuadPart = SHARED_ALLOC_SIZE;
	status = NtCreateSection(
		&shared->shared_section,
		SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
		&oa,
		&size,
		PAGE_READWRITE,
		SEC_COMMIT,
		NULL);
	if (!NT_SUCCESS(status))
	{
		log_error("shared_init: Create global shared area failed, status: %x", status);
		NtTerminateProcess(NtCurrentProcess(), 1);
	}

	SIZE_T view_size = SHARED_ALLOC_SIZE;
	status = NtMapViewOfSection(
		shared->shared_section,
		NtCurrentProcess(),
		&shared->shared_alloc_begin,
		0,
		SHARED_ALLOC_SIZE,
		NULL,
		&view_size,
		ViewUnmap,
		0,
		PAGE_READWRITE
		);
	if (!NT_SUCCESS(status))
	{
		log_error("shared_init: Map global shared area failed, status: %x", status);
		NtTerminateProcess(NtCurrentProcess(), 0);
	}
	shared->shared_alloc_current = shared->shared_alloc_begin;
	shared->shared_alloc_end = (char*)shared->shared_alloc_begin + SHARED_ALLOC_SIZE;
	/* Initialize shared heap */
	RtlInitUnicodeString(&name, L"shared_heap_mutex");
	InitializeObjectAttributes(&oa, &name, OBJ_INHERIT | OBJ_OPENIF, shared->object_directory, NULL);
	status = NtCreateMutant(&shared->shared_heap_mutex, MUTANT_ALL_ACCESS, &oa, FALSE);
	if (!NT_SUCCESS(status))
	{
		log_error("shared_init: Create shared heap mutex failed, status: %x", status);
		NtTerminateProcess(NtCurrentProcess(), 0);
	}
	shared->shared_heap = (struct shared_heap_data *)shared_alloc(sizeof(struct shared_heap_data));
}

bool shared_fork(HANDLE process)
{
	NTSTATUS status;
	/* Map shared data region */
	SIZE_T view_size = SHARED_ALLOC_SIZE;
	status = NtMapViewOfSection(
		shared->shared_section,
		process,
		&shared->shared_alloc_begin,
		0,
		SHARED_ALLOC_SIZE,
		NULL,
		&view_size,
		ViewUnmap,
		0,
		PAGE_READWRITE
		);
	if (!NT_SUCCESS(status))
	{
		log_error("shared_fork: Map global shared area failed, status: %x", status);
		return false;
	}
	/* Map mapped shared heap data regions */
	AcquireSRWLockShared(&shared->rw_lock);
	int current_pool = shared->shared_heap->pools[0].next_pool_id;
	while (current_pool != 0)
	{
		if (shared->shared_heap_mapped_pools[current_pool].addr)
		{
			view_size = SHARED_HEAP_POOL_SIZE;
			status = NtMapViewOfSection(
				shared->shared_heap_mapped_pools[current_pool].handle,
				process,
				&shared->shared_heap_mapped_pools[current_pool].addr,
				0,
				SHARED_HEAP_POOL_SIZE,
				NULL,
				&view_size,
				ViewUnmap,
				0,
				PAGE_READWRITE
				);
			if (!NT_SUCCESS(status))
			{
				log_error("shared_fork: Map shared heap pool %d failed, status: %x", current_pool, status);
				ReleaseSRWLockShared(&shared->rw_lock);
				return false;
			}
		}
		current_pool = shared->shared_heap->pools[current_pool].next_pool_id;
	}
	return true;
}

void shared_afterfork_parent()
{
	ReleaseSRWLockShared(&shared->rw_lock);
}

void shared_afterfork_child()
{
	shared = (struct shared_data*)mm_static_alloc(sizeof(struct shared_data));
	InitializeSRWLock(&shared->rw_lock);
	shared->shared_alloc_current = shared->shared_alloc_begin;
	shared->shared_heap = (struct shared_heap_data *)shared_alloc(sizeof(struct shared_heap_data));
}

void *shared_alloc(size_t size)
{
	if ((uint8_t*)shared->shared_alloc_current + size > shared->shared_alloc_end)
	{
		log_error("shared_alloc(): Overlarge static block size, remain: %p, requested: %p",
			(uint8_t*)shared->shared_alloc_end - (uint8_t*)shared->shared_alloc_current, size);
		log_error("Please enlarge SHARED_ALLOC_SIZE manually.");
		__debugbreak();
	}
	void *ret = shared->shared_alloc_current;
	shared->shared_alloc_current = (void*)ALIGN_TO((uint8_t*)shared->shared_alloc_current + size, 16);
	return ret;
}

static bool map_shared_heap_pool(size_t obj_size, int id)
{
	/* Create/open shared heap pool */
	WCHAR namebuf[64];
	UNICODE_STRING name;
	OBJECT_ATTRIBUTES oa;
	RtlInitEmptyUnicodeString(&name, namebuf, sizeof(namebuf));
	RtlAppendUnicodeToString(&name, L"shared_heap_pool_");
	RtlAppendIntegerToString(id, 10, &name);
	InitializeObjectAttributes(&oa, &name, OBJ_INHERIT | OBJ_OPENIF, shared->object_directory, NULL);

	LARGE_INTEGER size;
	size.QuadPart = SHARED_HEAP_POOL_SIZE;
	NTSTATUS status = NtCreateSection(&shared->shared_heap_mapped_pools[id].handle,
		SECTION_MAP_READ | SECTION_MAP_WRITE, &oa, &size, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		log_error("map_shared_heap_pool(%d, %d): NtCreateSection() failed, status: %x", (int)obj_size, id, status);
		return false;
	}
	SIZE_T view_size = SHARED_HEAP_POOL_SIZE;
	status = NtMapViewOfSection(shared->shared_heap_mapped_pools[id].handle, NtCurrentProcess(),
		(PVOID *)&shared->shared_heap_mapped_pools[id].addr, 0, SHARED_HEAP_POOL_SIZE, NULL, &view_size, 0, ViewUnmap,
		PAGE_READWRITE);
	if (NT_SUCCESS(status))
	{
		NtClose(shared->shared_heap_mapped_pools[id].handle);
		shared->shared_heap_mapped_pools[id].handle = NULL;
		shared->shared_heap_mapped_pools[id].addr = NULL;
		log_error("map_shared_heap_pool(%d, %d): NtMapViewOfSection() failed, status: %x", (int)obj_size, id, status);
		return false;
	}
	struct shared_heap_pool_header *pool = (struct shared_heap_pool_header *)shared->shared_heap_mapped_pools[id].addr;
	if (!pool->initialized)
	{
		/* We just created the pool, initialize it now */
		int pool_ref_count = (SHARED_HEAP_POOL_SIZE - sizeof(struct shared_heap_pool_header)) / obj_size;
		size_t start = (size_t)pool + ALIGN_TO(sizeof(struct shared_heap_pool_header), 8);
		size_t end = (size_t)pool + SHARED_HEAP_POOL_SIZE;
		pool->first_free = (void*)start;
		for (size_t addr = start; addr < end; addr += obj_size)
		{
			if (start + obj_size < end)
				*(void**)start = (void*)(start + obj_size);
			else
				*(void**)start = NULL;
		}
		shared->shared_heap->pools[id].obj_size = obj_size;
		shared->shared_heap->pools[id].ref_count = pool_ref_count;
		pool->initialized = true;
	}
	return true;
}

void *kmalloc_shared(size_t obj_size)
{
	obj_size = ALIGN_TO(obj_size, 8);
	AcquireSRWLockExclusive(&shared->rw_lock);
	WaitForSingleObject(shared->shared_heap_mutex, INFINITE);
	int pool_max_ref_count = (SHARED_HEAP_POOL_SIZE - sizeof(struct shared_heap_pool_header)) / obj_size;
	/* Find or create a pool suitable for requested object size */
	int last_pool = 0;
	int current_pool = shared->shared_heap->pools[0].next_pool_id;
	while (current_pool != 0)
	{
		if (shared->shared_heap->pools[current_pool].obj_size == obj_size
			&& shared->shared_heap->pools[current_pool].ref_count < pool_max_ref_count)
			break;
		last_pool = current_pool;
		current_pool = shared->shared_heap->pools[current_pool].next_pool_id;
	}
	if (current_pool == 0)
	{
		/* Did not find an appropriate pool, create a new one */
		/* Firstly, find an unused pool id */
		for (int i = 0; i < SHARED_HEAP_POOL_COUNT; i++)
		{
			if (shared->shared_heap->pools[i].obj_size == 0)
			{
				current_pool = i;
				break;
			}
		}
		/* All pool ids are exhausted, give up */
		if (current_pool == 0)
			goto failed;
		/* Secondly, create the pool with that id */
		if (!map_shared_heap_pool(obj_size, current_pool))
			goto failed;
		/* Finally, link the pool information to the shared data area */
		shared->shared_heap->pools[current_pool].next_pool_id = 0;
		shared->shared_heap->pools[last_pool].next_pool_id = current_pool;
	}
	else
	{
		if (shared->shared_heap_mapped_pools[current_pool].addr == NULL)
		{
			/* Pool currently not mapped on this process, map it now */
			if (!map_shared_heap_pool(obj_size, current_pool))
				goto failed;
		}
	}
	/* Pool found and successfully mapped, allocate memory on selected pool */
	void *cur = shared->shared_heap_mapped_pools[current_pool].addr->first_free;
	void *next = *(void **)cur;
	shared->shared_heap_mapped_pools[current_pool].addr->first_free = next;
	shared->shared_heap->pools[current_pool].ref_count--;
	NtReleaseMutant(shared->shared_heap_mutex, NULL);
	return cur;

failed:
	NtReleaseMutant(shared->shared_heap_mutex, NULL);
	ReleaseSRWLockExclusive(&shared->rw_lock);
	return NULL;
}

void kfree_shared(void *obj, size_t obj_size)
{
	obj_size = ALIGN_TO(obj_size, 8);
	AcquireSRWLockExclusive(&shared->rw_lock);
	WaitForSingleObject(shared->shared_heap_mutex, INFINITE);
	/* Find pool id */
	struct shared_heap_pool_header *pool = (struct shared_heap_pool_header *)((size_t)obj & -(SHARED_HEAP_POOL_SIZE));
	int last_pool = 0;
	int current_pool = shared->shared_heap->pools[0].next_pool_id;
	while (shared->shared_heap_mapped_pools[current_pool].addr != pool)
	{
		last_pool = current_pool;
		current_pool = shared->shared_heap->pools[current_pool].next_pool_id;
	}
	/* Remove occupied memory in shared heap pool */
	*(void **)obj = pool->first_free;
	pool->first_free = obj;
	shared->shared_heap->pools[current_pool].ref_count--;
	/* If the pool becomes empty after this operation, free the entire pool */
	if (shared->shared_heap->pools[current_pool].ref_count == 0)
	{
		/* Unlink pool */
		shared->shared_heap->pools[last_pool].next_pool_id = shared->shared_heap->pools[current_pool].next_pool_id;
		/* Delete pool */
		NtUnmapViewOfSection(NtCurrentProcess(), shared->shared_heap_mapped_pools[last_pool].addr);
		shared->shared_heap_mapped_pools[last_pool].handle = NULL;
		shared->shared_heap_mapped_pools[last_pool].addr = NULL;
	}
	NtReleaseMutant(shared->shared_heap_mutex, NULL);
	ReleaseSRWLockExclusive(&shared->rw_lock);
}
