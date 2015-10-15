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

struct shared_data
{
	HANDLE object_directory;

	/* For shared_alloc() */
	HANDLE shared_section;
	void *shared_alloc_begin, *shared_alloc_current, *shared_alloc_end;
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
}

bool shared_fork(HANDLE process)
{
	NTSTATUS status;
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
	return true;
}

void shared_afterfork_parent()
{
}

void shared_afterfork_child()
{
	shared = (struct shared_data*)mm_static_alloc(sizeof(struct shared_data));
	shared->shared_alloc_current = shared->shared_alloc_begin;
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
