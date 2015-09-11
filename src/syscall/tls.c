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
#include <common/prctl.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/tls.h>
#include <intrin.h>
#include <log.h>
#include <platform.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <stddef.h>

#define MAX_TLS_ENTRIES		0x10

struct tls_data
{
	SRWLOCK rw_lock; /* Read write lock */
	DWORD entries[MAX_TLS_ENTRIES]; /* Win32 TLS slot id */
	XWORD current_values[MAX_TLS_ENTRIES]; /* Set by fork() to passing tls data to the new process */
	int entry_count;
	DWORD kernel_entries[TLS_KERNEL_ENTRY_COUNT];
	XWORD current_kernel_values[TLS_KERNEL_ENTRY_COUNT];
};

static struct tls_data *tls;

void tls_init()
{
	tls = mm_static_alloc(sizeof(struct tls_data));
	InitializeSRWLock(&tls->rw_lock);
	for (int i = 0; i < TLS_KERNEL_ENTRY_COUNT; i++)
	{
		tls->kernel_entries[i] = TlsAlloc();
		log_info("Allocated kernel TLS entry, entry: %d, slot: %d, fs offset 0x%x", i, tls->kernel_entries[i], tls_slot_to_offset(tls->kernel_entries[i]));
	}
}

void tls_reset()
{
	for (int i = 0; i < tls->entry_count; i++)
		TlsFree(tls->entries[i]);
	tls->entry_count = 0;
}

void tls_shutdown()
{
	for (int i = 0; i < tls->entry_count; i++)
		TlsFree(tls->entries[i]);
	for (int i = 0; i < TLS_KERNEL_ENTRY_COUNT; i++)
		TlsFree(tls->kernel_entries[i]);
}

int tls_fork(HANDLE process)
{
	AcquireSRWLockShared(&tls->rw_lock);
	log_info("Saving TLS context...");
	/* Save tls data for current thread into shared memory regions */
	for (int i = 0; i < tls->entry_count; i++)
	{
		tls->current_values[i] = (XWORD)TlsGetValue(tls->entries[i]);
		log_info("user entry %d value 0x%p", tls->entries[i], tls->current_values[i]);
	}
	for (int i = 0; i < TLS_KERNEL_ENTRY_COUNT; i++)
	{
		tls->current_kernel_values[i] = (XWORD)TlsGetValue(tls->kernel_entries[i]);
		log_info("kernel entry %d value 0x%p", tls->kernel_entries[i], tls->current_kernel_values[i]);
	}
	return 1;
}

void tls_afterfork_child()
{
	log_info("Restoring TLS context...");
	tls = mm_static_alloc(sizeof(struct tls_data));
	InitializeSRWLock(&tls->rw_lock);
	for (int i = 0; i < tls->entry_count; i++)
	{
		tls->entries[i] = TlsAlloc();
		TlsSetValue(tls->entries[i], (LPVOID)tls->current_values[i]);
		log_info("user entry %d value 0x%p", tls->entries[i], tls->current_values[i]);
	}
	for (int i = 0; i < TLS_KERNEL_ENTRY_COUNT; i++)
	{
		tls->kernel_entries[i] = TlsAlloc();
		TlsSetValue(tls->kernel_entries[i], (LPVOID)tls->current_kernel_values[i]);
		log_info("kernel entry %d value 0x%p", tls->kernel_entries[i], tls->current_kernel_values[i]);
	}
}

void tls_afterfork_parent()
{
	ReleaseSRWLockShared(&tls->rw_lock);
}

static int tls_slot_to_offset(int slot)
{
	if (slot < 64)
		return offsetof(TEB, TlsSlots[slot]);
	else
		return offsetof(TEB, TlsExpansionSlots) + (slot - 64) * sizeof(PVOID);
}

static int tls_offset_to_slot(int offset)
{
	if (offset < offsetof(TEB, TlsSlots[64]))
		return (offset - offsetof(TEB, TlsSlots)) / sizeof(PVOID);
	else
		return (offset - offsetof(TEB, TlsExpansionSlots)) / sizeof(PVOID) + 64;
}

int tls_kernel_entry_to_offset(int entry)
{
	return tls_slot_to_offset(tls->kernel_entries[entry]);
}

int tls_user_entry_to_offset(int entry)
{
	return tls_slot_to_offset(tls->entries[entry]);
}

/* Segment register format:
 * 15    3  2   0
 * [Index|TI|RPL]
 * TI: GDT = 0, LDT = 1
 * RPL: Ring 3
 */
int tls_set_thread_area(struct user_desc *u_info)
{
	log_info("set_thread_area(%p): entry=%d, base=%p, limit=%p", u_info, u_info->entry_number, u_info->base_addr, u_info->limit);
	int ret = 0;
	AcquireSRWLockExclusive(&tls->rw_lock);
	if (u_info->entry_number == -1)
	{
		if (tls->entry_count == MAX_TLS_ENTRIES)
			ret = -L_ESRCH;
		else
		{
			int slot = TlsAlloc();
			tls->entries[tls->entry_count] = slot;
			u_info->entry_number = tls->entry_count;
			log_info("allocated entry %d (slot %d), fs offset 0x%x", tls->entry_count, slot, tls_slot_to_offset(u_info->entry_number));
			tls->entry_count++;
			TlsSetValue(slot, (LPVOID)u_info->base_addr);
		}
	}
	else
		TlsSetValue(tls->entries[u_info->entry_number], (LPVOID)u_info->base_addr);
	ReleaseSRWLockExclusive(&tls->rw_lock);
	return ret;
}

DEFINE_SYSCALL(set_thread_area, struct user_desc *, u_info)
{
	return tls_set_thread_area(u_info);
}

DEFINE_SYSCALL(arch_prctl, int, code, uintptr_t, addr)
{
	log_info("arch_prctl(%d, 0x%p)", code, addr);
	switch (code)
	{
	case ARCH_SET_FS:
		log_error("ARCH_SET_FS not supported.");
		return -L_EINVAL;

	case ARCH_GET_FS:
		log_error("ARCH_GET_FS not supported.");
		return -L_EINVAL;

	case ARCH_SET_GS:
		log_error("ARCH_SET_GS not supported.");
		return -L_EINVAL;

	case ARCH_GET_GS:
		log_error("ARCH_GET_GS not supported.");
		return -L_EINVAL;

	default:
		log_error("Unknown code.");
		return -L_EINVAL;
	}
}
