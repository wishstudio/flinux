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
#include <common/ldt.h>
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

/* Linux thread local storage (TLS) support emulation
 *
 * Q: Why we need emulation?
 *
 * The working of Linux's TLS mechanisms is summarized as the following:
 * 1. A thread register a TLS area using set_thread_area() call with
 *    entry_number = -1. The system will allocate a TLS entry and fill the
 *    field when return. The entry number is actually an index into the
 *    system's GDT table.
 * 2. Other threads can allocate its own TLS area and using the same entry
 *    number returned by step 1 to register to the same TLS slot.
 * 3. When task switching occurs, the kernel will reload a thread's all TLS
 *    descriptors into GDT.
 * 4. When a thread needs to access TLS data, it just set gs register to the
 *    corresponding TLS entry number. Due to the GDT settings done on task
 *    switching, [gs:0] will always be the address of the current thread's
 *    registered TLS area. This way we can access any TLS data using mov
 *    instructions with virtually no cost.
 *
 * The Windows' way of TLS is slightly different:
 * 1. Internally Windows uses the fs register to store the "Thread Information
 *    Block" (TIB), which is a per thread structure and automatically switched
 *    on task switching. The TIB structure contains many data/flags for a
 *    thread. Beginning with [fs:e10h] there is a 256-slots area for storing
 *    thread local DWORD values.
 * 2. A thread first calls TlsAlloc() function to allocate an empty TLS slot.
 *    Then all threads can use TlsSetValue() and TlsGetValue() to set and
 *    retrieve its own local storage pointer.
 *
 * The good news is that Linux rarely uses the fs register, and on Windows
 * the gs register is unused. We won't get conflict on the use of these two
 * segment registers.
 * The bad news is when mimicing Linux TLS behavior is the need to add custom
 * entries into GDT and maintain them on context switch. Depending on the
 * version of Windows, this may or may not be possible:
 * 1. On all current versions of Windows, the GDT is unmodifiable by a user
 *    mode (ring 3) process.
 * 2. On 32-bit Windows, the GDT can only be modified by a kernel driver.
 *    However, a user mode process can use NtSetInformationProcess() or
 *    NtAddLdtEntries() to add custom LDT entries. We can assign a different
 *    LDT slot per thread/TLS entry and return a fake entry_number on
 *    set_thread_area() call. When user application move the entry number
 *    to gs a access violation exception will occur and we have a chance to
 *    set correct gs value.
 * 3. On 64-bit Windows, the LDT simply does not exist. Calling
 *    NtSetInformationProcess() and NtAddLdtEntries() will return
 *    NT_STATUS_NOT_IMPLEMENTED. Even with a driver, due to the protection
 *    made by the newly introduced PatchGuard, modifying the GDT will BSOD
 *    the system. So we need software emulation in this case.
 * Currently I only work on software emulation of TLS. The non-emulated
 * way for 32-bit Windows remains a TODO.
 *
 * Q: How to implement TLS?
 *
 * There are two flavor of approaches, one is emulation and another is
 * patching.
 * 1. Emulation
 * Keep gs to the zero value. This will cause an access violation on every
 * access related to gs. In the exception handler we can manually inspect
 * which instruction caused the violation and emulate that behavior. This
 * does not require any modifications to the executables. But as exception
 * handling is very expensive, this will not get good performance. Another
 * issue is on x86_64 systems, the Windows WOW64 runtimes seems to mess up
 * Win64 TEB pointer to gs register at context switches. This approach
 * will easily lead to crashes in this case.
 *
 * 2. Patching
 * Make patches for glibc which is (AFAIK) the only source for gs accesses.
 * Windows x86 TLS uses the fs segment register for storage. The location for
 * each TLS slot can be easily figured. Since the offset may change between
 * operating systems and we don't want to check this in glibc, we calculate
 * the offset here and pass it to glibc. Then at each TLS access we patch
 * glibc to use the fs segment register to first acquire the location of
 * the current TLS storage, then access its own TLS variables.
 *
 */

/* Notes for x64
 * On x64 one can directly set the base address of FS and GS segment register
 * through SWAPFS and SWAPGS instructions. A system call arch_prctl() is
 * provided for this purpose. Windowx uses GS register and glibc uses FS
 * register for TLS storage. We do not need to fake GDT/LDT stuff but only a
 * base address for the FS segment register.
 */

#define MAX_TLS_ENTRIES		0x10

struct tls_data
{
	DWORD entries[MAX_TLS_ENTRIES]; /* Win32 TLS slot id */
	DWORD current_values[MAX_TLS_ENTRIES]; /* Set by fork() to passing tls data to the new process */
	int entry_count;
	DWORD kernel_entries[TLS_KERNEL_ENTRY_COUNT];
	DWORD current_kernel_values[TLS_KERNEL_ENTRY_COUNT];
};

static struct tls_data *const tls = TLS_DATA_BASE;

void tls_init()
{
	mm_mmap(TLS_DATA_BASE, sizeof(struct tls_data), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, NULL, 0);
	for (int i = 0; i < TLS_KERNEL_ENTRY_COUNT; i++)
	{
		tls->kernel_entries[i] = TlsAlloc();
		log_info("Allocated kernel TLS entry, entry: %d, slot: %d, fs offset 0x%x\n", i, tls->kernel_entries[i], tls_slot_to_offset(tls->kernel_entries[i]));
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
	mm_munmap(TLS_DATA_BASE, sizeof(struct tls_data));
}

void tls_beforefork()
{
	log_info("Saving TLS context...\n");
	/* Save tls data for current thread into shared memory regions */
	for (int i = 0; i < tls->entry_count; i++)
	{
		tls->current_values[i] = TlsGetValue(tls->entries[i]);
		log_info("user entry %d value 0x%p\n", tls->entries[i], tls->current_values[i]);
	}
	for (int i = 0; i < TLS_KERNEL_ENTRY_COUNT; i++)
	{
		tls->current_kernel_values[i] = TlsGetValue(tls->kernel_entries[i]);
		log_info("kernel entry %d value 0x%p\n", tls->kernel_entries[i], tls->current_kernel_values[i]);
	}
}

void tls_afterfork()
{
	log_info("Restoring TLS context...\n");
	for (int i = 0; i < tls->entry_count; i++)
	{
		tls->entries[i] = TlsAlloc();
		TlsSetValue(tls->entries[i], tls->current_values[i]);
		log_info("user entry %d value 0x%p\n", tls->entries[i], tls->current_values[i]);
	}
	for (int i = 0; i < TLS_KERNEL_ENTRY_COUNT; i++)
	{
		tls->kernel_entries[i] = TlsAlloc();
		TlsSetValue(tls->kernel_entries[i], tls->current_kernel_values[i]);
		log_info("kernel entry %d value 0x%p\n", tls->kernel_entries[i], tls->current_kernel_values[i]);
	}
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

DEFINE_SYSCALL(set_thread_area, struct user_desc *, u_info)
{
	log_info("set_thread_area(%p): entry=%d, base=%p, limit=%p\n", u_info, u_info->entry_number, u_info->base_addr, u_info->limit);
	if (u_info->entry_number == -1)
	{
		if (tls->entry_count == MAX_TLS_ENTRIES)
			return -ESRCH;
		int slot = TlsAlloc();
		tls->entries[tls->entry_count] = slot;
		u_info->entry_number = tls->entry_count;
		log_info("allocated entry %d (slot %d), fs offset 0x%x\n", tls->entry_count, slot, tls_slot_to_offset(u_info->entry_number));
		tls->entry_count++;
		TlsSetValue(slot, u_info->base_addr);
	}
	else
		TlsSetValue(tls_slot_to_offset(tls->entries[u_info->entry_number]), u_info->base_addr);
	return 0;
}

DEFINE_SYSCALL(arch_prctl, int, code, uintptr_t, addr)
{
	log_info("arch_prctl(%d, 0x%p)\n", code, addr);
	switch (code)
	{
	case ARCH_SET_FS:
		log_error("ARCH_SET_FS not supported.\n");
		return -EINVAL;

	case ARCH_GET_FS:
		log_error("ARCH_GET_FS not supported.\n");
		return -EINVAL;

	case ARCH_SET_GS:
		log_error("ARCH_SET_GS not supported.\n");
		return -EINVAL;

	case ARCH_GET_GS:
		log_error("ARCH_GET_GS not supported.\n");
		return -EINVAL;

	default:
		log_error("Unknown code.\n");
		return -EINVAL;
	}
}
