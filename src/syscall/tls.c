#include <common/ldt.h>
#include <common/prctl.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/tls.h>
#include <errno.h>
#include <intrin.h>
#include <log.h>
#include <platform.h>
#include <stddef.h>
#include <winternl.h>

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

#include "x86_inst.h" /* x86 instruction definitions */

#ifndef _WIN64
#define MAX_TLS_ENTRIES		0x80
#endif

struct tls_data
{
#ifdef _WIN64
	DWORD fs_base_slot; /* Win32 TLS slot id for storing current emulated fs base address */
	PVOID fs_base;
#else
	DWORD gs_slot; /* Win32 TLS slot id for storing current emulated gs register */
	DWORD entries_slot[MAX_TLS_ENTRIES]; /* Win32 TLS slot id for each emulated tls entries */
	PVOID current_gs_value;
	PVOID current_entries_addr[MAX_TLS_ENTRIES];
	/* current_gs_addr and current_entries_addr is sed by fork to passing tls data to the new process */
#endif
	uint8_t trampoline[2048]; /* TODO */
};

static struct tls_data *const tls = TLS_DATA_BASE;

void tls_init()
{
	mm_mmap(TLS_DATA_BASE, sizeof(struct tls_data), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, NULL, 0);
#ifdef _WIN64
	tls->fs_base_slot = TlsAlloc();
	TlsSetValue(tls->fs_base_slot, 0);
#else
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		tls->entries_slot[i] = -1;
	tls->gs_slot = TlsAlloc();
#endif
}

void tls_reset()
{
#ifdef _WIN64
	TlsSetValue(tls->fs_base_slot, 0);
#else
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		if (tls->entries_slot[i] != -1)
		{
			TlsFree(tls->entries_slot[i]);
			tls->entries_slot[i] = -1;
		}
#endif
}

void tls_shutdown()
{
#ifdef _WIN64
	TlsFree(tls->fs_base_slot);
#else
	TlsFree(tls->gs_slot);
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		if (tls->entries_slot[i] != -1)
			TlsFree(tls->entries_slot[i]);
	mm_munmap(TLS_DATA_BASE, sizeof(struct tls_data));
#endif
}

void tls_beforefork()
{
	log_info("Saving TLS context...\n");
	/* Save tls data for current thread into shared memory regions */
#ifdef _WIN64
	tls->fs_base = TlsGetValue(tls->fs_base_slot);
	log_info("fs base addr 0x%p\n", tls->fs_base);
#else
	tls->current_gs_value = TlsGetValue(tls->gs_slot);
	log_info("gs slot %d value 0x%p\n", tls->gs_slot, tls->current_gs_value);
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		if (tls->entries_slot[i] != -1)
		{
			tls->current_entries_addr[i] = TlsGetValue(tls->entries_slot[i]);
			log_info("entry %d slot %d addr 0x%p\n", i, tls->entries_slot[i], tls->current_entries_addr[i]);
		}
#endif
}

void tls_afterfork()
{
	log_info("Restoring TLS context...\n");
#ifdef _WIN64
	tls->fs_base_slot = TlsAlloc();
	TlsSetValue(tls->fs_base_slot, tls->fs_base);
	log_info("fs base addr 0x%p\n", tls->fs_base);
#else
	tls->gs_slot = TlsAlloc();
	TlsSetValue(tls->gs_slot, tls->current_gs_value);
	log_info("gs slot %d value 0x%p\n", tls->gs_slot, tls->current_gs_value);
	/* Restore saved tls info from shared memory regions */
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		if (tls->entries_slot[i] != -1)
		{
			DWORD slot = TlsAlloc();
			tls->entries_slot[i] = slot;
			TlsSetValue(slot, tls->current_entries_addr[i]);
			log_info("entry %d slot %d addr 0x%p\n", i, tls->entries_slot[i], tls->current_entries_addr[i]);
		}
#endif
}

static size_t tls_slot_to_offset(DWORD slot)
{
	if (slot < 64)
		return offsetof(TEB, TlsSlots[slot]);
	else
		return offsetof(TEB, TlsExpansionSlots) + (slot - 64) * sizeof(PVOID);
}

static DWORD tls_offset_to_slot(size_t offset)
{
	if (offset < offsetof(TEB, TlsSlots[64]))
		return (offset - offsetof(TEB, TlsSlots)) / sizeof(PVOID);
	else
		return (offset - offsetof(TEB, TlsExpansionSlots)) / sizeof(PVOID) + 64;
}

#define LOW8(x) (*((uint8_t *)&(x)))
#define LOW16(x) (*((uint16_t *)&(x)))
#define LOW32(x) (*((uint32_t *)&(x)))
#define LOW64(x) (*((uint64_t *)&(x)))

#ifdef _WIN64
DEFINE_SYSCALL(arch_prctl, int, code, uintptr_t, addr)
{
	log_info("arch_prctl(%d, 0x%p)\n", code, addr);
	switch (code)
	{
	case ARCH_SET_FS:
		log_info("ARCH_SET_FS: new fs addr: 0x%p\n", addr);
		TlsSetValue(tls->fs_base_slot, (void *)addr);
		return 0;

	case ARCH_GET_FS:
		log_info("ARCH_GET_FS: old fs addr: 0x%p\n", *(uintptr_t *)addr = (uintptr_t)TlsGetValue(tls->fs_base_slot));
		return 0;

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

#else
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
		/* Find an empty entry */
		for (int i = 0; i < MAX_TLS_ENTRIES; i++)
			if (tls->entries_slot[i] == -1)
			{
				DWORD slot = TlsAlloc();
				tls->entries_slot[i] = slot;
				u_info->entry_number = tls_slot_to_offset(slot);
				log_info("allocated entry %d (slot %d), calculated fs offset 0x%x\n", i, slot, u_info->entry_number);
				break;
			}
		if (u_info->entry_number == -1)
			return -ESRCH;
	}
	__writefsdword(u_info->entry_number, u_info->base_addr);
	return 0;
}

static int handle_mov_reg_gs(PCONTEXT context, uint8_t modrm)
{
	/* 11 101 rrr */
	if ((modrm & 0xE8) != 0xE8)
	{
		return 0;
	}
	uint16_t val = TlsGetValue(tls->gs_slot);
	switch (modrm & 7)
	{
	case 0: LOW16(context->Eax) = val; break;
	case 1: LOW16(context->Ecx) = val; break;
	case 2: LOW16(context->Edx) = val; break;
	case 3: LOW16(context->Ebx) = val; break;
	case 4: LOW16(context->Esp) = val; break;
	case 5: LOW16(context->Ebp) = val; break;
	case 6: LOW16(context->Esi) = val; break;
	case 7: LOW16(context->Edi) = val; break;
	}
	return 1;
}

static int handle_mov_gs_reg(PCONTEXT context, uint8_t modrm)
{
	/* 11 101 rrr */
	if ((modrm & 0xE8) != 0xE8)
	{
		return 0;
	}
	uint16_t val;
	switch (modrm & 7)
	{
	case 0: val = context->Eax; break;
	case 1: val = context->Ecx; break;
	case 2: val = context->Edx; break;
	case 3: val = context->Ebx; break;
	case 4: val = context->Esp; break;
	case 5: val = context->Ebp; break;
	case 6: val = context->Esi; break;
	case 7: val = context->Edi; break;
	}
	uint16_t gs_offset = (val >> 3);
	log_info("mov gs, %d\n", tls_offset_to_slot(gs_offset));
	TlsSetValue(tls->gs_slot, tls_offset_to_slot(gs_offset));
	return 1;
}
#endif

#define GET_MODRM_MOD(c)	(((c) >> 6) & 7)
#define GET_MODRM_R(c)		(((c) >> 3) & 7)
#define GET_MODRM_RM(c)		((c) & 7)
#define GET_MODRM_CODE(c)	GET_MODRM_R(c)

#define GET_SIB_SCALE(s)	((s) >> 6)
#define GET_SIB_INDEX(s)	(((s) >> 3) & 7)
#define GET_SIB_BASE(s)		((s) & 7)

#define GET_REX_W(r)		(((r) >> 3) & 1)
#define GET_REX_R(r)		(((r) >> 2) & 1)
#define GET_REX_X(r)		(((r) >> 1) & 1)
#define GET_REX_B(r)		(r & 1)

#ifdef _WIN64
#define MODRM_RIP_RELATIVE	1
#else
#define MODRM_RIP_RELATIVE	0
#endif
/* Return bytes of ModR/M + SIB + disp, 0 on failure */
int process_modrm(uint8_t *code, int rex, int *reg, int *base, int *index, int *scale, int32_t *disp, int *flags)
{
	*flags = 0;
	uint8_t modrm = code[0];
	*reg = GET_MODRM_R(modrm);
	if (GET_REX_R(rex))
		*reg += 8;
	int mod = GET_MODRM_MOD(modrm);
	if (mod == 3)
	{
		log_error("ModR/M: Pure register access.\n");
		return 0;
	}
	int sib_bytes = 0;
	int rm = GET_MODRM_RM(modrm);
	if (rm == 4)
	{
		/* ModR/M with SIB byte */
		sib_bytes = 1;
		int sib = code[1];
		*scale = GET_SIB_SCALE(sib);
		if ((*index = GET_SIB_INDEX(sib)) == 4)
			*index = -1;
		else if (GET_REX_X(rex))
			*index += 8;
		if ((*base = GET_SIB_BASE(sib)) == 5 && mod == 0)
		{
			*base = -1;
			mod = 2; /* For use later to correctly extract disp32 */
		}
		else if (GET_REX_B(rex))
			*base += 8;
	}
	else
	{
		/* ModR/M without SIB byte */
		*index = -1;
		*scale = 0;
		if (mod == 0 && rm == 5) /* disp32 */
		{
			*base = -1;
			*disp = *(int32_t *)&code[1];
			*flags |= MODRM_RIP_RELATIVE;
			return 5;
		}
		if (GET_REX_B(rex))
			*base = rm + 8;
		else
			*base = rm;
	}
	/* Displacement */
	if (mod == 1) /* disp8 */
	{
		*disp = *(int8_t *)&code[sib_bytes + 1];
		return sib_bytes + 2;
	}
	else if (mod == 2) /* disp32 */
	{
		*disp = *(int32_t *)&code[sib_bytes + 1];
		return sib_bytes + 5;
	}
	else /* no disp */
	{
		*disp = 0;
		return sib_bytes + 1;
	}
}

static __forceinline void gen_byte(uint8_t **trampoline, uint8_t x)
{
	*(*trampoline)++ = x;
}

static __forceinline void gen_word(uint8_t **trampoline, uint16_t x)
{
	*(uint16_t *)(*trampoline) = x;
	*trampoline += 2;
}

static __forceinline void gen_dword(uint8_t **trampoline, uint32_t x)
{
	*(uint32_t *)(*trampoline) = x;
	*trampoline += 4;
}

static __forceinline void gen_qword(uint8_t **trampoline, uint64_t x)
{
	*(uint64_t *)(*trampoline) = x;
	*trampoline += 8;
}

static __forceinline void gen_copy(uint8_t **trampoline, uint8_t *code, int count)
{
	for (int i = 0; i < count; i++)
		gen_byte(trampoline, *code++);
}

static __forceinline void gen_copy_prefix(uint8_t **trampoline, uint8_t *code, int count)
{
#ifdef _WIN64
#define TLS_OVERRIDE_CODE 0x64 /* FS */
#else
#define TLS_OVERRIDE_CODE 0x65 /* GS */
#endif
	for (int i = 0; i < count; i++)
		if (*code != TLS_OVERRIDE_CODE)
			gen_byte(trampoline, *code++);
		else
			code++;
}

static __forceinline void gen_rex(uint8_t **trampoline, int w, int r, int x, int b)
{
	gen_byte(trampoline, 0x40 + (w << 3) + (r << 2) + (x << 1) + b);
}

static __forceinline void gen_modrm(uint8_t **trampoline, int mod, int r, int rm)
{
	gen_byte(trampoline, (mod << 6) + (r << 3) + rm);
}

static __forceinline void gen_sib(uint8_t **trampoline, int base, int index, int scale)
{
	gen_byte(trampoline, (scale << 6) + (index << 3) + base);
}

static __forceinline void gen_epilogue(uint8_t **trampoline, uint8_t *return_addr)
{
#ifdef _WIN64
	gen_byte(trampoline, 0xFF); /* FF /4: JMP r/m64 */
	gen_modrm(trampoline, 0, 4, 5); /* RIP relative disp32 */
	gen_dword(trampoline, 0);
	gen_qword(trampoline, (uint64_t)return_addr);
#else
	gen_byte(trampoline, 0x68); /* PUSH imm32 */
	gen_dword(trampoline, (uint32_t)return_addr);
	gen_byte(trampoline, 0xC3); /* RET */
#endif
}

static __forceinline void gen_inst_modrm(uint8_t **trampoline, uint8_t *opcode, int opcode_bytes,
	int rex_w, int reg, int base, int index, int scale, int32_t disp, int flags)
{
	if (index == 4)
	{
		log_error("gen_modrm(): rsp or r12 cannot be used as an index register.\n");
		return;
	}
#ifdef _WIN64
	if (rex_w != -1) /* rex_w == 1 means no rex prefix */
	{
		int rex_r = 0, rex_x = 0, rex_b = 0;
		if (reg >= 8)
		{
			rex_r = 1;
			reg -= 8;
		}
		if (base >= 8)
		{
			rex_b = 1;
			base -= 8;
		}
		if (index >= 8)
		{
			rex_x = 1;
			index -= 8;
		}
		gen_rex(trampoline, rex_w, rex_r, rex_x, rex_b);
	}
#endif
	for (int i = 0; i < opcode_bytes; i++)
		gen_byte(trampoline, *opcode++);
	/* TODO: Shall we support disp8? */
	if (base == -1 && index == -1) /* disp32 */
	{
#ifdef _WIN64
		if (flags & MODRM_RIP_RELATIVE)
			gen_modrm(trampoline, 0, reg, 5);
		else
		{
			gen_modrm(trampoline, 0, reg, 4);
			gen_sib(trampoline, 5, 4, 0);
		}
#else
		gen_modrm(trampoline, 0, reg, 5);
#endif
		gen_dword(trampoline, disp);
	}
	else if (base == -1) /* [scaled index] + disp32 */
	{
		gen_modrm(trampoline, 0, reg, 4);
		gen_sib(trampoline, 5, index, scale);
		gen_dword(trampoline, disp);
	}
	else if (base == 4) /* SIB required */
	{
		gen_modrm(trampoline, 2, reg, 4);
		gen_sib(trampoline, base, index, scale);
		gen_dword(trampoline, disp);
	}
	else
	{
		/* SIB not needed */
		gen_modrm(trampoline, 2, reg, base);
		gen_dword(trampoline, disp);
	}
}

int tls_emulation(PCONTEXT context, uint8_t *code)
{
	log_info("TLS Emulation begin.\n");
	if (context->Xip >= tls->trampoline && context->Xip < tls->trampoline + sizeof(tls->trampoline))
	{
		log_warning("IP Inside TLS trampoline!!!!! Emulation skipped.\n");
		return 0;
	}
#ifndef _WIN64
	if (code[0] == 0x8C)
	{
		/* 8C /r: MOV r/m16, Sreg */
		if (handle_mov_reg_gs(context, code[1]))
		{
			context->Eip += 2;
			return 1;
		}
	}
	else if (code[0] == 0x66 && code[1] == 0x8C)
	{
		/* ... with optional 16-bit prefix 66H */
		if (handle_mov_reg_gs(context, code[2]))
		{
			context->Eip += 3;
			return 1;
		}
	}
	else if (code[0] == 0x8E)
	{
		/* 8E /r: MOV Sreg, r/m16 */
		if (handle_mov_gs_reg(context, code[1]))
		{
			context->Eip += 2;
			return 1;
		}
	}
	else if (code[0] == 0x66 && code[1] == 0x8E)
	{
		if (handle_mov_gs_reg(context, code[2]))
		{
			context->Eip += 3;
			return 1;
		}
	}
#endif
	else
	{
		/* Maybe a normal instruction involving with segment prefix.
		 * Because x86 has a large number of instructions, we don't emulate
		 * any of them, instead we examine the address mode of the instruction
		 * and patch it to use the base address.
		 */
		log_info("TLS: Try emulating instruction at %p\n", context->Xip);
		/* First let's deal with instruction prefix.
		 * According to x86 doc the prefixes can appear in any order.
		 * We just loop over the prefixes and ensure it has the GS segment
		 * override prefix we want.
		 */
		uint8_t *prefix = code;
		int prefix_len = 0;
		int operand_size_prefix = 0, address_size_prefix = 0;
		int found_segment_override = 0;
		for (;;)
		{
			if (prefix[prefix_len] == 0xF0) /* LOCK */
				prefix_len++;
			else if (prefix[prefix_len] == 0xF2) /* REPNE/REPNZ */
				prefix_len++;
			else if (prefix[prefix_len] == 0xF3) /* REP/REPE/REPZ */
				prefix_len++;
			else if (prefix[prefix_len] == 0x2E) /* CS segment override */
			{
				log_info("Found CS segment override, skipped\n");
				return 0;
			}
			else if (prefix[prefix_len] == 0x36) /* SS segment override */
			{
				log_info("Found SS segment override, skipped\n");
				return 0;
			}
			else if (prefix[prefix_len] == 0x3E) /* DS segment override */
			{
				log_info("Found DS segment override, skipped\n");
				return 0;
			}
			else if (prefix[prefix_len] == 0x26) /* ES segment override */
			{
				log_info("Found ES segment override, skipped\n");
				return 0;
			}
			else if (prefix[prefix_len] == 0x64) /* FS segment override */
			{
#ifdef _WIN64
				prefix_len++;
				found_segment_override = 1;
#else
				log_info("Found FS segment override, skipped\n");
				return 0;
#endif
			}
			else if (prefix[prefix_len] == 0x65) /* GS segment override <- we're interested */
			{
#ifdef _WIN64
				log_info("Found GS segment override, skipped\n");
				return 0;
#else
				prefix_len++;
				found_segment_override = 1;
#endif
			}
			else if (prefix[prefix_len] == 0x66) /* Operand size prefix */
			{
				operand_size_prefix = 1;
				prefix_len++;
			}
			else if (prefix[prefix_len] == 0x67) /* Address size prefix */
			{
				address_size_prefix = 1;
				log_warning("Address size prefix not supported.\n");
				return 0;
			}
			else
				break;
		}
		if (!found_segment_override)
		{
			log_info("Instruction has no gs override.\n");
			return 0;
		}

		uint8_t *opcode = prefix + prefix_len;
		int rex = 0;
		int rex_w = -1;
#ifdef _WIN64
		if (*opcode >= 0x40 && *opcode <= 0x4F) /* REX Prefix */
		{
			log_info("Found rex prefix.\n");
			rex = *opcode++;
			rex_w = GET_REX_W(rex);
		}
#endif

		struct instruction_desc *desc;
		int opcode_len;
		if (opcode[0] == 0x0F)
		{
			log_info("Opcode: 0x0F%02x\n", opcode[1]);
			desc = &two_byte_inst[opcode[1]];
			opcode_len = 2;
		}
		else
		{
			log_info("Opcode: 0x%02x\n", opcode[0]);
			desc = &one_byte_inst[opcode[0]];
			opcode_len = 1;
		}

		uint8_t *operand = opcode + opcode_len;

#ifdef _WIN64
		size_t tls_addr = TlsGetValue(tls->fs_base_slot);
#else
		/* TODO: Optimization to reduce one lookup? */
		size_t gs_value = TlsGetValue(tls->gs_slot);
		size_t tls_addr = TlsGetValue(gs_value);
#endif

		uint8_t *_temp = tls->trampoline;
		uint8_t **trampoline = &_temp;

		#define FINISH_TRAMPOLINE() \
			do { \
				context->Xip = tls->trampoline; \
				log_info("Building trampoline successfully at %p\n", tls->trampoline); \
			} while (0)

		switch (desc->type)
		{
		case INST_TYPE_NOP: log_error("The opcode contains no interested memory references.\n"); return 0;
		case INST_TYPE_IMMEDIATE: log_error("The opcode contains no interested memory references.\n"); return 0;
		case INST_TYPE_UNKNOWN: log_error("Unknown opcode.\n"); return 0;
		case INST_TYPE_INVALID: log_error("Invalid opcode.\n"); return 0;
		case INST_TYPE_UNSUPPORTED: log_error("Unsupported opcode.\n"); return 0;
		case INST_TYPE_MODRM:
		{
			int imm_bytes = desc->imm_bytes;
			if (imm_bytes == PREFIX_OPERAND_SIZE)
			{
				imm_bytes = operand_size_prefix? 2: 4;
#ifdef _WIN64
				if ((rex & 0x08) > 0)
					imm_bytes = 4;
#endif
			}
			else if (imm_bytes == PREFIX_OPERAND_SIZE_64)
			{
				imm_bytes = operand_size_prefix? 2: 4;
#ifdef _WIN64
				if ((rex & 0x08) > 0)
					imm_bytes = 4;
#endif
			}
			int reg, base, index, scale, flags, modrm_bytes;
			int32_t disp;
			if (!(modrm_bytes = process_modrm(operand, rex, &reg, &base, &index, &scale, &disp, &flags)))
				return 0;

#ifdef _WIN64
			/* x64 does not support 64bit offsets in ModR/M
			 * Thus we have to store the computed address in a temporary register
			 */
			/* Calculate used registers in this instruction */
			int used_regs = desc->read_regs | desc->write_regs;
			if (reg != -1)
				used_regs |= REG_MASK(reg);
			if (base != -1)
				used_regs |= REG_MASK(base);
			if (index != -1)
				used_regs |= REG_MASK(index);

			/* Find an unused register to hold the temporary address */
			/* We need to be careful here because the accessible register file is different when switching
			 * rex prefix on and off (AH/SPL, CH/BPL, DH/SIL, BH/DIL stuff).
			 * So we must ensure that we won't change the status of the rex prefix. Thus we cannot use
			 * the extended registers R8-R15
			 */
			int temp_reg = -1;
			DWORD64 saved_value;
			#define TEST_REG(r, name) do { \
				if ((used_regs & REG_MASK(r)) == 0) { temp_reg = r; saved_value = context->name; } \
			} while (0)
			TEST_REG(0, Rax);
			TEST_REG(1, Rcx);
			TEST_REG(2, Rdx);
			TEST_REG(3, Rbx);
			TEST_REG(6, Rsi);
			TEST_REG(7, Rdi);
			#undef TEST_REG
			if (temp_reg == -1)
			{
				log_error("No usable temporary register found, there must be a bug in our implementation.\n");
				return 0;
			}

			/* mov Rxx, <fs base addr> */
			gen_rex(trampoline, 1, 0, 0, 0);
			gen_byte(trampoline, 0xB8 + temp_reg); /* MOV r64, imm64 */
			gen_qword(trampoline, tls_addr);

			/* lea Rxx, [Rxx + base reg] */
			if (base != -1)
			{
				char inst = 0x8D; /* LEA r64, m*/
				gen_inst_modrm(trampoline, &inst, 1, 1, temp_reg, temp_reg, base, 0, 0, 0);
			}

			/* <inst> ... [Rxx + index * scale + disp] ... */
			gen_copy_prefix(trampoline, prefix, prefix_len);
			gen_inst_modrm(trampoline, opcode, opcode_len, rex_w, reg, temp_reg, index, scale, disp, flags);
			gen_copy(trampoline, operand + modrm_bytes, imm_bytes);

			/* mov Rxx, <saved value> */
			gen_rex(trampoline, 1, 0, 0, 0);
			gen_byte(trampoline, 0xB8 + temp_reg); /* MOV r64, imm64 */
			gen_qword(trampoline, saved_value);

			/* epilogue */
			gen_epilogue(trampoline, operand + modrm_bytes + imm_bytes);

			FINISH_TRAMPOLINE();
#else
			/* Generate equivalent trampoline code by patching ModR/M */
			gen_copy_prefix(trampoline, prefix, prefix_len);
			gen_inst_modrm(trampoline, opcode, opcode_len, -1, reg, base, index, scale, disp + tls_addr, flags);
			gen_copy(trampoline, operand + modrm_bytes, imm_bytes);
			gen_epilogue(trampoline, operand + modrm_bytes + imm_bytes);

			FINISH_TRAMPOLINE();
#endif
			return 1;
		}

		case INST_TYPE_MOV_MOFFSET:
		{
#ifdef _WIN64
			__debugbreak();
#else
			/* MOV AL, moffs8 */
			/* MOV AX, moffs16 */
			/* MOV EAX, moffs32 */
			/* MOV moffs8, AL */
			/* MOV moffs16, AX */
			/* MOV moffs32, EAX */
			/* TODO: Deal with address_size_prefix when we support it */
			uint32_t addr = tls_addr + LOW32(operand[0]);
			gen_copy_prefix(trampoline, prefix, prefix_len);
			gen_byte(trampoline, opcode[0]);
			gen_dword(trampoline, addr);
			gen_epilogue(trampoline, operand + 4);

			FINISH_TRAMPOLINE();
			return 1;
#endif
		}

		case INST_TYPE_EXTENSION(5):
#ifdef _WIN64
			__debugbreak();
#else
			if (GET_MODRM_CODE(operand[0]) == 2)
			{
				int reg, base, index, scale, flags, modrm_bytes;
				int32_t disp;
				if (!(modrm_bytes = process_modrm(operand, rex, &reg, &base, &index, &scale, &disp, &flags)))
					return 0;

				/* CALL r/m16; CALL r/m32; */
				/* Push return address */
				gen_byte(trampoline, 0x68); /* PUSH imm32 */
				gen_dword(trampoline, operand + modrm_bytes); /* Return address */
				gen_copy_prefix(trampoline, prefix, prefix_len);
				/* Change to JMP r/m16; JMP r/m32; */
				char inst = 0xFF;
				gen_inst_modrm(trampoline, &inst, 1, -1, 4, base, index, scale, disp + tls_addr, flags);

				FINISH_TRAMPOLINE();
				return 1;
			}
#endif
			/* Fall through */

		default: log_error("Unhandled instruction type: %d\n", desc->type); return 0;
		}
	}
	return 0;
}
