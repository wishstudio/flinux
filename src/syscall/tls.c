#include <syscall/mm.h>
#include <syscall/tls.h>
#include <errno.h>
#include <intrin.h>
#include <log.h>
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

#include "x86_inst.h" /* x86 instruction definitions */

#define MAX_TLS_ENTRIES		0x80

struct tls_data
{
	DWORD gs_slot; /* Win32 TLS slot id for storing current emulated gs register */
	DWORD entries_slot[MAX_TLS_ENTRIES]; /* Win32 TLS slot id for each emulated tls entries */
	PVOID current_gs_value;
	PVOID current_entries_addr[MAX_TLS_ENTRIES];
	/* current_gs_addr and current_entries_addr is sed by fork to passing tls data to the new process */
	uint8_t trampoline[2048]; /* TODO */
};

static struct tls_data *const tls = TLS_DATA_BASE;

void tls_init()
{
	sys_mmap(TLS_DATA_BASE, sizeof(struct tls_data), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		tls->entries_slot[i] = -1;
	tls->gs_slot = TlsAlloc();
}

void tls_reset()
{
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		if (tls->entries_slot[i] != -1)
		{
			TlsFree(tls->entries_slot[i]);
			tls->entries_slot[i] = -1;
		}
}

void tls_shutdown()
{
	TlsFree(tls->gs_slot);
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		if (tls->entries_slot[i] != -1)
			TlsFree(tls->entries_slot[i]);
	sys_munmap(TLS_DATA_BASE, sizeof(struct tls_data));
}

void tls_beforefork()
{
	log_info("Saving TLS context...\n");
	/* Save tls data for current thread into shared memory regions */
	tls->current_gs_value = TlsGetValue(tls->gs_slot);
	log_info("gs slot %d value 0x%x\n", tls->gs_slot, tls->current_gs_value);
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		if (tls->entries_slot[i] != -1)
		{
			tls->current_entries_addr[i] = TlsGetValue(tls->entries_slot[i]);
			log_info("entry %d slot %d addr 0x%x\n", i, tls->entries_slot[i], tls->current_entries_addr[i]);
		}
}

void tls_afterfork()
{
	log_info("Restoring TLS context...\n");
	tls->gs_slot = TlsAlloc();
	TlsSetValue(tls->gs_slot, tls->current_gs_value);
	log_info("gs slot %d value 0x%x\n", tls->gs_slot, tls->current_gs_value);
	/* Restore saved tls info from shared memory regions */
	for (int i = 0; i < MAX_TLS_ENTRIES; i++)
		if (tls->entries_slot[i] != -1)
		{
			DWORD slot = TlsAlloc();
			tls->entries_slot[i] = slot;
			TlsSetValue(slot, tls->current_entries_addr[i]);
			log_info("entry %d slot %d addr 0x%x\n", i, tls->entries_slot[i], tls->current_entries_addr[i]);
		}
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

/* Segment register format:
 * 15    3  2   0
 * [Index|TI|RPL]
 * TI: GDT = 0, LDT = 1
 * RPL: Ring 3
 */

int sys_set_thread_area(struct user_desc *u_info)
{
	log_info("set_thread_area(%x): entry=%d, base=%x, limit=%x\n", u_info, u_info->entry_number, u_info->base_addr, u_info->limit);
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
#if _WIN64
	__writefsqword(u_info->entry_number, u_info->base_addr);
#else
	__writefsdword(u_info->entry_number, u_info->base_addr);
#endif
	return 0;
}

#define LOW8(x) (*((uint8_t *)&(x)))
#define LOW16(x) (*((uint16_t *)&(x)))
#define LOW32(x) (*((uint32_t *)&(x)))
#define LOW64(x) (*((uint64_t *)&(x)))
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

#define MODRM_MOD(c)	(((c) >> 6) & 7)
#define MODRM_R(c)		(((c) >> 3) & 7)
#define MODRM_M(c)		((c) & 7)
#define MODRM_CODE(c)	MODRM_R(c)
int tls_gs_emulation(PCONTEXT context, uint8_t *code)
{
	log_info("TLS Emulation begin.\n");
	if (context->Eip >= tls->trampoline && context->Eip < tls->trampoline + sizeof(tls->trampoline))
	{
		log_warning("EIP Inside TLS trampoline!!!!! Emulation skipped.\n");
		return 0;
	}
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
	else
	{
		/* Maybe a normal instruction involving with segment prefix.
		 * Because x86 has a large number of instructions, we don't emulate
		 * any of them, instead we examine the address mode of the instruction
		 * and patch it to use the base address.
		 */
		log_info("TLS: Try emulating instruction at %x\n", context->Eip);
		/* First let's deal with instruction prefix.
		 * According to x86 doc the prefixes can appear in any order.
		 * We just loop over the prefixes and ensure it has the GS segment
		 * override prefix we want.
		 */
		int prefix_end = 0, operand_size_prefix = 0, address_size_prefix = 0;
		int found_gs_override = 0;
		for (;;)
		{
			if (code[prefix_end] == 0xF0) /* LOCK */
				prefix_end++;
			else if (code[prefix_end] == 0xF2) /* REPNE/REPNZ */
				prefix_end++;
			else if (code[prefix_end] == 0xF3) /* REP/REPE/REPZ */
				prefix_end++;
			else if (code[prefix_end] == 0x2E) /* CS segment override */
			{
				log_info("Found CS segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x36) /* SS segment override */
			{
				log_info("Found SS segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x3E) /* DS segment override */
			{
				log_info("Found DS segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x26) /* ES segment override */
			{
				log_info("Found ES segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x64) /* FS segment override */
			{
				log_info("Found FS segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x65) /* GS segment override <- we're interested */
			{
				prefix_end++;
				found_gs_override = 1;
			}
			else if (code[prefix_end] == 0x66) /* Operand size prefix */
			{
				operand_size_prefix = 1;
				prefix_end++;
			}
			else if (code[prefix_end] == 0x67) /* Address size prefix */
			{
				address_size_prefix = 1;
				log_warning("Address size prefix not supported.\n");
				return 0;
			}
			else
				break;
		}
		if (!found_gs_override)
		{
			log_warning("Instruction has no gs override.\n");
			return 0;
		}
		struct instruction_desc *desc;
		int inst_len;
		if (code[prefix_end] == 0x0F)
		{
			log_info("Opcode: 0x0F%02x\n", code[prefix_end + 1]);
			desc = &two_byte_inst[code[prefix_end + 1]];
			inst_len = 2;
		}
		else
		{
			log_info("Opcode: 0x%02x\n", code[prefix_end]);
			desc = &one_byte_inst[code[prefix_end]];
			inst_len = 1;
		}
		/* TODO: Optimization to reduce one lookup? */
		size_t gs_value = TlsGetValue(tls->gs_slot);
		size_t gs_addr = TlsGetValue(gs_value);

		int idx = 0;
		#define JUMP_TO_TRAMPOLINE() \
			context->Eip = tls->trampoline; \
			log_info("Building trampoline successfully at %x\n", tls->trampoline)
		#define GEN_BYTE(x)		tls->trampoline[idx++] = (x)
		#define GEN_WORD(x)		*(uint16_t *)&tls->trampoline[(idx += 2) - 2] = (x)
		#define GEN_DWORD(x)	*(uint32_t *)&tls->trampoline[(idx += 4) - 4] = (x)
		#define PATCH_DWORD(idx, x)		*(uint32_t *)&tls->trampoline[idx] = (x)
		#define COPY_PREFIX() \
			/* Copy prefixes */ \
			for (int i = 0; i < prefix_end; i++) \
				if (code[i] == 0x65) /* GS segment override -> skip */ \
					continue; \
				else \
					GEN_BYTE(code[i])
		#define GEN_EPILOGUE(inst_len) \
			GEN_BYTE(0x68); /* PUSH imm32 */ \
			GEN_DWORD(context->Eip + prefix_end + (inst_len)); \
			GEN_BYTE(0xC3); /* RET */
		#define GEN_MODRM_R(changed_r) \
			{ \
				uint8_t modrm = code[prefix_end + inst_len]; \
				if (changed_r != -1) \
					modrm = (modrm & 0xC7) | (changed_r << 3);; \
				uint8_t mod = MODRM_MOD(modrm); \
				if (mod == 3) \
				{ \
					log_warning("ModR/M: Pure register access."); \
					return 0; \
				} \
				inst_len++; \
				int sib = (MODRM_M(modrm) == 4); \
				int addr_bytes = 0; \
				uint32_t base_addr = 0; \
				if (mod == 1) /* disp8 (sign-extended) */ \
				{ \
					base_addr = (int8_t)code[prefix_end + inst_len + sib]; \
					addr_bytes = 1; \
				} \
				else if (mod == 2 /* disp32 */ \
					|| (mod == 0 && MODRM_M(modrm) == 5)) /* special case: immediate disp32 */ \
				{ \
					base_addr = *(uint32_t *)&code[prefix_end + inst_len + sib]; \
					addr_bytes = 4; \
				} \
				base_addr += gs_addr; \
				if (mod == 0 && MODRM_M(modrm) == 5) /* special case: immediate disp32 */ \
				{ \
					GEN_BYTE(modrm); \
					GEN_DWORD(base_addr); \
				} \
				else \
				{ \
					GEN_BYTE((modrm & 0x3F) | 0x80); /* Mod == 10: [...] + disp32 */ \
					if (sib) \
						GEN_BYTE(code[prefix_end + inst_len]); \
					GEN_DWORD(base_addr); \
				} \
				inst_len += sib + addr_bytes; \
			}
		#define GEN_MODRM() GEN_MODRM_R(-1)

		switch (desc->type)
		{
		case INST_TYPE_NOP: return 0;
		case INST_TYPE_UNKNOWN: log_error("Unknown opcode.\n"); return 0;
		case INST_TYPE_MODRM:
		{
			/* Generate equivalent trampoline code by patch ModR/M */
			COPY_PREFIX();

			/* Copy opcode */
			for (int i = prefix_end; i < prefix_end + inst_len; i++)
				GEN_BYTE(code[i]);

			/* Patch ModR/M */
			GEN_MODRM();

			/* Copy immediate value */
			int imm_bytes = desc->imm_bytes;
			if (imm_bytes == SIZE_DEPENDS_ON_PREFIX)
				imm_bytes = operand_size_prefix? 2: 4;
			for (int i = 0; i < imm_bytes; i++)
				GEN_BYTE(code[prefix_end + inst_len + i]);

			GEN_EPILOGUE(inst_len + imm_bytes);
			JUMP_TO_TRAMPOLINE();
			return 1;
		}

		case INST_TYPE_MOV_MOFFSET:
		{
			/* MOV AL, moffs8 */
			/* MOV AX, moffs16 */
			/* MOV EAX, moffs32 */
			/* MOV moffs8, AL */
			/* MOV moffs16, AX */
			/* MOV moffs32, EAX */
			/* TODO: Deal with address_size_prefix when we support it */
			uint32_t addr = gs_addr + LOW32(code[prefix_end + 1]);
			COPY_PREFIX();
			GEN_BYTE(code[prefix_end]);
			GEN_DWORD(addr);
			GEN_EPILOGUE(5);
			JUMP_TO_TRAMPOLINE();
			return 1;
		}

		case INST_TYPE_EXTENSION(5):
			if (MODRM_CODE(code[prefix_end + inst_len]) == 2)
			{
				/* CALL r/m16; CALL r/m32; */
				/* Push return address */
				GEN_BYTE(0x68); /* PUSH imm32 */
				int patch_idx = idx;
				GEN_DWORD(0); /* Patch later */
				COPY_PREFIX();
				/* Change to JMP r/m16; JMP r/m32; */
				GEN_BYTE(0xFF);
				GEN_MODRM_R(4);
				/* Patch return address */
				PATCH_DWORD(patch_idx, context->Eip + prefix_end + (inst_len));
				JUMP_TO_TRAMPOLINE();
				return 1;
			}
			/* Fall through */

		default: log_error("Unhandled instruction type: %d\n", desc->type); return 0;
		}
	}
	return 0;
}
