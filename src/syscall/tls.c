#include "tls.h"
#include "mm.h"
#include <log.h>

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
 * Q: How to emulate TLS?
 *
 * Keep gs to the zero value. This will cause an access violation on every
 * access related to gs. In the exception handler we can manually inspect
 * which instruction caused the violation and emulate that behavior.
 */

#include "x86_inst.h" /* x86 instruction definitions */

#define VIRTUAL_GDT_BASE	0x80 /* To guarantee access violation when in use */
#define MAX_TLS_ENTRIES		0x80

struct tls_entry
{
	int allocated;
	int addr;
	int limit;
};

struct tls_data
{
	struct tls_entry entries[MAX_TLS_ENTRIES];
	uint32_t gs, gs_addr; /* i386 explicitly requires pre-fetching segment information */
	uint8_t trampoline[PAGE_SIZE];
};

static struct tls_data *const tls = TLS_DATA_BASE;

void tls_init()
{
	sys_mmap(TLS_DATA_BASE, sizeof(struct tls_data), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void tls_shutdown()
{
	sys_munmap(TLS_DATA_BASE, sizeof(struct tls_data));
}

/* Segment register format:
 * 15    3  2   0
 * [Index|TI|RPL]
 * TI: GDT = 0, LDT = 1
 * RPL: Ring 3
 */

int sys_set_thread_area(struct user_desc *u_info)
{
	log_debug("set_thread_area(%x): entry=%d, base=%x, limit=%x\n", u_info, u_info->entry_number, u_info->base_addr, u_info->limit);
	if (u_info->entry_number == -1)
	{
		/* Find an empty entry */
		for (int i = 0; i < MAX_TLS_ENTRIES; i++)
			if (!tls->entries[i].allocated)
			{
				u_info->entry_number = VIRTUAL_GDT_BASE + i;
				log_debug("allocated entry %d (%x)\n", i, u_info->entry_number);
				break;
			}
		if (u_info->entry_number == -1)
		{
			/* TODO: errno */
			return -1;
		}
	}
	else if (u_info->entry_number < VIRTUAL_GDT_BASE) /* A simply consistency check */
		return -1;
	int entry = u_info->entry_number - VIRTUAL_GDT_BASE;
	tls->entries[entry].allocated = 1;
	tls->entries[entry].addr = u_info->base_addr;
	tls->entries[entry].limit = u_info->limit;
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
	uint16_t val = tls->gs;
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
	uint16_t entry = (val >> 3) - VIRTUAL_GDT_BASE;
	if (entry >= MAX_TLS_ENTRIES || !tls->entries[entry].allocated)
		return 0;
	tls->gs = val;
	tls->gs_addr = tls->entries[entry].addr;
	return 1;
}

#define MODRM_MOD(c)	(((c) >> 6) & 7)
#define MODRM_R(c)		(((c) >> 3) & 7)
#define MODRM_M(c)		((c) & 7)
#define MODRM_CODE(c)	MODRM_R(c)
int tls_gs_emulation(PCONTEXT context, uint8_t *code)
{
	if (context->Eip >= tls->trampoline && context->Eip < tls->trampoline + sizeof(tls->trampoline))
	{
		log_debug("EIP Inside TLS trampoline!!!!! Emulation skipped.\n");
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
		log_debug("TLS: Try emulating instruction at %x\n", context->Eip);
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
				log_debug("Found CS segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x36) /* SS segment override */
			{
				log_debug("Found SS segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x3E) /* DS segment override */
			{
				log_debug("Found DS segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x26) /* ES segment override */
			{
				log_debug("Found ES segment override, skipped\n");
				return 0;
			}
			else if (code[prefix_end] == 0x64) /* FS segment override */
			{
				log_debug("Found FS segment override, skipped\n");
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
				log_debug("Address size prefix not supported.\n");
				return 0;
			}
			else
				break;
		}
		if (!found_gs_override)
		{
			log_debug("Instruction has no gs override.\n");
			return 0;
		}
		struct instruction_desc *desc;
		int modrm_offset;
		if (code[prefix_end] == 0x0F)
		{
			desc = &two_byte_inst[code[prefix_end + 1]];
			modrm_offset = 2;
		}
		else
		{
			desc = &one_byte_inst[code[prefix_end]];
			modrm_offset = 1;
		}

		int idx = 0;
		#define GEN_BYTE(x)		tls->trampoline[idx++] = (x)
		#define GEN_WORD(x)		*(uint16_t *)&tls->trampoline[(idx += 2) - 2] = (x)
		#define GEN_DWORD(x)	*(uint32_t *)&tls->trampoline[(idx += 4) - 4] = (x)
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
			GEN_BYTE(0xC3); /* RET */ \
			context->Eip = tls->trampoline; \
			log_debug("Building trampoline successfully at %x\n", tls->trampoline)

		switch (desc->type)
		{
		case INST_TYPE_NOP: return 0;
		case INST_TYPE_UNKNOWN: log_debug("Unknown opcode.\n"); return 0;
		case INST_TYPE_MODRM:
		{
			/* Generate equivalent trampoline code by patch ModR/M */
			COPY_PREFIX();

			/* Copy opcode */
			for (int i = prefix_end; i < prefix_end + modrm_offset; i++)
				GEN_BYTE(code[i]);

			/* Patch ModR/M */
			uint8_t modrm = code[prefix_end + modrm_offset];
			uint8_t mod = MODRM_MOD(modrm);
			if (mod == 3)
			{
				log_debug("ModR/M: Pure register access.");
				return 0;
			}
			int sib = (MODRM_M(modrm) == 4);
			int addr_bytes = 0;
			uint32_t base_addr = 0;
			if (mod == 1) /* disp8 (sign-extended) */
			{
				base_addr = (int8_t) code[prefix_end + modrm_offset + 1 + sib];
				addr_bytes = 1;
			}
			else if (mod == 2 /* disp32 */
				|| (mod == 0 && MODRM_M(modrm) == 5)) /* special case: immediate disp32 */
			{
				base_addr = *(uint32_t *) &code[prefix_end + modrm_offset + 1 + sib];
				addr_bytes = 4;
			}
			base_addr += tls->gs_addr;
			if (mod == 0 && MODRM_M(modrm) == 5) /* special case: immediate disp32 */
			{
				GEN_BYTE(modrm);
				GEN_DWORD(base_addr);
			}
			else
			{
				GEN_BYTE((modrm & 0x3F) | 0x80); /* Mod == 10: [...] + disp32 */
				if (sib)
					GEN_BYTE(code[prefix_end + modrm_offset + 1]);
				GEN_DWORD(base_addr);
			}
			/* Copy immediate value */
			int imm_bytes = desc->imm_bytes;
			if (imm_bytes == SIZE_DEPENDS_ON_PREFIX)
				imm_bytes = operand_size_prefix? 2: 4;
			for (int i = 0; i < imm_bytes; i++)
				GEN_BYTE(code[prefix_end + modrm_offset + 1 + sib + addr_bytes + i]);

			GEN_EPILOGUE(modrm_offset + 1 + sib + addr_bytes + imm_bytes);
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
			uint32_t addr = tls->gs_addr + LOW32(code[prefix_end + 1]);
			COPY_PREFIX();
			GEN_BYTE(code[prefix_end]);
			GEN_DWORD(addr);
			GEN_EPILOGUE(5);
			return 1;
		}

		default: log_debug("Unhandled instruction type: %d\n", desc->type); return 0;
		}
	}
	return 0;
}
