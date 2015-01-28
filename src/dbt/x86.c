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

#include <core/forward_list.h>
#include <dbt/x86.h>
#include <dbt/x86_inst.h>
#include <syscall/fork.h>
#include <syscall/mm.h>
#include <syscall/tls.h>
#include <log.h>

#include <stddef.h>
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define ALIGN_TO(x, a)		((uintptr_t)((x) + (a) - 1) & -(a))

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

#define EAX		0
#define ECX		1
#define EDX		2
#define EBX		3
#define ESP		4
#define EBP		5
#define ESI		6
#define EDI		7

/* ModR/M flags */
#define MODRM_PURE_REGISTER	1

struct modrm_rm_t
{
	int base, index, scale, flags;
	int32_t disp;
};

/* Helpers for constructing modrm_rm_t structure */
static struct modrm_rm_t __forceinline modrm_rm_reg(int r)
{
	struct modrm_rm_t rm;
	rm.base = r;
	rm.index = -1;
	rm.scale = 0;
	rm.disp = 0;
	rm.flags = MODRM_PURE_REGISTER;
	return rm;
}

static struct modrm_rm_t __forceinline modrm_rm_disp(int32_t disp)
{
	struct modrm_rm_t rm;
	rm.base = -1;
	rm.index = -1;
	rm.scale = 0;
	rm.disp = disp;
	rm.flags = 0;
	return rm;
}

static struct modrm_rm_t __forceinline modrm_rm_mreg(int base, int32_t disp)
{
	struct modrm_rm_t rm;
	rm.base = base;
	rm.index = -1;
	rm.scale = 0;
	rm.disp = disp;
	rm.flags = 0;
	return rm;
}

static struct modrm_rm_t __forceinline modrm_rm_mscale(int base, int index, int scale, int32_t disp)
{
	struct modrm_rm_t rm;
	rm.base = base;
	rm.index = index;
	rm.scale = scale;
	rm.disp = disp;
	rm.flags = 0;
	return rm;
}

static int __forceinline modrm_rm_is_r(struct modrm_rm_t rm)
{
	return rm.flags & MODRM_PURE_REGISTER;
}

static int __forceinline modrm_rm_is_m(struct modrm_rm_t rm)
{
	return (rm.flags & MODRM_PURE_REGISTER) == 0;
}

static uint8_t __forceinline parse_byte(uint8_t **code)
{
	return *(*code)++;
}

static uint16_t __forceinline parse_word(uint8_t **code)
{
	return *((uint16_t*)*code)++;
}

static uint32_t __forceinline parse_dword(uint8_t **code)
{
	return *((uint32_t*)*code)++;
}

static uint64_t __forceinline parse_qword(uint8_t **code)
{
	return *((uint64_t*)*code)++;
}

static int32_t __forceinline parse_rel(uint8_t **code, int rel_bytes)
{
	if (rel_bytes == 1)
		return (int8_t)parse_byte(code);
	else if (rel_bytes == 2)
		return (int16_t)parse_word(code);
	else
		return (int32_t)parse_dword(code);
}

static uint32_t __forceinline parse_moffset(uint8_t **code, int imm_bytes)
{
	if (imm_bytes == 1)
		return parse_byte(code);
	else if (imm_bytes == 2)
		return parse_word(code);
	else
		return parse_dword(code);
}

static void parse_modrm(uint8_t **code, int *r, struct modrm_rm_t *rm)
{
	uint8_t modrm = parse_byte(code);
	*r = GET_MODRM_R(modrm);
	int mod = GET_MODRM_MOD(modrm);
	if (mod == 3)
	{
		rm->flags = MODRM_PURE_REGISTER;
		rm->base = GET_MODRM_RM(modrm);
		rm->index = -1;
		return;
	}
	rm->flags = 0;
	int sib_bytes = 0;
	int modrm_rm = GET_MODRM_RM(modrm);
	if (modrm_rm == 4)
	{
		/* ModR/M with SIB byte */
		sib_bytes = 1;
		int sib = parse_byte(code);
		rm->scale = GET_SIB_SCALE(sib);
		if ((rm->index = GET_SIB_INDEX(sib)) == 4)
			rm->index = -1;
		if ((rm->base = GET_SIB_BASE(sib)) == 5 && mod == 0)
		{
			rm->base = -1;
			mod = 2; /* For use later to correctly extract disp32 */
		}
	}
	else
	{
		/* ModR/M without SIB byte */
		rm->index = -1;
		rm->scale = 0;
		if (mod == 0 && modrm_rm == 5) /* disp32 */
		{
			rm->base = -1;
			rm->disp = (int32_t)parse_dword(code);
			return;
		}
		rm->base = modrm_rm;
	}
	/* Displacement */
	if (mod == 1) /* disp8 */
		rm->disp = (int8_t)parse_byte(code);
	else if (mod == 2) /* disp32 */
		rm->disp = (int32_t)parse_dword(code);
	else /* no disp */
		rm->disp = 0;
}

static __forceinline void gen_byte(uint8_t **out, uint8_t x)
{
	*(*out)++ = x;
}

static __forceinline void gen_word(uint8_t **out, uint16_t x)
{
	*(uint16_t *)(*out) = x;
	*out += 2;
}

static __forceinline void gen_dword(uint8_t **out, uint32_t x)
{
	*(uint32_t *)(*out) = x;
	*out += 4;
}

static __forceinline void gen_qword(uint8_t **out, uint64_t x)
{
	*(uint64_t *)(*out) = x;
	*out += 8;
}

static __forceinline void gen_copy(uint8_t **out, uint8_t *code, int count)
{
	for (int i = 0; i < count; i++)
		gen_byte(out, *code++);
}

static __forceinline void gen_modrm(uint8_t **out, int mod, int r, int rm)
{
	gen_byte(out, (mod << 6) + (r << 3) + rm);
}

static __forceinline void gen_sib(uint8_t **out, int base, int index, int scale)
{
	gen_byte(out, (scale << 6) + (index << 3) + base);
}

static __forceinline void gen_modrm_sib(uint8_t **out, int r, struct modrm_rm_t rm)
{
	if (rm.flags == MODRM_PURE_REGISTER)
	{
		gen_modrm(out, 3, r, rm.base);
		return;
	}
	if (rm.index == 4)
	{
		log_error("gen_modrm(): rsp or r12 cannot be used as an index register.\n");
		return;
	}
	int is_disp8 = (((int8_t)rm.disp) == rm.disp);
	if (rm.base == -1 && rm.index == -1) /* disp32 */
	{
		gen_modrm(out, 0, r, 5);
		gen_dword(out, rm.disp);
	}
	else if (rm.base == -1) /* [scaled index] + disp32 */
	{
		gen_modrm(out, 0, r, 4);
		gen_sib(out, 5, rm.index, rm.scale);
		gen_dword(out, rm.disp);
	}
	else if (rm.base == 4 || rm.index != -1) /* SIB required */
	{
		gen_modrm(out, is_disp8? 1: 2, r, 4);
		gen_sib(out, rm.base, rm.index == -1? 4: rm.index, rm.scale);
		if (is_disp8)
			gen_byte(out, (int8_t)rm.disp);
		else
			gen_dword(out, rm.disp);
	}
	else /* [base] + disp */
	{
		if (is_disp8)
		{
			gen_modrm(out, 1, r, rm.base);
			gen_byte(out, (int8_t)rm.disp);
		}
		else
		{
			gen_modrm(out, 2, r, rm.base);
			gen_dword(out, rm.disp);
		}
	}
}

static __forceinline void gen_fs_prefix(uint8_t **out)
{
	gen_byte(out, 0x64);
}

static __forceinline void gen_mov_rm_imm32(uint8_t **out, struct modrm_rm_t rm, uint32_t imm)
{
	gen_byte(out, 0xC7);
	gen_modrm_sib(out, 0, rm);
	gen_dword(out, imm);
}

static __forceinline void gen_mov_r_rm_16(uint8_t **out, int r, struct modrm_rm_t rm)
{
	gen_byte(out, 0x66);
	gen_byte(out, 0x8B);
	gen_modrm_sib(out, r, rm);
}

static __forceinline void gen_mov_rm_r_16(uint8_t **out, struct modrm_rm_t rm, int r)
{
	gen_byte(out, 0x66);
	gen_byte(out, 0x89);
	gen_modrm_sib(out, r, rm);
}

static __forceinline void gen_mov_r_rm_32(uint8_t **out, int r, struct modrm_rm_t rm)
{
	gen_byte(out, 0x8B);
	gen_modrm_sib(out, r, rm);
}

static __forceinline void gen_mov_rm_r_32(uint8_t **out, struct modrm_rm_t rm, int r)
{
	gen_byte(out, 0x89);
	gen_modrm_sib(out, r, rm);
}

static __forceinline void gen_xchg_r_rm_32(uint8_t **out, int r, struct modrm_rm_t rm)
{
	gen_byte(out, 0x87);
	gen_modrm_sib(out, r, rm);
}

static __forceinline void gen_shr_rm_32(uint8_t **out, struct modrm_rm_t rm, uint8_t imm8)
{
	gen_byte(out, 0xC1);
	gen_modrm_sib(out, 5, rm);
	gen_byte(out, imm8);
}

static __forceinline void gen_lea(uint8_t **out, int r, struct modrm_rm_t rm)
{
	gen_byte(out, 0x8D);
	gen_modrm_sib(out, r, rm);
}

static __forceinline void gen_popfd(uint8_t **out)
{
	gen_byte(out, 0x9D);
}

static __forceinline void gen_pop_rm(uint8_t **out, struct modrm_rm_t rm)
{
	gen_byte(out, 0x8F);
	gen_modrm_sib(out, 0, rm);
}

static __forceinline void gen_pushfd(uint8_t **out)
{
	gen_byte(out, 0x9C);
}

static __forceinline void gen_push_rm(uint8_t **out, struct modrm_rm_t rm)
{
	gen_byte(out, 0xFF);
	gen_modrm_sib(out, 6, rm);
}

static __forceinline void gen_push_imm32(uint8_t **out, uint32_t imm)
{
	gen_byte(out, 0x68);
	gen_dword(out, imm);
}

static __forceinline void gen_call(uint8_t **out, size_t dest)
{
	int32_t rel = (int32_t)(dest - (((size_t)*out) + 5));
	gen_byte(out, 0xE8);
	gen_dword(out, rel);
}

static __forceinline void gen_jmp(uint8_t **out, size_t dest)
{
	int32_t rel = (int32_t)(dest - (((size_t)*out) + 5));
	gen_byte(out, 0xE9);
	gen_dword(out, rel);
}

static __forceinline void gen_jmp_rm(uint8_t **out, struct modrm_rm_t rm)
{
	gen_byte(out, 0xFF);
	gen_modrm_sib(out, 4, rm);
}

static __forceinline void gen_jcc(uint8_t **out, int cond, size_t dest)
{
	int32_t rel = (int32_t)(dest - (((size_t)*out) + 6));
	gen_byte(out, 0x0F);
	gen_byte(out, 0x80 + cond);
	gen_dword(out, rel);
}

struct dbt_block
{
	FORWARD_LIST_NODE(struct dbt_block);
	size_t pc;
	uint8_t *start;
};

#define DBT_OUT_ALIGN			16
#define DBT_BLOCK_HASH_BUCKETS	4096
#define DBT_BLOCK_MAXSIZE		1024 /* Maximum size of a translated basic block */
#define MAX_DBT_BLOCKS			(DBT_BLOCKS_SIZE / sizeof(struct dbt_block))
struct dbt_data
{
	FORWARD_LIST(struct dbt_block) block_hash[DBT_BLOCK_HASH_BUCKETS];
	struct dbt_block *blocks;
	int blocks_count;
	uint8_t *out, *end;
	/* Cached offsets for accessing thread local storage in fs:[.] */
	int tls_sp_offset; /* client/kernel stack pointer storage */
	int tls_indirect_dest_offset; /* indirect jump destination */
	int tls_scratch_offset; /* scratch variable */
	int tls_gs_offset; /* gs value */
	int tls_gs_addr_offset; /* gs base address */
	/* Address to trampolines */
	uint8_t *direct_trampoline;
	uint8_t *indirect_trampoline;
};

static struct dbt_data *const dbt = DBT_DATA_BASE;
static uint8_t *const dbt_cache = DBT_CACHE_BASE;

void dbt_init()
{
	log_info("Initializing dbt subsystem...\n");
	if (!VirtualAlloc(dbt, sizeof(struct dbt_data), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
		log_error("VirtualAlloc() for dbt_data failed.\n");
	if (!VirtualAlloc(DBT_BLOCKS_BASE, DBT_BLOCKS_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
		log_error("VirtualAlloc() for dbt_blocks failed.\n");
	if (!VirtualAlloc(dbt_cache, DBT_CACHE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
		log_error("VirtualAlloc() for dbt_cache failed.\n");
	dbt->blocks = DBT_BLOCKS_BASE;
	dbt->blocks_count = 0;
	dbt->out = dbt_cache;
	dbt->end = dbt_cache + DBT_CACHE_SIZE;
	dbt->tls_sp_offset = tls_kernel_entry_to_offset(TLS_ENTRY_SP);
	dbt->tls_indirect_dest_offset = tls_kernel_entry_to_offset(TLS_ENTRY_INDIRECT_DEST);
	dbt->tls_scratch_offset = tls_kernel_entry_to_offset(TLS_ENTRY_SCRATCH);
	dbt->tls_gs_offset = tls_kernel_entry_to_offset(TLS_ENTRY_GS);
	dbt->tls_gs_addr_offset = tls_kernel_entry_to_offset(TLS_ENTRY_GS_ADDR);
	log_info("dbt subsystem initialized.\n");
}

void dbt_shutdown()
{
	VirtualFree(dbt, 0, MEM_RELEASE);
	VirtualFree(dbt_cache, 0, MEM_RELEASE);
}

static void dbt_flush()
{
	for (int i = 0; i < DBT_BLOCK_HASH_BUCKETS; i++)
		forward_list_init(&dbt->block_hash[i]);
	dbt->blocks_count = 0;
	dbt->out = dbt_cache;
	dbt->end = dbt_cache + DBT_CACHE_SIZE;
	log_info("dbt code cache flushed.\n");
}

void dbt_reset()
{
	dbt_flush();
}

static int hash_block_pc(size_t pc)
{
	return (pc + (pc << 3) + (pc << 9)) % DBT_BLOCK_HASH_BUCKETS;
}

static struct dbt_block *alloc_block()
{
	if (dbt->blocks_count == MAX_DBT_BLOCKS || dbt->end - dbt->out < DBT_BLOCK_MAXSIZE)
		return NULL;
	return &dbt->blocks[dbt->blocks_count++];
}

static struct dbt_block *find_block(size_t pc)
{
	int bucket = hash_block_pc(pc);
	struct dbt_block *block, *prev;
	forward_list_iterate(&dbt->block_hash[bucket], prev, block)
		if (block->pc == pc)
			return block;
	return NULL;
}

static void dbt_gen_xchg_sp(uint8_t **out)
{
	/* xchg esp, fs:[sp_offset] */
	gen_fs_prefix(out);
	gen_xchg_r_rm_32(out, 4, modrm_rm_disp(dbt->tls_sp_offset));
}

size_t dbt_find_next(size_t pc);
size_t dbt_find_direct(size_t pc, size_t patch_addr);

void dbt_gen_indirect_trampoline()
{
	uint8_t *out = ALIGN_TO(dbt->out, DBT_OUT_ALIGN);
	dbt->indirect_trampoline = out;
	/* This function runs in user stack, the indirect destination address is in fs:[indirect_dest] */
	/* save context */
	dbt_gen_xchg_sp(&out);
	gen_push_rm(&out, modrm_rm_reg(EAX));
	gen_push_rm(&out, modrm_rm_reg(ECX));
	gen_push_rm(&out, modrm_rm_reg(EDX));
	gen_pushfd(&out);

	/* call dbt_find_next() */
	gen_fs_prefix(&out); /* pc */
	gen_push_rm(&out, modrm_rm_disp(dbt->tls_indirect_dest_offset));
	gen_call(&out, &dbt_find_next);
	/* mov fs:[scratch], eax */
	gen_fs_prefix(&out);
	gen_mov_rm_r_32(&out, modrm_rm_disp(dbt->tls_scratch_offset), EAX);

	/* restore context */
	gen_lea(&out, ESP, modrm_rm_mreg(ESP, 4));
	gen_popfd(&out);
	gen_pop_rm(&out, modrm_rm_reg(EDX));
	gen_pop_rm(&out, modrm_rm_reg(ECX));
	gen_pop_rm(&out, modrm_rm_reg(EAX));
	dbt_gen_xchg_sp(&out);

	/* jump to destination */
	/* jmp fs:[scratch] */
	gen_fs_prefix(&out);
	gen_jmp_rm(&out, modrm_rm_disp(dbt->tls_scratch_offset));

	dbt->out = out;
}

static void dbt_gen_direct_trampoline()
{
	uint8_t *out = ALIGN_TO(dbt->out, DBT_OUT_ALIGN);
	dbt->direct_trampoline = out;
	/* This function runs in kernel stack, it has two arguments: pc and patch_addr.
	 * Argument should be pushed in trampoline generated by dbt_get_direct_trampoline().
	 */
	/* save context */
	gen_push_rm(&out, modrm_rm_reg(EAX));
	gen_push_rm(&out, modrm_rm_reg(ECX));
	gen_push_rm(&out, modrm_rm_reg(EDX));
	gen_pushfd(&out);

	/* call dbt_find_direct() */
	gen_mov_r_rm_32(&out, ECX, modrm_rm_mreg(ESP, 20)); /* patch_addr */
	gen_mov_r_rm_32(&out, EDX, modrm_rm_mreg(ESP, 16)); /* pc */
	gen_push_rm(&out, modrm_rm_reg(ECX));
	gen_push_rm(&out, modrm_rm_reg(EDX));
	gen_call(&out, &dbt_find_direct);
	/* mov fs:[scratch], eax */
	gen_fs_prefix(&out);
	gen_mov_rm_r_32(&out, modrm_rm_disp(dbt->tls_scratch_offset), EAX);

	/* restore context */
	gen_lea(&out, ESP, modrm_rm_mreg(ESP, 8));
	gen_popfd(&out);
	gen_pop_rm(&out, modrm_rm_reg(EDX));
	gen_pop_rm(&out, modrm_rm_reg(ECX));
	gen_pop_rm(&out, modrm_rm_reg(EAX));
	gen_lea(&out, ESP, modrm_rm_mreg(ESP, 8));
	dbt_gen_xchg_sp(&out);

	/* jump to destination */
	/* jmp fs:[scratch] */
	gen_fs_prefix(&out);
	gen_jmp_rm(&out, modrm_rm_disp(dbt->tls_scratch_offset));

	dbt->out = out;
}

static size_t dbt_get_direct_trampoline_wrapper(size_t pc, size_t patch_addr)
{
	struct dbt_block *cached_block = find_block(pc);
	if (cached_block)
		return cached_block->start;

	/* Not found in cache, create a stub */
	dbt->end -= DBT_OUT_ALIGN * 2;
	uint8_t *out = dbt->end;
	dbt_gen_xchg_sp(&out);
	gen_push_imm32(&out, patch_addr);
	gen_push_imm32(&out, pc);
	gen_jmp(&out, dbt->direct_trampoline);
	return (size_t)dbt->end;
}

#define PREFIX_CS		0x2E
#define PREFIX_SS		0x36
#define PREFIX_DS		0x3E
#define PREFIX_ES		0x26
#define PREFIX_FS		0x64
#define PREFIX_GS		0x65
struct instruction_t
{
	uint8_t opcode;
	uint8_t opsize_prefix, rep_prefix;
	int segment_prefix;
	int lock_prefix;
	int escape_0x0f;
	uint8_t escape_byte2; /* 0x38 or 0x3A */
	int r;
	struct modrm_rm_t rm;
	int imm_bytes;
	struct instruction_desc *desc;
};

/* Find and return an unused register in an instruction, which can be used to hold temporary values */
static int find_unused_register(struct instruction_t *ins)
{
	/* Calculate used registers in this instruction */
	int used_regs = ins->desc->read_regs | ins->desc->write_regs;
	if (ins->rep_prefix)
		used_regs |= REG_CX;
	if (ins->r != -1)
		used_regs |= REG_MASK(ins->r);
	if (ins->rm.base != -1)
		used_regs |= REG_MASK(ins->rm.base);
	if (ins->rm.index != -1)
		used_regs |= REG_MASK(ins->rm.index);
#define TEST_REG(r) do { if ((used_regs & REG_MASK(r)) == 0) return r; } while (0)
	/* We really don't want to use esp or ebp as a temporary register */
	TEST_REG(EAX);
	TEST_REG(ECX);
	TEST_REG(EDX);
	TEST_REG(EBX);
	TEST_REG(ESI);
	TEST_REG(EDI);
#undef TEST_REG
	log_error("find_unused_register: No usable register found. There must be a bug in our implementation.\n");
	__debugbreak();
}

static void dbt_copy_instruction(uint8_t **out, uint8_t **code, struct instruction_t *ins)
{
	uint8_t *imm_start = *code;
	*code += ins->imm_bytes;
	if (ins->lock_prefix)
		gen_byte(out, 0xF0);
	if (ins->opsize_prefix)
		gen_byte(out, ins->opsize_prefix);
	if (ins->rep_prefix)
		gen_byte(out, ins->rep_prefix);
	if (ins->segment_prefix && ins->segment_prefix != PREFIX_GS)
		gen_byte(out, ins->segment_prefix);
	if (ins->escape_0x0f)
	{
		gen_byte(out, 0x0f);
		if (ins->escape_byte2)
			gen_byte(out, ins->escape_byte2);
	}
	gen_byte(out, ins->opcode);
	if (ins->desc->has_modrm)
		gen_modrm_sib(out, ins->r, ins->rm);
	gen_copy(out, imm_start, ins->imm_bytes);
}

static void dbt_gen_indirect_jmp(uint8_t **out, struct instruction_t ins)
{
	if (ins.segment_prefix == PREFIX_GS && modrm_rm_is_m(ins.rm))
	{
		/* jmp with effective gs segment override */
		int temp_reg = find_unused_register(&ins);
		/* mov fs:[scratch], temp_reg */
		gen_fs_prefix(out);
		gen_mov_rm_r_32(out, modrm_rm_disp(dbt->tls_scratch_offset), temp_reg);

		/* mov temp_reg, fs:[gs_addr] */
		gen_fs_prefix(out);
		gen_mov_r_rm_32(out, temp_reg, modrm_rm_disp(dbt->tls_gs_addr_offset));

		if (ins.rm.base != -1)
		{
			/* lea temp_reg, [temp_reg + rm.base] */
			gen_lea(out, temp_reg, modrm_rm_mscale(temp_reg, ins.rm.base, 0, 0));
		}
		/* Replace rm.base with temp_reg */
		ins.rm.base = temp_reg;

		/* mov temp_reg, [rm] */
		gen_mov_r_rm_32(out, temp_reg, ins.rm);

		/* mov fs:[indirect_dest], temp_reg */
		gen_fs_prefix(out);
		gen_mov_rm_r_32(out, modrm_rm_disp(dbt->tls_indirect_dest_offset), temp_reg);

		/* mov temp_reg, fs:[scratch] */
		gen_fs_prefix(out);
		gen_mov_r_rm_32(out, temp_reg, modrm_rm_disp(dbt->tls_scratch_offset));
	}
	else
	{
		if (ins.segment_prefix && ins.segment_prefix != PREFIX_GS)
		{
			log_error("segment prefix not supported in indirect jmp/call.\n");
			__debugbreak();
		}
		if (modrm_rm_is_m(ins.rm))
		{
			/* mov fs:[indirect_dest], ecx */
			gen_fs_prefix(out);
			gen_mov_rm_r_32(out, modrm_rm_disp(dbt->tls_indirect_dest_offset), ECX);

			/* mov ecx, [rm] */
			gen_mov_r_rm_32(out, ECX, ins.rm);

			/* xchg ecx, fs:[indirect_dest] */
			gen_fs_prefix(out);
			gen_xchg_r_rm_32(out, ECX, modrm_rm_disp(dbt->tls_indirect_dest_offset));
		}
		else
		{
			gen_fs_prefix(out);
			gen_mov_rm_r_32(out, modrm_rm_disp(dbt->tls_indirect_dest_offset), ins.rm.base);
		}
	}
	gen_jmp(out, dbt->indirect_trampoline);
}

/* CAUTION
 * We do not save x87/MMX/SSE/AVX states across a translation request
 * Thus we have to ensure these get unchanged during the translation
 * All Windows system calls cannot be used as they reset XMM registers to 0 upon return
 * To use these functions for debugging, wraps them in dbt_save_simd_state() and
 * dbt_restore_simd_state(). This including log_*() functions.
 */
static struct dbt_block *dbt_translate(size_t pc)
{
	extern void dbt_save_simd_state();
	extern void dbt_restore_simd_state();

	extern void dbt_cpuid_internal();

	struct dbt_block *block = alloc_block();
	if (!block) /* The cache is full */
	{
		/* TODO: We may need to check this flush-all-on-full semantic when we add signal handling */
		dbt_flush();
		block = alloc_block(); /* We won't fail again */
	}
	block->pc = pc;
	block->start = ((size_t)dbt->out + DBT_OUT_ALIGN - 1) & -(size_t)DBT_OUT_ALIGN;

	//dbt_save_simd_state();
	//log_debug("block id: %d, pc: %p, block start: %p\n", dbt->blocks_count, block->pc, block->start);
	//dbt_restore_simd_state();

	uint8_t *code = (uint8_t *)pc;
	uint8_t *out = block->start;
	for (;;)
	{
		struct instruction_t ins;
		ins.rep_prefix = 0;
		ins.opsize_prefix = 0;
		ins.segment_prefix = 0;
		ins.lock_prefix = 0;
		/* Handle prefixes. According to x86 doc, they can appear in any order */
		for (;;)
		{
			ins.opcode = parse_byte(&code);
			/* TODO: Can we migrate this switch to a table driven approach? */
			/* TODO: Detect invalid multiple segment prefixes */
			switch (ins.opcode)
			{
			case 0xF0: /* LOCK */
				ins.lock_prefix = 1;
				break;

			case 0xF2: /* REPNE/REPNZ */
				ins.rep_prefix = 0xF2;
				break;

			case 0xF3: /* REP/REPE/REPZ */
				ins.rep_prefix = 0xF3;
				break;

			case 0x2E: /* CS segment override*/
				ins.segment_prefix = 0x2E;
				break;

			case 0x36: /* SS segment override */
				ins.segment_prefix = 0x36;
				break;

			case 0x3E: /* DS segment override */
				ins.segment_prefix = 0x3E;
				break;

			case 0x26: /* ES segment override */
				ins.segment_prefix = 0x26;
				break;

			case 0x64: /* FS segment override */
				log_error("FS segment override not supported\n");
				__debugbreak();
				break;

			case 0x65: /* GS segment override */
				ins.segment_prefix = 0x65;
				break;

			case 0x66: /* Operand size prefix */
				ins.opsize_prefix = 0x66;
				break;

			case 0x67: /* Address size prefix */
				log_error("Address size prefix not supported\n");
				__debugbreak();
				break;

			default:
				goto done_prefix;
			}
		}

done_prefix:

		/* Extract instruction descriptor */
		ins.escape_0x0f = 0;
		ins.escape_byte2 = 0;

		if (ins.opcode == 0x0F)
		{
			ins.escape_0x0f = 1;
			ins.opcode = parse_byte(&code);
			if (ins.opcode == 0x38)
			{
				ins.escape_byte2 = 0x38;
				ins.opcode = parse_byte(&code);
				ins.desc = &three_byte_inst_0x38[ins.opcode];
			}
			else if (ins.opcode == 0x3A)
			{
				ins.escape_byte2 = 0x3A;
				ins.opcode = parse_byte(&code);
				ins.desc = &three_byte_inst_0x3A[ins.opcode];
			}
			else
				ins.desc = &two_byte_inst[ins.opcode];
		}
		else
			ins.desc = &one_byte_inst[ins.opcode];

	inst_mandatory_reentry:
		if (ins.desc->has_modrm)
			parse_modrm(&code, &ins.r, &ins.rm);
		
	inst_extension_reentry:
		ins.imm_bytes = ins.desc->imm_bytes;
		if (ins.imm_bytes == PREFIX_OPERAND_SIZE)
			ins.imm_bytes = ins.opsize_prefix? 2: 4;
		else if (ins.imm_bytes == PREFIX_ADDRESS_SIZE)
			ins.imm_bytes = 4;

		if (ins.desc->require_0x66 && !ins.opsize_prefix)
		{
			log_error("Unknown opcode.\n");
			__debugbreak();
		}

		/* Translate instruction */
		switch (ins.desc->type)
		{
		case INST_TYPE_UNKNOWN: log_error("Unknown opcode.\n"); __debugbreak(); break;
		case INST_TYPE_INVALID: log_error("Invalid opcode.\n"); __debugbreak(); break;
		case INST_TYPE_UNSUPPORTED: log_error("Unsupported opcode.\n"); __debugbreak(); break;

		case INST_TYPE_EXTENSION:
		{
			ins.desc = &ins.desc->extension_table[ins.r];
			goto inst_extension_reentry;
		}

		case INST_TYPE_MANDATORY:
		{
			if (!ins.escape_0x0f)
			{
				log_error("Invalid opcode.\n");
				__debugbreak();
			}
			if (ins.opsize_prefix)
				ins.desc = &ins.desc->extension_table[MANDATORY_0x66];
			else if (ins.rep_prefix == 0xF3)
				ins.desc = &ins.desc->extension_table[MANDATORY_0xF3];
			else if (ins.rep_prefix == 0xF2)
				ins.desc = &ins.desc->extension_table[MANDATORY_0xF2];
			else
				ins.desc = &ins.desc->extension_table[MANDATORY_NONE];
			goto inst_mandatory_reentry;
		}

		case INST_TYPE_X87:
		{
			/* A very simplistic way to handle x87 escape opcode */
			uint8_t modrm = *code; /* Peek potential ModR/M byte */
			if (GET_MODRM_MOD(modrm) == 3) /* A non-operand opcode */
			{
				/* TODO: Do we need to handle prefixes here? */
				code++;
				gen_byte(&out, ins.opcode);
				gen_byte(&out, modrm);
				break;
			}
			/* An escape opcode with ModR/M, properly parse ModR/M */
			ins.desc = &x87_desc;
			parse_modrm(&code, &ins.r, &ins.rm);
			/* Fall through */
		}

		case INST_TYPE_NORMAL:
		{
			if (ins.segment_prefix == PREFIX_GS && ins.desc->has_modrm && modrm_rm_is_m(ins.rm)
				&& !(!ins.escape_0x0f && ins.opcode == 0x8D)) /* LEA */
			{
				/* Instruction with effective gs segment override */
				int temp_reg = find_unused_register(&ins);
				/* mov fs:[scratch], temp_reg */
				gen_fs_prefix(&out);
				gen_mov_rm_r_32(&out, modrm_rm_disp(dbt->tls_scratch_offset), temp_reg);

				/* mov temp_reg, fs:[gs_addr] */
				gen_fs_prefix(&out);
				gen_mov_r_rm_32(&out, temp_reg, modrm_rm_disp(dbt->tls_gs_addr_offset));
				if (ins.rm.base != -1)
				{
					/* lea temp_reg, [temp_reg + rm.base] */
					gen_lea(&out, temp_reg, modrm_rm_mscale(temp_reg, ins.rm.base, 0, 0));
				}
				/* Replace rm.base with temp_reg */
				ins.rm.base = temp_reg;

				/* Copy instruction */
				dbt_copy_instruction(&out, &code, &ins);

				/* mov temp_reg, fs:[scratch] */
				gen_fs_prefix(&out);
				gen_mov_r_rm_32(&out, temp_reg, modrm_rm_disp(dbt->tls_scratch_offset));
			}
			else /* If nothing special, directly copy instruction */
				dbt_copy_instruction(&out, &code, &ins);

			if (ins.desc->is_privileged)
			{
				/* We have to support translate privileged opcodes because e.g. glibc uses HLT as
				 * a backup program terminator. */
				/* The instructions following it won't be executed and could be crap so we stop here */
				goto end_block;
			}
			break;
		}

		case INST_MOV_MOFFSET:
		{
			if (ins.segment_prefix == PREFIX_GS)
			{
				/* mov moffs with effective gs segment override */
				int temp_reg = find_unused_register(&ins);
				/* mov fs:[scratch], temp_reg */
				gen_fs_prefix(&out);
				gen_mov_rm_r_32(&out, modrm_rm_disp(dbt->tls_scratch_offset), temp_reg);

				/* mov temp_reg, fs:[gs_addr] */
				gen_fs_prefix(&out);
				gen_mov_r_rm_32(&out, temp_reg, modrm_rm_disp(dbt->tls_gs_addr_offset));

				/* Generate patched instruction */
				if (ins.lock_prefix)
					gen_byte(&out, 0xF0);
				if (ins.opsize_prefix)
					gen_byte(&out, ins.opsize_prefix);
				if (ins.opcode == 0xA0) /* mov al, fs:moffs8 */
					gen_byte(&out, 0x8A);
				else if (ins.opcode == 0xA1) /* mov ?ax, moffs? */
					gen_byte(&out, 0x8B);
				else if (ins.opcode == 0xA2) /* mov moffs8, al */
					gen_byte(&out, 0x88);
				else /* if (ins.opcode ==0xA3) mov moffs?, ?ax */
					gen_byte(&out, 0x89);
				uint32_t disp = parse_moffset(&code, ins.imm_bytes);
				gen_modrm_sib(&out, 0, modrm_rm_mreg(temp_reg, disp));

				/* mov temp_reg, fs:[scratch] */
				gen_fs_prefix(&out);
				gen_mov_r_rm_32(&out, temp_reg, modrm_rm_disp(dbt->tls_scratch_offset));
				break;
			}

			/* Directly copy instruction */
			dbt_copy_instruction(&out, &code, &ins);
			break;
		}

		case INST_CALL_DIRECT:
		{
			int32_t rel = parse_rel(&code, ins.imm_bytes);
			size_t dest = (size_t)code + rel;
			gen_push_imm32(&out, (size_t)code);
			size_t patch_addr = (size_t)out + 1;
			gen_jmp(&out, dbt_get_direct_trampoline_wrapper(dest, patch_addr));
			goto end_block;
		}

		case INST_CALL_INDIRECT:
		{
			/* TODO: Bad codegen for `call esp', although should never be used in practice */
			gen_push_imm32(&out, (size_t)code);
			if (ins.rm.base == ESP)
				if (modrm_rm_is_r(ins.rm))
				{
					log_error("call esp not supported.\n");
					__debugbreak();
				}
				else
					ins.rm.disp += 4;
			dbt_gen_indirect_jmp(&out, ins);
			goto end_block;
		}

		case INST_RET:
		{
			gen_fs_prefix(&out);
			gen_pop_rm(&out, modrm_rm_disp(dbt->tls_indirect_dest_offset));
			gen_jmp(&out, dbt->indirect_trampoline);
			goto end_block;
		}

		case INST_RETN:
		{
			int count = parse_word(&code);
			gen_fs_prefix(&out);
			gen_pop_rm(&out, modrm_rm_disp(dbt->tls_indirect_dest_offset));
			/* lea esp, [esp + count] */
			gen_lea(&out, ESP, modrm_rm_mreg(ESP, count));
			gen_jmp(&out, dbt->indirect_trampoline);
			goto end_block;
		}

		case INST_JMP_DIRECT:
		{
			int32_t rel = parse_rel(&code, ins.imm_bytes);
			size_t dest = (size_t)code + rel;
			size_t patch_addr = (size_t)out + 1;
			gen_jmp(&out, dbt_get_direct_trampoline_wrapper(dest, patch_addr));
			goto end_block;
		}

		case INST_JMP_INDIRECT:
		{
			dbt_gen_indirect_jmp(&out, ins);
			goto end_block;
		}

		case INST_JCC + 0:
		case INST_JCC + 1:
		case INST_JCC + 2:
		case INST_JCC + 3:
		case INST_JCC + 4:
		case INST_JCC + 5:
		case INST_JCC + 6:
		case INST_JCC + 7:
		case INST_JCC + 8:
		case INST_JCC + 9:
		case INST_JCC + 10:
		case INST_JCC + 11:
		case INST_JCC + 12:
		case INST_JCC + 13:
		case INST_JCC + 14:
		case INST_JCC + 15:
		{
			int cond = GET_JCC_COND(ins.desc->type);
			int32_t rel = parse_rel(&code, ins.imm_bytes);
			size_t dest0 = (size_t)code + rel; /* Branch taken */
			size_t dest1 = (size_t)code; /* Branch not taken */
			size_t patch_addr0 = (size_t)out + 2;
			gen_jcc(&out, cond, dbt_get_direct_trampoline_wrapper(dest0, patch_addr0));
			size_t patch_addr1 = (size_t)out + 1;
			gen_jmp(&out, dbt_get_direct_trampoline_wrapper(dest1, patch_addr1));
			goto end_block;
		}

		case INST_JCC_REL8:
		{
			int32_t rel = parse_rel(&code, ins.imm_bytes);
			size_t dest0 = (size_t)code + rel; /* Branch taken */
			size_t dest1 = (size_t)code; /* Branch not taken */
			/* LOOP, LOOPE, LOOPNE, JCXZ, JECXZ, JRCXZ */
			/* op $+2 */
			gen_byte(&out, ins.opcode);
			gen_byte(&out, 2); /* sizeof(jmp rel8) */
			/* jmp $+5 */
			gen_byte(&out, 0xEB);
			gen_byte(&out, 5); /* sizeof(jmp rel32) */
			size_t patch_addr0 = (size_t)out + 1;
			gen_jmp(&out, dbt_get_direct_trampoline_wrapper(dest0, patch_addr0));
			size_t patch_addr1 = (size_t)out + 1;
			gen_jmp(&out, dbt_get_direct_trampoline_wrapper(dest1, patch_addr1));
			goto end_block;
		}

		case INST_INT:
		{
			extern void syscall_handler();
			uint8_t id = parse_byte(&code);
			if (id != 0x80)
			{
				log_error("INT 0x%x not supported.\n", id);
				__debugbreak();
			}
			dbt_gen_xchg_sp(&out);

			/* push eip */
			gen_push_imm32(&out, (size_t)code);
			/* push fs:[sp] */
			gen_fs_prefix(&out);
			gen_push_rm(&out, modrm_rm_disp(dbt->tls_sp_offset));
			/* call syscall handler */
			gen_call(&out, &syscall_handler);
			/* lea esp, [esp+8] */
			gen_lea(&out, ESP, modrm_rm_mreg(ESP, 8));

			dbt_gen_xchg_sp(&out);
			break;
		}

		case INST_MOV_FROM_SEG:
		{
			if (ins.r != 5) /* GS */
			{
				log_error("mov from segment selectors other than GS not supported.\n");
				__debugbreak();
			}
			int temp_reg = find_unused_register(&ins, 0);
			/* mov fs:[scratch], temp_reg */
			gen_fs_prefix(&out);
			gen_mov_rm_r_32(&out, modrm_rm_disp(dbt->tls_scratch_offset), temp_reg);

			/* mov temp_reg, fs:[gs] */
			gen_fs_prefix(&out);
			gen_mov_r_rm_32(&out, temp_reg, modrm_rm_disp(dbt->tls_gs_offset));

			/* mov |rm|, temp_reg */
			gen_mov_rm_r_32(&out, ins.rm, temp_reg);

			/* mov temp_reg, fs:[scratch] */
			gen_fs_prefix(&out);
			gen_mov_r_rm_32(&out, temp_reg, modrm_rm_disp(dbt->tls_scratch_offset));
			break;
		}

		case INST_MOV_TO_SEG:
		{
			if (ins.r != 5) /* GS */
			{
				log_error("mov to segment selector other than GS not supported.\n");
				__debugbreak();
			}
			int temp_reg = find_unused_register(&ins);
			/* mov fs:[scratch], temp_reg */
			gen_fs_prefix(&out);
			gen_mov_rm_r_32(&out, modrm_rm_disp(dbt->tls_scratch_offset), temp_reg);

			/* mov temp_reg, |rm| */
			gen_mov_r_rm_32(&out, temp_reg, ins.rm);

			/* This is very ugly and inefficient, but anyway this instruction should not be used very often */
			gen_pushfd(&out);

			/* mov fs:[gs], temp_reg */
			gen_fs_prefix(&out);
			gen_mov_rm_r_32(&out, modrm_rm_disp(dbt->tls_gs_offset), temp_reg);

			/* call tls_slot_to_offset() to get the offset */
			gen_shr_rm_32(&out, modrm_rm_reg(temp_reg), 3);
			gen_push_rm(&out, modrm_rm_reg(0));
			gen_push_rm(&out, modrm_rm_reg(1));
			gen_push_rm(&out, modrm_rm_reg(2));
			gen_push_rm(&out, modrm_rm_reg(temp_reg));
			gen_call(&out, &tls_user_entry_to_offset);
			
			/* mov temp_reg, fs:eax */
			gen_fs_prefix(&out);
			gen_mov_r_rm_32(&out, temp_reg, modrm_rm_mreg(0, 0));
			/* mov fs:[gs_addr], temp_reg */
			gen_fs_prefix(&out);
			gen_mov_rm_r_32(&out, modrm_rm_disp(dbt->tls_gs_addr_offset), temp_reg);

			/* Clean up */
			gen_lea(&out, 4, modrm_rm_mreg(4, 4));
			gen_pop_rm(&out, modrm_rm_reg(2));
			gen_pop_rm(&out, modrm_rm_reg(1));
			gen_pop_rm(&out, modrm_rm_reg(0));

			gen_popfd(&out);

			/* mov temp_reg, fs:[scratch] */
			gen_fs_prefix(&out);
			gen_mov_r_rm_32(&out, temp_reg, modrm_rm_disp(dbt->tls_scratch_offset));
			break;
		}
		
		case INST_CPUID:
		{
			gen_call(&out, &dbt_cpuid_internal);
			break;
		}
		}
		continue;

	end_block:
		break;
	}
	dbt->out = out;
	return block;
}

size_t dbt_find_next(size_t pc)
{
	int bucket = hash_block_pc(pc);
	struct dbt_block *block, *prev;
	forward_list_iterate(&dbt->block_hash[bucket], prev, block)
		if (block->pc == pc)
			return block->start;

	/* Block not found, translate it now */
	block = dbt_translate(pc);
	forward_list_add(&dbt->block_hash[bucket], block);
	return block->start;
}

size_t dbt_find_direct(size_t pc, size_t patch_addr)
{
	/* Translate or generate the block */
	size_t block_start = dbt_find_next(pc);
	/* Patch the jmp/call address so we don't need to repeat work again */
	*(size_t*)patch_addr = (intptr_t)(block_start - (patch_addr + 4)); /* Relative address */
	return block_start;
}

void __declspec(noreturn) dbt_restore_fork_context(struct syscall_context *ctx)
{
	dbt_gen_direct_trampoline();
	dbt_gen_indirect_trampoline();
	ctx->eip = dbt_find_next(ctx->eip);
	extern __declspec(noreturn) void dbt_restore_fork_context_internal(struct syscall_context *ctx, size_t tls_sp_offset);
	dbt_restore_fork_context_internal(ctx, dbt->tls_sp_offset);
}

void __declspec(noreturn) dbt_run(size_t pc, size_t sp)
{
	dbt_gen_direct_trampoline();
	dbt_gen_indirect_trampoline();
	size_t entrypoint = dbt_find_next(pc);
	extern __declspec(noreturn) void dbt_run_internal(size_t pc, size_t sp, size_t tls_sp_offset);
	log_info("dbt: Calling into application code generated at %p, (original: pc: %p, sp: %p)\n", entrypoint, pc, sp);
	dbt_run_internal(entrypoint, sp, dbt->tls_sp_offset);
}
