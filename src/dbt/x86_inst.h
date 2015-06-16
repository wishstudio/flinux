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

/* Instruction description tables */
#include <stdint.h>

/* Generic instruction types */
#define INST_TYPE_UNKNOWN		0 /* Unknown/not implemented */
#define INST_TYPE_INVALID		1 /* Invalid instruction */
#define INST_TYPE_UNSUPPORTED	2 /* Unsupported instruction */
#define INST_TYPE_EXTENSION		3 /* Opcode extension, use ModR/M R field to distinguish */
#define INST_TYPE_MANDATORY		4 /* SIMD opcode, distinguished with a mandatory prefix (none, 0x66, 0xF3, 0xF2) */
#define INST_TYPE_X87			5 /* An x87 escape code */
#define INST_TYPE_NORMAL		6 /* Normal instruction which does not need special handling */

/* Extension table indices for mandatory prefixes */
#define MANDATORY_NONE			0
#define MANDATORY_0x66			1
#define MANDATORY_0xF3			2
#define MANDATORY_0xF2			3

/* Special instruction types */
#define INST_TYPE_SPECIAL		7
#define INST_MOV_MOFFSET		(INST_TYPE_SPECIAL + 0)
#define INST_CALL_DIRECT		(INST_TYPE_SPECIAL + 1)
#define INST_CALL_INDIRECT		(INST_TYPE_SPECIAL + 2)
#define INST_RET				(INST_TYPE_SPECIAL + 3)
#define INST_RETN				(INST_TYPE_SPECIAL + 4)
#define INST_JMP_DIRECT			(INST_TYPE_SPECIAL + 5)
#define INST_JMP_INDIRECT		(INST_TYPE_SPECIAL + 6)
/* Jcc occupies 16 instruction types for each condition code */
#define INST_JCC				(INST_TYPE_SPECIAL + 7)
#define GET_JCC_COND(type)		((type) - INST_JCC)
#define INST_JCC_REL8			(INST_TYPE_SPECIAL + 23)
#define INST_INT				(INST_TYPE_SPECIAL + 24)
#define INST_MOV_FROM_SEG		(INST_TYPE_SPECIAL + 25)
#define INST_MOV_TO_SEG			(INST_TYPE_SPECIAL + 26)
#define INST_CPUID				(INST_TYPE_SPECIAL + 27)

#define REG_AX			0x00000001 /* AL, AH, AX, EAX, RAX register */
#define REG_CX			0x00000002 /* CL, CH, CX, ECX, RCX register */
#define REG_DX			0x00000004 /* DL, DH, DX, EDX, RDX register */
#define REG_BX			0x00000008 /* BL, BH, BX, EBX, RBX register */
#define REG_SP			0x00000010 /* SPL, SP, ESP, RSP register */
#define REG_BP			0x00000020 /* BPL, BP, EBP, RBP register */
#define REG_SI			0x00000040 /* SIL, SI, ESI, RSI register */
#define REG_DI			0x00000080 /* DIL, DI, EDI, RDI register */
#define REG_R8			0x00000100 /* R8L, R8W, R8D, R8 register */
#define REG_R9			0x00000200 /* R9L, R9W, R9D, R9 register */
#define REG_R10			0x00000400 /* R10L, R10W, R10D, R10 register */
#define REG_R11			0x00000800 /* R11L, R11W, R11D, R11 register */
#define REG_R12			0x00001000 /* R12L, R12W, R12D, R12 register */
#define REG_R13			0x00002000 /* R13L, R13W, R13D, R13 register */
#define REG_R14			0x00004000 /* R14L, R14W, R14D, R14 register */
#define REG_R15			0x00008000 /* R15L, R15W, R15D, R15 register */
#define REG_MASK(r)		(1 << (r)) /* Generate a mask from a numeric register id */
#define MODRM_R			0x01000000 /* R field of ModR/M */
#define MODRM_RM_R		0x02000000 /* Register type of ModR/M R/M field */
#define MODRM_RM_M		0x04000000 /* Memory type of ModR/M R/M field */
#define MODRM_RM		MODRM_RM_R | MODRM_RM_M /* R/M field of ModR/M */

#define PREFIX_OPERAND_SIZE		9 /* Indicate imm_bytes is 2 or 4 bytes depends on operand size prefix */
#ifdef _WIN64
#define PREFIX_OPERAND_SIZE_64	10 /* Indicate imm_bytes is 2 or 4 or 8 bytes depends on operand size prefix */
#else
#define PREFIX_OPERAND_SIZE_64	PREFIX_OPERAND_SIZE /* Not supported on x86 */
#endif
#define PREFIX_ADDRESS_SIZE		11 /* Indicate imm_bytes is 2 or 4 or 8 bytes depends on address size prefix */
#define PREFIX_ADDRESS_SIZE_64	PREFIX_ADDRESS_SIZE /* Indicate imm_bytes is 2 or 4 or 8 bytes depends on address size prefix */
struct instruction_desc
{
	int type:8; /* Instruction type */
	int has_modrm:1; /* Whether the instruction has ModR/M opcode */
	int require_0x66:1; /* Whether the instruction requires a mandatory 0x66 prefix */
	int is_privileged:1; /* Whether the instruction is a privileged instruction */
	uint8_t imm_bytes:4; /* Bytes of immediate, 1, 2, 4, 8, or PREFIX_xxx_SIZE */
	union
	{
		struct
		{
			int read_regs; /* The bitmask of registers which are read from */
			int write_regs; /* The bitmask of registers which are written to */
		};
		const struct instruction_desc *extension_table; /* Secondary lookup table for INST_TYPE_EXTENSION */
	};
};
#define UNKNOWN()		{ .type = INST_TYPE_UNKNOWN },
#define INVALID()		{ .type = INST_TYPE_INVALID },
#define UNSUPPORTED()	{ .type = INST_TYPE_UNSUPPORTED },
#define MANDATORY(x)	{ .type = INST_TYPE_MANDATORY, .extension_table = mandatory_##x },
#define X87()			{ .type = INST_TYPE_X87 },
#define EXTENSION(x)	{ .type = INST_TYPE_EXTENSION, .has_modrm = 1, .extension_table = extension_##x },

#define INST(...)		{ .type = INST_TYPE_NORMAL, __VA_ARGS__ },
#define SPECIAL(s, ...)	{ .type = s, __VA_ARGS__ },
#define MODRM()			.has_modrm = 1
#define REQUIRE_0x66()	.require_0x66 = 1
#define PRIVILEGED()	.is_privileged = 1
#define IMM(i)			.imm_bytes = (i)
#define READ(x)			.read_regs = (x)
#define WRITE(x)		.write_regs = (x)

struct instruction_desc x87_desc = { .type = INST_TYPE_NORMAL, MODRM() };

static const struct instruction_desc extension_C6[8] =
{ 
	/* 0: MOV r/m8, imm8 */ INST(MODRM(), IMM(1), WRITE(MODRM_RM))
	/* 1: ??? */ UNKNOWN()
	/* 2: ??? */ UNKNOWN()
	/* 3: ??? */ UNKNOWN()
	/* 4: ??? */ UNKNOWN()
	/* 5: ??? */ UNKNOWN()
	/* 6: ??? */ UNKNOWN()
	/* 7: ??? */ UNKNOWN()
};

static const struct instruction_desc extension_C7[8] =
{
	/* 0: MOV r/m?, imm? */ INST(MODRM(), IMM(PREFIX_OPERAND_SIZE), WRITE(MODRM_RM))
	/* 1: ??? */ UNKNOWN()
	/* 2: ??? */ UNKNOWN()
	/* 3: ??? */ UNKNOWN()
	/* 4: ??? */ UNKNOWN()
	/* 5: ??? */ UNKNOWN()
	/* 6: ??? */ UNKNOWN()
	/* 7: ??? */ UNKNOWN()
};

/* [GRP3]: 0/TEST, 2/NOT, 3/NEG, 4/MUL, 5/IMUL, 6/DIV, 7/IDIV */
static const struct instruction_desc extension_F6[8] =
{
	/* 0: TEST r/m8, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM))
	/* 1: ??? */ UNKNOWN()
	/* 2: NOT r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 3: NEG r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 4: MUL r/m8 */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX))
	/* 5: IMUL r/m8 */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX))
	/* 6: DIV r/m8 */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX))
	/* 7: IDIV r/m8 */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX))
};

static const struct instruction_desc extension_F7[8] =
{
	/* 0: TEST r/m?, imm? */ INST(MODRM(), IMM(PREFIX_OPERAND_SIZE), READ(MODRM_RM))
	/* 1: ??? */ UNKNOWN()
	/* 2: NOT r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 3: NEG r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 4: MUL r/m? */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX | REG_DX))
	/* 5: IMUL r/m? */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX | REG_DX))
	/* 6: DIV r/m? */ INST(MODRM(), READ(REG_AX | REG_DX | MODRM_RM), WRITE(REG_AX | REG_DX))
	/* 7: IDIV r/m? */ INST(MODRM(), READ(REG_AX | REG_DX | MODRM_RM), WRITE(REG_AX | REG_DX))
};

static const struct instruction_desc extension_FF[8] = 
{
	/* 0: INC r/m16; INC r/m32 */ INST(MODRM(), READ(MODRM_RM_R), WRITE(MODRM_RM_R))
	/* 1: DEC r/m16; DEC r/m32 */ INST(MODRM(), READ(MODRM_RM_R), WRITE(MODRM_RM_R))
	/* 2: CALL r/m16; CALL r/m32 */ SPECIAL(INST_CALL_INDIRECT, MODRM())
	/* 3: CALL FAR m16:16; CALL FAR m16:32 */ UNSUPPORTED()
	/* 4: JMP r/m32; JMP r/m64 */ SPECIAL(INST_JMP_INDIRECT, MODRM())
	/* 5: JMP FAR m16:16; JMP FAR m16:32 */ UNSUPPORTED()
	/* 6: PUSH r/m16; PUSH r/m32 */ INST(MODRM(), READ(MODRM_RM_R))
	/* 7: ??? */ UNKNOWN()
};

static const struct instruction_desc one_byte_inst[256] =
{
	/* 0x00: ADD r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x01: ADD r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x02: ADD r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x03: ADD r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x04: ADD AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x05: ADD ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x06: ??? */ UNKNOWN()
#ifdef _WIN64
	/* 0x07: INVALID */ INVALID()
#else
	/* 0x07: POP ES */ UNSUPPORTED()
#endif
	/* 0x08: OR r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x09: OR r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x0A: OR r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0B: OR r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0C: OR AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x0D: OR ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x0E: ??? */ UNKNOWN()
	/* 0x0F: ??? */ UNKNOWN()
	/* 0x10: ADC r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x11: ADC r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x12: ADC r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x13: ADC r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x14: ADC AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x15: ADC ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x16: ??? */ UNKNOWN()
#ifdef _WIN64
	/* 0x17: INVALID */ INVALID()
#else
	/* 0x17: POP SS */ UNSUPPORTED()
#endif
	/* 0x18: SBB r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x19: SBB r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x1A: SBB r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x1B: SBB r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x1C: SBB AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x1D: SBB ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x1E: ??? */ UNKNOWN()
#ifdef _WIN64
	/* 0x1F: INVALID */ INVALID()
#else
	/* 0x1F: POP DS */ UNSUPPORTED()
#endif
	/* 0x20: AND r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x21: AND r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x22: AND r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x23: AND r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x24: AND AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x25: AND ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x26: ES segment prefix */ INVALID()
#ifdef _WIN64
	/* 0x27: INVALID */ INVALID()
#else
	/* 0x27: DAA */ INST(READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x28: SUB r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x29: SUB r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x2A: SUB r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x2B: SUB r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x2C: SUB AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x2D: SUB ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x2E: CS segment prefix */ INVALID()
#ifdef _WIN64
	/* 0x2F: INVALID */ INVALID()
#else
	/* 0x2F: DAS */ INST(READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x30: XOR r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x31: XOR r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x32: XOR r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x33: XOR r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x34: XOR AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x35: XOR ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x36: SS segment prefix */ INVALID()
#ifdef _WIN64
	/* 0x37: Invalid */ INVALID()
#else
	/* 0x37: AAA */ INST(READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x38: CMP r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x39: CMP r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x3A: CMP r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3B: CMP r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3C: CMP AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x3D: CMP ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x3E: DS segment prefix */ INVALID()
#ifdef _WIN64
	/* 0x3F; INVALID */ INVALID()
	/* 0x40: REX prefix */ INVALID()
	/* 0x41: REX prefix */ INVALID()
	/* 0x42: REX prefix */ INVALID()
	/* 0x43: REX prefix */ INVALID()
	/* 0x44: REX prefix */ INVALID()
	/* 0x45: REX prefix */ INVALID()
	/* 0x46: REX prefix */ INVALID()
	/* 0x47: REX prefix */ INVALID()
	/* 0x48: REX prefix */ INVALID()
	/* 0x49: REX prefix */ INVALID()
	/* 0x4A: REX prefix */ INVALID()
	/* 0x4B: REX prefix */ INVALID()
	/* 0x4C: REX prefix */ INVALID()
	/* 0x4D: REX prefix */ INVALID()
	/* 0x4E: REX prefix */ INVALID()
	/* 0x4F: REX prefix */ INVALID()
#else
	/* 0x3F: AAS */ INST(READ(REG_AX), WRITE(REG_AX))
	/* 0x40: INC ?AX */ INST(READ(REG_AX), WRITE(REG_AX))
	/* 0x41: INC ?CX */ INST(READ(REG_CX), WRITE(REG_CX))
	/* 0x42: INC ?DX */ INST(READ(REG_DX), WRITE(REG_DX))
	/* 0x43: INC ?BX */ INST(READ(REG_BX), WRITE(REG_BX))
	/* 0x44: INC ?SP */ INST(READ(REG_SP), WRITE(REG_SP))
	/* 0x45: INC ?BP */ INST(READ(REG_BP), WRITE(REG_BP))
	/* 0x46: INC ?SI */ INST(READ(REG_SI), WRITE(REG_SI))
	/* 0x47: INC ?DI */ INST(READ(REG_DI), WRITE(REG_DI))
	/* 0x48: DEC ?AX */ INST(READ(REG_AX), WRITE(REG_AX))
	/* 0x49: DEC ?CX */ INST(READ(REG_CX), WRITE(REG_CX))
	/* 0x4A: DEC ?DX */ INST(READ(REG_DX), WRITE(REG_DX))
	/* 0x4B: DEC ?BX */ INST(READ(REG_BX), WRITE(REG_BX))
	/* 0x4C: DEC ?SP */ INST(READ(REG_SP), WRITE(REG_SP))
	/* 0x4D: DEC ?BP */ INST(READ(REG_BP), WRITE(REG_BP))
	/* 0x4E: DEC ?SI */ INST(READ(REG_SI), WRITE(REG_SI))
	/* 0x4F: DEC ?DI */ INST(READ(REG_DI), WRITE(REG_DI))
#endif
	/* NOTE: The read and write information of these are not very accurate */
	/* 0x50: PUSH ?AX/R8? */ INST(READ(REG_SP | REG_AX | REG_R8), WRITE(REG_SP))
	/* 0x51: PUSH ?CX/R9? */ INST(READ(REG_SP | REG_CX | REG_R9), WRITE(REG_SP))
	/* 0x52: PUSH ?DX/R10? */ INST(READ(REG_SP | REG_DX | REG_R10), WRITE(REG_SP))
	/* 0x53: PUSH ?BX/R11? */ INST(READ(REG_SP | REG_BX | REG_R11), WRITE(REG_SP))
	/* 0x54: PUSH ?SP/R12? */ INST(READ(REG_SP | REG_SP | REG_R12), WRITE(REG_SP))
	/* 0x55: PUSH ?BP/R13? */ INST(READ(REG_SP | REG_BP | REG_R13), WRITE(REG_SP))
	/* 0x56: PUSH ?SI/R14? */ INST(READ(REG_SP | REG_SI | REG_R14), WRITE(REG_SP))
	/* 0x57: PUSH ?DI/R15? */ INST(READ(REG_SP | REG_DI | REG_R15), WRITE(REG_SP))
	/* 0x58: POP ?AX/R8? */ INST(READ(REG_SP), WRITE(REG_SP | REG_AX | REG_R8))
	/* 0x59: POP ?CX/R9? */ INST(READ(REG_SP), WRITE(REG_SP | REG_CX | REG_R9))
	/* 0x5A: POP ?DX/R10? */ INST(READ(REG_SP), WRITE(REG_SP | REG_DX | REG_R10))
	/* 0x5B: POP ?BX/R11? */ INST(READ(REG_SP), WRITE(REG_SP | REG_BX | REG_R11))
	/* 0x5C: POP ?SP/R12? */ INST(READ(REG_SP), WRITE(REG_SP | REG_SP | REG_R12))
	/* 0x5D: POP ?BP/R13? */ INST(READ(REG_SP), WRITE(REG_SP | REG_BP | REG_R13))
	/* 0x5E: POP ?SI/R14? */ INST(READ(REG_SP), WRITE(REG_SP | REG_SI | REG_R14))
	/* 0x5F: POP ?DI/R15? */ INST(READ(REG_SP), WRITE(REG_SP | REG_DI | REG_R15))
#ifdef _WIN64
	/* 0x60: INVALID */ INVALID()
	/* 0x61: INVALID */ INVALID()
	/* 0x62: EVEX prefix */ INVALID()
	/* 0x63: INVALID */ INVALID()
#else
	/* 0x60: PUSHA_PUSHAD */ INST(READ(REG_AX | REG_CX | REG_DX | REG_BX | REG_SP | REG_BP | REG_SI | REG_DI), WRITE(REG_SP))
	/* 0x61: POPA/POPAD */ INST(READ(REG_SP), WRITE(REG_AX | REG_CX | REG_DX | REG_BX | REG_SP | REG_BP | REG_SI | REG_DI))
	/* 0x62: BOUND r?, m?&? */ INST(MODRM(), READ(MODRM_R | MODRM_RM_M))
	/* 0x63: ARPL r/m16, r16 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
#endif
	/* 0x64: FS segment prefix */ INVALID()
	/* 0x65: GS segment prefix */ INVALID()
	/* 0x66: ??? */ UNKNOWN()
	/* 0x67: ??? */ UNKNOWN()
	/* 0x68: PUSH imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_SP), WRITE(REG_SP))
	/* 0x69: IMUL r?, r/m?, imm? */ INST(MODRM(), IMM(PREFIX_OPERAND_SIZE), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6A: PUSH imm8 */ INST(IMM(1), READ(REG_SP), WRITE(REG_SP))
	/* 0x6B: IMUL r?, r/m?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6C: INSB */ UNSUPPORTED()
	/* 0x6D: INSW/INSD */ UNSUPPORTED()
	/* 0x6E: OUTSB */ UNSUPPORTED()
	/* 0x6F: OUTSW/OUTSD */ UNSUPPORTED()
	/* 0x70: JO rel8 */ SPECIAL(INST_JCC + 0, IMM(1))
	/* 0x71: JNO rel8 */ SPECIAL(INST_JCC + 1, IMM(1))
	/* 0x72: JB/JC/JNAE rel8 */ SPECIAL(INST_JCC + 2, IMM(1))
	/* 0x73: JAE/JNB/JNC rel8 */ SPECIAL(INST_JCC + 3, IMM(1))
	/* 0x74: JE/JZ rel8 */ SPECIAL(INST_JCC + 4, IMM(1))
	/* 0x75: JNE/JNZ rel8 */ SPECIAL(INST_JCC + 5, IMM(1))
	/* 0x76: JBE/JNA rel8 */ SPECIAL(INST_JCC + 6, IMM(1))
	/* 0x77: JA/JNBE rel8 */ SPECIAL(INST_JCC + 7, IMM(1))
	/* 0x78: JS rel8 */ SPECIAL(INST_JCC + 8, IMM(1))
	/* 0x79: JNS rel8 */ SPECIAL(INST_JCC + 9, IMM(1))
	/* 0x7A: JP/JPE rel8 */ SPECIAL(INST_JCC + 10, IMM(1))
	/* 0x7B: JNP/JPO rel8 */ SPECIAL(INST_JCC + 11, IMM(1))
	/* 0x7C: JL/JNGE rel8 */ SPECIAL(INST_JCC + 12, IMM(1))
	/* 0x7D: JGE/JNL rel8 */ SPECIAL(INST_JCC + 13, IMM(1))
	/* 0x7E: JLE/JNG rel8 */ SPECIAL(INST_JCC + 14, IMM(1))
	/* 0x7F: JG/JNLE rel8 */ SPECIAL(INST_JCC + 15, IMM(1))
	/* [GRP1]: 0/ADD, 1/OR, 2/ADC, 3/SBB, 4/AND, 5/SUB, 6/XOR, 7/CMP */
	/* 0x80: [GRP1] r/m8, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x81: [GRP1] r/m?, imm? */ INST(MODRM(), IMM(PREFIX_OPERAND_SIZE), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x82: ??? */ UNKNOWN()
	/* 0x83: [GRP1] r/m?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x84: TEST r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0x85: TEST r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0x86: XCHG r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0x87: XCHG r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0x88: MOV r/m8, r8 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* 0x89: MOV r/m?, r? */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* 0x8A: MOV r8, r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x8B: MOV r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x8C: MOV r/m16, Sreg; MOV r/m64, Sreg */ SPECIAL(INST_MOV_FROM_SEG, MODRM(), WRITE(MODRM_RM))
	/* 0x8D: LEA r?, m */ INST(MODRM(), READ(MODRM_RM_M), WRITE(MODRM_R))
	/* 0x8E: MOV Sreg, r/m16; MOV Sreg, r/m64 */ SPECIAL(INST_MOV_TO_SEG, MODRM(), READ(MODRM_RM))
	/* 0x8F: POP r/m? */ INST(MODRM(), READ(REG_SP), WRITE(REG_SP | MODRM_RM))
	/* NOTE: The read and write information of these are not very accurate */
	/* 0x90: XCHG ?AX, ?AX/R8?; NOP */ INST()
	/* 0x91: XCHG ?AX, ?CX/R9? */ INST(READ(REG_AX | REG_CX | REG_R9), WRITE(REG_AX | REG_CX | REG_R9))
	/* 0x92: XCHG ?AX, ?DX/R10? */ INST(READ(REG_AX | REG_DX | REG_R10), WRITE(REG_AX | REG_DX | REG_R10))
	/* 0x93: XCHG ?AX, ?BX/R11? */ INST(READ(REG_AX | REG_BX | REG_R11), WRITE(REG_AX | REG_BX | REG_R11))
	/* 0x94: XCHG ?AX, ?SP/R12? */ INST(READ(REG_AX | REG_SP | REG_R12), WRITE(REG_AX | REG_SP | REG_R12))
	/* 0x95: XCHG ?AX, ?BP/R13? */ INST(READ(REG_AX | REG_BP | REG_R13), WRITE(REG_AX | REG_BP | REG_R13))
	/* 0x96: XCHG ?AX, ?SI/R14? */ INST(READ(REG_AX | REG_SI | REG_R14), WRITE(REG_AX | REG_SI | REG_R14))
	/* 0x97: XCHG ?AX, ?DI/R15? */ INST(READ(REG_AX | REG_DI | REG_R15), WRITE(REG_AX | REG_DI | REG_R15))
	/* 0x98: CBW; CWDE; CDQE */ INST(READ(REG_AX), WRITE(REG_AX))
	/* 0x99: CWD; CDQ; CQO */ INST(READ(REG_AX), WRITE(REG_AX | REG_DX))
#ifdef _WIN64
	/* 0x9A: INVALID */ INVALID()
#else
	/* 0x9A: CALL FAR ptr16:? */ UNSUPPORTED()
#endif
	/* 0x9B: FWAIT */ INST()
	/* 0x9C: PUSHF/PUSHFD/PUSHFQ */ INST(READ(REG_SP), WRITE(REG_SP))
	/* 0x9D: POPF/POPFD/POPFQ */ INST(READ(REG_SP), WRITE(REG_SP))
#ifdef _WIN64
	/* 0x9E: INVALID */ INVALID()
	/* 0x9F: INVALID */ INVALID()
#else
	/* 0x9E: SAHF */ INST(READ(REG_AX))
	/* 0x9F: LAHF */ INST(WRITE(REG_AX))
#endif
	/* 0xA0: MOV AL, moffs8 */ SPECIAL(INST_MOV_MOFFSET, IMM(PREFIX_ADDRESS_SIZE_64), WRITE(REG_AX))
	/* 0xA1: MOV ?AX, moffs? */ SPECIAL(INST_MOV_MOFFSET, IMM(PREFIX_ADDRESS_SIZE_64), WRITE(REG_AX))
	/* 0xA2: MOV moffs8, AL */ SPECIAL(INST_MOV_MOFFSET, IMM(PREFIX_ADDRESS_SIZE_64), READ(REG_AX))
	/* 0xA3: MOV moffs?, ?AX */ SPECIAL(INST_MOV_MOFFSET, IMM(PREFIX_ADDRESS_SIZE_64), READ(REG_AX))
	/* 0xA4: MOVSB */ INST(READ(REG_SI | REG_DI))
	/* 0xA5: MOVSW/MOVSD/MOVSQ */ INST(READ(REG_SI | REG_DI))
	/* 0xA6: CMPSB */ INST(READ(REG_SI | REG_DI))
	/* 0xA7: CMPSW/CMPSD/CMPSDQ */ INST(READ(REG_SI | REG_DI))
	/* 0xA8: TEST AL, imm8 */ INST(IMM(1), READ(REG_AX))
	/* 0xA9: TEST ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX))
	/* 0xAA: STOSB */ INST(READ(REG_AX | REG_DI))
	/* 0xAB: STOSW/STOSD/STOSQ */ INST(READ(REG_AX | REG_DI))
	/* 0xAC: LODSB */ INST(READ(REG_SI), WRITE(REG_AX))
	/* 0xAD: LODSW/LODSD/LODSQ */ INST(READ(REG_SI), WRITE(REG_AX))
	/* 0xAE: SCASB */ INST(READ(REG_AX | REG_DI))
	/* 0xAF: SCASW/SCASD/SCASQ */ INST(READ(REG_AX | REG_DI))
	/* NOTE: The read and write information of these are not very accurate */
	/* 0xB0: MOV AL/R8L, imm8 */ INST(IMM(1), WRITE(REG_AX | REG_R8))
	/* 0xB1: MOV CL/R9L, imm8 */ INST(IMM(1), WRITE(REG_CX | REG_R9))
	/* 0xB2: MOV DL/R10L, imm8 */ INST(IMM(1), WRITE(REG_DX | REG_R10))
	/* 0xB3: MOV BL/R11L, imm8 */ INST(IMM(1), WRITE(REG_BX | REG_R11))
	/* 0xB4: MOV AH/SP/R12L, imm8 */ INST(IMM(1), WRITE(REG_AX | REG_SP | REG_R12))
	/* 0xB5: MOV CH/BP/R13L, imm8 */ INST(IMM(1), WRITE(REG_CX | REG_BP | REG_R13))
	/* 0xB6: MOV DH/SI/R14L, imm8 */ INST(IMM(1), WRITE(REG_DX | REG_SI | REG_R14))
	/* 0xB7: MOV BH/DI/R15L, imm8 */ INST(IMM(1), WRITE(REG_BX | REG_DI | REG_R15))
	/* 0xB8: MOV ?AX/R8?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_AX | REG_R8))
	/* 0xB9: MOV ?CX/R9?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_CX | REG_R9))
	/* 0xBA: MOV ?DX/R10?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_DX | REG_R10))
	/* 0xBB: MOV ?BX/R11?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_BX | REG_R11))
	/* 0xBC: MOV ?SP/R12?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_SP | REG_R12))
	/* 0xBD: MOV ?BP/R13?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_BP | REG_R13))
	/* 0xBE: MOV ?SI/R14?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_SI | REG_R14))
	/* 0xBF: MOV ?DI/R15?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_DI | REG_R15))
	/* [GRP2]: 0/ROL, 1/ROR, 2/RCL, 3/RCR, 4/SHL/SAL, 5/SHR, 7/SAR */
	/* 0xC0: [GRP2] r/m8, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xC1: [GRP2] r/m?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xC2: RET imm16 */ SPECIAL(INST_RETN, IMM(2))
	/* 0xC3: RET */ SPECIAL(INST_RET)
#ifdef _WIN64
	/* 0xC4: INVALID */ INVALID()
	/* 0xC5: INVALID */ INVALID()
#else
	/* 0xC4: LES r?, m16:? */ UNSUPPORTED()
	/* 0xC5: LDS r?, m16:? */ UNSUPPORTED()
#endif
	/* 0xC6: */ EXTENSION(C6)
	/* 0xC7: */ EXTENSION(C7)
	/* 0xC8: ENTER */ UNSUPPORTED()
	/* 0xC9: LEAVE */ INST(READ(REG_BP), WRITE(REG_BP | REG_SP))
	/* 0xCA: RET FAR imm16 */ UNSUPPORTED()
	/* 0xCB: RET FAR */ UNSUPPORTED()
	/* 0xCC: INT 3 */ INST()
	/* 0xCD: INT */ SPECIAL(INST_INT, IMM(1))
#ifdef _WIN64
	/* 0xCE: INVALID */ INVALID()
#else
	/* 0xCE: INTO */ INST()
#endif
	/* 0xCF: IRET/IRETD/IRETQ */ UNSUPPORTED()
	/* 0xD0: [GRP2] r/m8, 1 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xD1: [GRP2] r/m?, 1 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xD2: [GRP2] r/m8, CL */ INST(MODRM(), READ(MODRM_RM | REG_CX), WRITE(MODRM_RM))
	/* 0xD3: [GRP2] r/m?, CL */ INST(MODRM(), READ(MODRM_RM | REG_CX), WRITE(MODRM_RM))
#ifdef _WIN64
	/* 0xD4: INVALID */ INVALID()
	/* 0xD5: INVALID */ INVALID()
#else
	/* 0xD4: AAM */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0xD5: AAD */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0xD6: ??? */ UNKNOWN()
	/* 0xD7: XLAT */ UNSUPPORTED()
	/* 0xD8: (x87 escape) */ X87()
	/* 0xD9: (x87 escape) */ X87()
	/* 0xDA: (x87 escape) */ X87()
	/* 0xDB: (x87 escape) */ X87()
	/* 0xDC: (x87 escape) */ X87()
	/* 0xDD: (x87 escape) */ X87()
	/* 0xDE: (x87 escape) */ X87()
	/* 0xDF: (x87 escape) */ X87()
	/* 0xE0: LOOPNE rel8 */ SPECIAL(INST_JCC_REL8, IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE1: LOOPE rel8 */ SPECIAL(INST_JCC_REL8, IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE2: LOOP rel8 */ SPECIAL(INST_JCC_REL8, IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE3: JCXZ/JECXZ rel8 */ SPECIAL(INST_JCC_REL8, IMM(1), READ(REG_CX))
	/* 0xE4: IN AL, imm8 */ INST(PRIVILEGED(), IMM(1), WRITE(REG_AX))
	/* 0xE5: IN AX/EAX, imm8 */ INST(PRIVILEGED(), IMM(1), WRITE(REG_AX))
	/* 0xE6: OUT imm8, AL */ INST(PRIVILEGED(), IMM(1), READ(REG_AX))
	/* 0xE7: OUT imm8, AX/EAX */ INST(PRIVILEGED(), IMM(1), READ(REG_AX))
	/* 0xE8: CALL rel16/rel32 */ SPECIAL(INST_CALL_DIRECT, IMM(PREFIX_OPERAND_SIZE))
	/* 0xE9: JMP rel? */ SPECIAL(INST_JMP_DIRECT, IMM(PREFIX_OPERAND_SIZE))
#ifdef _WIN64
	/* 0xEA: INVALID */ INVALID()
#else
	/* 0xEA: JMP FAR ptr16:? */ UNSUPPORTED()
#endif
	/* 0xEB: JMP rel8 */ SPECIAL(INST_JMP_DIRECT, IMM(1))
	/* 0xEC: IN AL, DX */ INST(PRIVILEGED(), READ(REG_DX), WRITE(REG_AX))
	/* 0xED: IN AX/EAX, DX */ INST(PRIVILEGED(), READ(REG_DX), WRITE(REG_AX))
	/* 0xEE: OUT DX, AL */ INST(PRIVILEGED(), READ(REG_DX | REG_AX))
	/* 0xEF: OUT DX, AX/EAX */ INST(PRIVILEGED(), READ(REG_DX | REG_AX))
	/* 0xF0: LOCK prefix */ INVALID()
	/* 0xF1: ??? */ UNKNOWN()
	/* 0xF2: ??? */ UNKNOWN()
	/* 0xF3: ??? */ UNKNOWN()
	/* 0xF4: HLT */ INST(PRIVILEGED())
	/* 0xF5: CMC */ INST()
	/* 0xF6 */ EXTENSION(F6)
	/* 0xF7 */ EXTENSION(F7)
	/* 0xF8: CLC */ INST()
	/* 0xF9: STC */ INST()
	/* 0xFA: CLI */ INST()
	/* 0xFB: STI */ INST()
	/* 0xFC: CLD */ INST()
	/* 0xFD: STD */ INST()
	/* [GRP4]: 0/INC, /DEC */
	/* 0xFE: [GRP4] r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xFF */ EXTENSION(FF)
};

static const struct instruction_desc mandatory_0x0F10[4] =
{
	/* 00: (SSE) MOVUPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) MOVUPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) MOVSS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) MOVSD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F11[4] =
{
	/* 00: (SSE) MOVUPS xmm2/m128, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* 66: (SSE2) MOVUPD xmm2/m128, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* F3: (SSE) MOVSS xmm2/m32, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* F2: (SSE2) MOVSD xmm2/m64, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
};

static const struct instruction_desc mandatory_0x0F12[4] =
{
	/* 00: (SSE) MOVLPS xmm, m64; MOVHLPS xmm1, xmm2 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) MOVLPD xmm, m64 */ INST(MODRM(), READ(MODRM_RM_M), WRITE(MODRM_R))
	/* F3: (SSE3) MOVSLDUP xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE3) MOVDDUP xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F13[4] =
{
	/* 00: (SSE) MOVLPS m64, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_M))
	/* 66: (SSE2) MOVLPD m64, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_M))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F14[4] =
{
	/* 00: (SSE) UNPCKLPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) UNPCKLPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F15[4] =
{
	/* 00: (SSE) UNPCKHPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) UNPCKHPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F16[4] =
{
	/* 00: (SSE) MOVHPS xmm, m64; MOVLHPS xmm1, xmm2 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) MOVHPD xmm, m64 */ INST(MODRM(), READ(MODRM_RM_M), WRITE(MODRM_R))
	/* F3: (SSE3) MOVSHDUP xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F17[4] =
{
	/* 00: (SSE) MOVHPS/MOVLHPS m64, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_R))
	/* 66: (SSE2) MOVHPD m64, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F28[4] =
{
	/* 00: (SSE) MOVAPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) MOVAPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F29[4] =
{
	/* 00: (SSE) MOVAPS xmm2/m128, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* 66: (SSE2) MOVAPD xmm2/m128, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F2A[4] =
{
	/* 00: (MMX) CVTPI2PS xmm, mm/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (MMX) CVTPI2PD xmm, mm/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE2) CVTSI2SS xmm, r/m32 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) CVTSI2SD xmm, r/m32 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F2B[4] =
{
	/* 00: (SSE) MOVNTPS m128, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_M))
	/* 66: (SSE2) MOVNTPD m128, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_M))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F2C[4] =
{
	/* 00: (MMX) CVTTPS2PI mm, xmm/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (MMX) CVTTPD2PI mm, xmm/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) CVTTSS2SI r32, xmm/m32 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) CVTTSD2SI r32, xmm/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F2D[4] =
{
	/* 00: (MMX) CVTPS2PI mm, xmm/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (MMX) CVTPD2PI mm, xmm/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) CVTSS2SI r32, xmm/m32 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) CVTSD2SI r32, xmm/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F2E[4] =
{
	/* 00: (SSE) UCOMISS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) UCOMISD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F2F[4] =
{
	/* 00: (SSE) COMISS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) COMISD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F50[4] =
{
	/* 00: (SSE) MOVMSKPS reg, xmm */ INST(MODRM(), READ(MODRM_RM_R), WRITE(MODRM_R))
	/* 66: (SSE2) MOVMSKPD reg, xmm */ INST(MODRM(), READ(MODRM_RM_R), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F51[4] =
{
	/* 00: (SSE) SQRTPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) SQRTPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) SQRTSS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) SQRTSD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F52[4] =
{
	/* 00: (SSE) RSQRTPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: ??? */ UNKNOWN()
	/* F3: (SSE) RSQRTSS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F53[4] =
{
	/* 00: (SSE) RCPPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: ??? */ UNKNOWN()
	/* F3: (SSE) RCPSS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F54[4] =
{
	/* 00: (SSE) ANDPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) ANDPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F55[4] =
{
	/* 00: (SSE) ANDNPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) ANDNPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F56[4] =
{
	/* 00: (SSE) ORPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) ORPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F57[4] =
{
	/* 00: (SSE) XORPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) XORPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F58[4] =
{
	/* 00: (SSE) ADDPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) ADDPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) ADDSS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) ADDSD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F59[4] =
{
	/* 00: (SSE) MULPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) MULPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) MULSS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) MULSD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F5A[4] =
{
	/* 00: (SSE2) CVTPS2PD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) CVTPD2PS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE2) CVTSS2SD xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) CVTSD2SS xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F5B[4] =
{
	/* 00: (SSE2) CVTDQ2PS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) CVTPS2DQ xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE2) CVTTPS2DQ xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F5C[4] =
{
	/* 00: (SSE) SUBPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) SUBPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) SUBSS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) SUBSD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F5D[4] =
{
	/* 00: (SSE) MINPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) MINPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) MINSS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) MINSD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F5E[4] =
{
	/* 00: (SSE) DIVPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) DIVPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) DIVSS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) DIVSD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F5F[4] =
{
	/* 00: (SSE) MAXPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) MAXPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) MAXSS xmm1, xmm2/m32 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) MAXSD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F6C[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: PUNPCKLQDQ xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F6F[4] =
{
	/* 00: (MMX) MOVQ mm, mm/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) MOVDQA xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE2) MOVDQU xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F70[4] =
{
	/* 00: (SSE2) PSHUFW mm1, mm2/m64, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) PSHUFD xmm1, xmm2/m128, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE2) PSHUFHW xmm1, xmm2/m128, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) PSHUFLW xmm1, xmm2/m128, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F7C[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: (SSE3) HADDPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: (SSE3) HADDPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F7D[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: (SSE3) HSUBPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: (SSE3) HSUBPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0F7E[4] =
{
	/* 00: (MMX) MOVD r/m32, mm; MOVQ r/m64, mm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* 66: (SSE2) MOVD r/m32, xmm; MOVQ r/m64, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* F3: (SSE2) MOVQ xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0F7F[4] =
{
	/* 00: (MMX) MOVQ mm/m64, mm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* 66: (SSE2) MOVDQA xmm2/m128, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* F3: (SSE2) MOVDQU xmm2/m128, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc extension_0xAE[8] =
{
	/* 0: FXSAVE */ INST(MODRM(), WRITE(MODRM_RM_M))
	/* 1: FXRSTOR */ INST(MODRM(), READ(MODRM_RM_M))
	/* 2: LDMXCSR m32 */ INST(MODRM(), READ(MODRM_RM_M))
	/* 3: STMXCSR m32 */ INST(MODRM(), WRITE(MODRM_RM_M))
	/* 4: mem: XSAVE mem */ INST(MODRM(), WRITE(MODRM_RM_M))
	/* 5: r: LFENCE (0F AE E8)
	      mem: XRSTOR mem*/ INST(MODRM(), READ(MODRM_RM_M))
	/* 6: r: MFENCE (0F AE F0)
	      mem: XSAVEOPT mem */ INST(MODRM(), WRITE(MODRM_RM_M))
	/* 7: r: SFENCE (0F AE F8)
	      mem: CLFLUSH m8 */ INST(MODRM(), READ(MODRM_RM_M))
};

static const struct instruction_desc mandatory_0x0FB8[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: ??? */ UNKNOWN()
	/* F3: POPCNT r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0FC2[4] =
{
	/* 00: (SSE) CMPPS xmm1, xmm2/m128, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: (SSE2) CMPPD xmm1, xmm2/m128, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE) CMPSS xmm1, xmm2/m32, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) CMPSD xmm1, xmm2/m64, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0FC6[4] =
{
	/* 00: SHUFPS xmm1, xmm2/m128, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 66: SHUFPD xmm1, xmm2/m128, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0FD0[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: (SSE3) ADDSUBPD xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* F3: ??? */ UNKNOWN()
	/* F2: (SSE3) ADDSUBPS xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0FD6[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: (SSE2) MOVQ xmm2/m64, xmm1 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* F3: (MMX/SSE) MOVQ2DQ xmm, mm */ INST(MODRM(), READ(MODRM_RM_R), WRITE(MODRM_R))
	/* F2: (MMX/SSE) MOVDQ2Q mm, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_R))
};

static const struct instruction_desc mandatory_0x0FE6[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: (SSE2) CVTTPD2DQ xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F3: (SSE2) CVTDQ2PD xmm1, xmm2/m64 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* F2: (SSE2) CVTPD2DQ xmm1, xmm2/m128 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

static const struct instruction_desc mandatory_0x0FE7[4] =
{
	/* 00: (MMX) MOVNTQ m64, mm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_M))
	/* 66: (SSE2) MOVNTDQ m128, xmm */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_M))
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};

static const struct instruction_desc mandatory_0x0FF0[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: ??? */ UNKNOWN()
	/* F3: ??? */ UNKNOWN()
	/* F2: (SSE3) LDDQU xmm1, mem */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
};

#if 0
static const struct instruction_desc mandatory_0x0Fxx[4] =
{
	/* 00: ??? */ UNKNOWN()
	/* 66: ??? */ UNKNOWN()
	/* F3: ??? */ UNKNOWN()
	/* F2: ??? */ UNKNOWN()
};
#endif

/* Instructions with 0F prefix */
static const struct instruction_desc two_byte_inst[256] =
{
	/* 0x00: [GRP6]
	0: SLDT r/m16
	1: STR r/m16
	2: LLDT r/m16
	3: LTR r/m16
	4: VERR r/m16
	5: VERW r/m16 */ UNSUPPORTED()
	/* 0x01: [GRP7]
	0: SGDT m
	1: SIDT m
	2: LGDT m16&32; LGDT m16&64
	3: LIDT m16&32; LIDT m16&64
	4: SMSW r/m16; SMSW r32/m16
	6: LMSW r/m16
	7: INVLPG */ UNSUPPORTED()
	/* 0x02: LAR r16, r16/m16; LAR reg, r32/m16 */ UNSUPPORTED()
	/* 0x03: LSL r?, r?/m16 */ UNSUPPORTED()
	/* 0x04: ??? */ UNKNOWN()
	/* 0x05: SYSCALL */ UNSUPPORTED()
	/* 0x06: CLTS */ UNSUPPORTED()
	/* 0x07: SYSRET */ UNSUPPORTED()
	/* 0x08: INVD */ INST()
	/* 0x09: WBINVD */ UNSUPPORTED()
	/* 0x0A: ??? */ UNKNOWN()
	/* 0x0B: UD2 */ INVALID()
	/* 0x0C: ??? */ UNKNOWN()
	/* 0x0D:
	1: PREFETCHW m8
	2: PREFETCHWT1 m8 */ INST(MODRM(), READ(MODRM_RM_M))
	/* 0x0E: ??? */ UNKNOWN()
	/* 0x0F: ??? */ UNKNOWN()
	/* 0x10: MANDATORY */ MANDATORY(0x0F10)
	/* 0x11: MANDATORY */ MANDATORY(0x0F11)
	/* 0x12: MANDATORY */ MANDATORY(0x0F12)
	/* 0x13: MANDATORY */ MANDATORY(0x0F13)
	/* 0x14: MANDATORY */ MANDATORY(0x0F14)
	/* 0x15: MANDATORY */ MANDATORY(0x0F15)
	/* 0x16: MANDATORY */ MANDATORY(0x0F16)
	/* 0x17: MANDATORY */ MANDATORY(0x0F17)
	/* 0x18:
	0: PREFETCHNTA m8
	1: PREFETCH0 m8
	2: PREFETCH1 m8
	3: PREFETCH2 m8 */ INST(MODRM(), READ(MODRM_RM_M))
	/* 0x19: ??? */ UNKNOWN()
	/* 0x1A: ??? */ UNKNOWN()
	/* 0x1B: ??? */ UNKNOWN()
	/* 0x1C: ??? */ UNKNOWN()
	/* 0x1D: ??? */ UNKNOWN()
	/* 0x1E: ??? */ UNKNOWN()
	/* 0x1F: NOP r/m? */ INST(MODRM())
	/* 0x20: MOV r32, CR0-CR7; MOV r64, CR0-CR7 */ UNSUPPORTED()
	/* 0x21: MOV r32, DR0-DR7; MOV r64, DR0-DR7 */ UNSUPPORTED()
	/* 0x22: MOV CR0-CR7, r32; MOV CR0-CR7, r64 */ UNSUPPORTED()
	/* 0x23: MOV DR0-DR7, r32; MOV DR0-DR7, r64 */ UNSUPPORTED()
	/* 0x24: ??? */ UNKNOWN()
	/* 0x25: ??? */ UNKNOWN()
	/* 0x26: ??? */ UNKNOWN()
	/* 0x27: ??? */ UNKNOWN()
	/* 0x28: MANDATORY */ MANDATORY(0x0F28)
	/* 0x29: MANDATORY */ MANDATORY(0x0F29)
	/* 0x2A: MANDATORY */ MANDATORY(0x0F2A)
	/* 0x2B: MANDATORY */ MANDATORY(0x0F2B)
	/* 0x2C: MANDATORY */ MANDATORY(0x0F2C)
	/* 0x2D: MANDATORY */ MANDATORY(0x0F2D)
	/* 0x2E: MANDATORY */ MANDATORY(0x0F2E)
	/* 0x2F: MANDATORY */ MANDATORY(0x0F2F)
	/* 0x30: WRMSR */ INST(PRIVILEGED(), READ(REG_AX | REG_CX | REG_DX))
	/* 0x31: RDTSC */ INST(WRITE(REG_AX | REG_DX))
	/* 0x32: RDMSR */ INST(PRIVILEGED(), READ(REG_CX), WRITE(REG_AX | REG_DX))
	/* 0x33: RDPMC */ INST(READ(REG_CX), WRITE(REG_AX | REG_DX))
	/* 0x34: SYSENTER */ UNSUPPORTED()
	/* 0x35: SYSEXIT */ UNSUPPORTED()
	/* 0x36: ??? */ UNKNOWN()
	/* 0x37: ??? */ UNKNOWN()
	/* 0x38: ??? */ UNKNOWN()
	/* 0x39: ??? */ UNKNOWN()
	/* 0x3A: ??? */ UNKNOWN()
	/* 0x3B: ??? */ UNKNOWN()
	/* 0x3C: ??? */ UNKNOWN()
	/* 0x3D: ??? */ UNKNOWN()
	/* 0x3E: ??? */ UNKNOWN()
	/* 0x3F: ??? */ UNKNOWN()
	/* 0x40: CMOVO r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x41: CMOVNO r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x42: CMOVB/CMOVNAE/CMOVC r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x43: CMOVAE/CMOVNB/CMOVNC r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x44: CMOVE/CMOVZ r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x45: CMOVNE/CMOVNZ r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x46: CMOVBE/CMOVNA r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x47: CMOVA/CMOVNBE r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x48: CMOVS r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x49: CMOVNS r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4A: CMOVP/CMOVPE r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4B: CMOVNP/CMOVPO r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4C: CMOVL/CMOVNGE r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4D: CMOVGE/CMOVNL r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4E: CMOVLE/CMOVNG r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4F: CMOVG/CMOVNLE r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x50: MANDATORY */ MANDATORY(0x0F50)
	/* 0x51: MANDATORY */ MANDATORY(0x0F51)
	/* 0x52: MANDATORY */ MANDATORY(0x0F52)
	/* 0x53: MANDATORY */ MANDATORY(0x0F53)
	/* 0x54: MANDATORY */ MANDATORY(0x0F54)
	/* 0x55: MANDATORY */ MANDATORY(0x0F55)
	/* 0x56: MANDATORY */ MANDATORY(0x0F56)
	/* 0x57: MANDATORY */ MANDATORY(0x0F57)
	/* 0x58: MANDATORY */ MANDATORY(0x0F58)
	/* 0x59: MANDATORY */ MANDATORY(0x0F59)
	/* 0x5A: MANDATORY */ MANDATORY(0x0F5A)
	/* 0x5B: MANDATORY */ MANDATORY(0x0F5B)
	/* 0x5C: MANDATORY */ MANDATORY(0x0F5C)
	/* 0x5D: MANDATORY */ MANDATORY(0x0F5D)
	/* 0x5E: MANDATORY */ MANDATORY(0x0F5E)
	/* 0x5F: MANDATORY */ MANDATORY(0x0F5F)
	/* 0x60: PUNPCKLBW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x61: PUNPCKLWD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x62: PUNPCKLDQ ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x63: PACKSSWB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x64: PCMPGTB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x65: PCMPGTW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x66: PCMPGTD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x67: PACKUSWB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x68: PUNPCKHBW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x69: PUNPCKHWD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6A: PUNPCKHDQ ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6B: PACKSSDW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6C: MANDATORY */ MANDATORY(0x0F6C)
	/* 0x6D: ??? */ UNKNOWN()
	/* 0x6E: MOVD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x6F: MANDATORY */ MANDATORY(0x0F6F)
	/* 0x70: MANDATORY */ MANDATORY(0x0F70)
	/* [...]: 2/SRL 4/SRA 6/SLL */
	/* 0x71: P???W ?mm1, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x72: P???D ?mm1, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* [GRP]: 2/PSRLQ 3/PSRLDQ 6/PSLLQ 7/PSLLDQ */
	/* 0x73: [GRP] ?mm1, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x74: PCMPEQB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x75: PCMPEQW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x76: PCMPEQD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x77: EMMS */ INST()
	/* 0x78: ??? */ UNKNOWN()
	/* 0x79: ??? */ UNKNOWN()
	/* 0x7A: ??? */ UNKNOWN()
	/* 0x7B: ??? */ UNKNOWN()
	/* 0x7C: MANDATORY */ MANDATORY(0x0F7C)
	/* 0x7D: MANDATORY */ MANDATORY(0x0F7D)
	/* 0x7E: MANDATORY */ MANDATORY(0x0F7E)
	/* 0x7F: MANDATORY */ MANDATORY(0x0F7F)
	/* 0x80: JO rel? */ SPECIAL(INST_JCC + 0, IMM(PREFIX_OPERAND_SIZE))
	/* 0x81: JNO rel? */ SPECIAL(INST_JCC + 1, IMM(PREFIX_OPERAND_SIZE))
	/* 0x82: JB/JC/JNAE rel? */ SPECIAL(INST_JCC + 2, IMM(PREFIX_OPERAND_SIZE))
	/* 0x83: JAE/JNB/JNC rel? */ SPECIAL(INST_JCC + 3, IMM(PREFIX_OPERAND_SIZE))
	/* 0x84: JE/JZ rel? */ SPECIAL(INST_JCC + 4, IMM(PREFIX_OPERAND_SIZE))
	/* 0x85: JNE/JNZ rel? */ SPECIAL(INST_JCC + 5, IMM(PREFIX_OPERAND_SIZE))
	/* 0x86: JBE/JNA rel? */ SPECIAL(INST_JCC + 6, IMM(PREFIX_OPERAND_SIZE))
	/* 0x87: JA/JNBE rel? */ SPECIAL(INST_JCC + 7, IMM(PREFIX_OPERAND_SIZE))
	/* 0x88: JS rel? */ SPECIAL(INST_JCC + 8, IMM(PREFIX_OPERAND_SIZE))
	/* 0x89: JNS rel? */ SPECIAL(INST_JCC + 9, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8A: JP/JPE rel? */ SPECIAL(INST_JCC + 10, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8B: JNP/JPO rel? */ SPECIAL(INST_JCC + 11, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8C: JL/JNGE rel? */ SPECIAL(INST_JCC + 12, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8D: JGE/JNL rel? */ SPECIAL(INST_JCC + 13, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8E: JLE/JNG rel? */ SPECIAL(INST_JCC + 14, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8F: JG/JNLE rel? */ SPECIAL(INST_JCC + 15, IMM(PREFIX_OPERAND_SIZE))
	/* 0x90: SETO r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x91: SETNO r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x92: SETB/SETC/SETNAE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x93: SETAE/SETNB/SETNC r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x94: SETE/SETZ r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x95: SETNE/SETNZ r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x96: SETBE/SETNA r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x97: SETA/SETNBE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x98: SETS r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x99: SETNS r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9A: SETP/SETPE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9B: SETNP/SETPO r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9C: SETL/SETNGE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9D: SETGE/SETNL r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9E: SETLE/SETNG r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9F: SETG/SETNLE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0xA0: ??? */ UNKNOWN()
	/* 0xA1: POP FS */ UNSUPPORTED()
	/* 0xA2: CPUID */ SPECIAL(INST_CPUID, READ(REG_AX | REG_BX | REG_CX | REG_DX), WRITE(REG_AX | REG_BX | REG_CX | REG_DX))
	/* 0xA3: BT r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0xA4: SHLD r/m?, r?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM | MODRM_R), WRITE(MODRM_RM))
	/* 0xA5: SHLD r/m?, r?, CL */ INST(MODRM(), READ(MODRM_RM | MODRM_R | REG_CX), WRITE(MODRM_RM))
	/* 0xA6: ??? */ UNKNOWN()
	/* 0xA7: ??? */ UNKNOWN()
	/* 0xA8: ??? */ UNKNOWN()
	/* 0xA9: POP GS */ UNSUPPORTED()
#ifdef _WIN64
	/* 0xAA: INVALID */ INVALID()
#else
	/* 0xAA: RSM */ UNSUPPORTED()
#endif
	/* 0xAB: BTS r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0xAC: SHRD r/m?, r?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM | MODRM_R), WRITE(MODRM_RM))
	/* 0xAD: SHRD r/m?, r?, CL */ INST(MODRM(), READ(MODRM_RM | MODRM_R | REG_CX), WRITE(MODRM_RM))
	/* 0xAE: EXTENSION */ EXTENSION(0xAE)
	/* 0xAF: IMUL r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xB0: CMPXCHG r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_RM | REG_AX))
	/* 0xB1: CMPXCHG r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_RM | REG_AX))
	/* 0xB2: LSS r?, m16:? */ UNSUPPORTED()
	/* 0xB3: BTR r/m?, r? */ INST(MODRM(), READ(MODRM_RM))
	/* 0xB4: LFS r?, m16:? */ UNSUPPORTED()
	/* 0xB5: LGS r?, m16:? */ UNSUPPORTED()
	/* 0xB6: MOVZX r?, r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xB7: MOVZX r?, r/m16 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xB8: MANDATORY */ MANDATORY(0x0FB8)
	/* 0xB9: ??? */ UNKNOWN()
	/* GRP8: 4/BT, 5/BTS, 6/BTR, 7/BTC */
	/* 0xBA: [GRP8] r/m?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM))
	/* 0xBB: BTC r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0xBC: BSF r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBD: BSR r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBE: MOVSX r?, r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBF: MOVSX r?, r/m16 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xC0: XADD r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0xC1: XADD r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0xC2: MANDATORY */ MANDATORY(0x0FC2)
	/* 0xC3: MOVNTI m?, r? */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_M))
	/* 0xC4: PINSRW ?mm1, r32/m16, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xC5: PEXTRW reg, ?mm, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM_R), WRITE(MODRM_R))
	/* 0xC6: MANDATORY */ MANDATORY(0x0FC6)
	/* 0xC7:
	1: CMPXCHG8B m64/m128
	5: XSAVES mem; XSAVES64 mem */ UNSUPPORTED()
	/* NOTE: The read and write information of these are not very accurate */
	/* 0xC8: BSWAP ?AX/R8? */ INST(READ(REG_AX | REG_R8), WRITE(REG_AX | REG_R8))
	/* 0xC9: BSWAP ?CX/R9? */ INST(READ(REG_CX | REG_R9), WRITE(REG_CX | REG_R9))
	/* 0xCA: BSWAP ?DX/R10? */ INST(READ(REG_DX | REG_R10), WRITE(REG_DX | REG_R10))
	/* 0xCB: BSWAP ?BX/R11? */ INST(READ(REG_BX | REG_R11), WRITE(REG_BX | REG_R11))
	/* 0xCC: BSWAP ?SP/R12? */ INST(READ(REG_SP | REG_R12), WRITE(REG_SP | REG_R12))
	/* 0xCD: BSWAP ?BP/R13? */ INST(READ(REG_BP | REG_R13), WRITE(REG_BP | REG_R13))
	/* 0xCE: BSWAP ?SI/R14? */ INST(READ(REG_SI | REG_R14), WRITE(REG_SI | REG_R14))
	/* 0xCF: BSWAP ?DI/R15? */ INST(READ(REG_DI | REG_R15), WRITE(REG_DI | REG_R15))
	/* 0xD0: MANDATORY */ MANDATORY(0x0FD0)
	/* 0xD1: PSRLW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xD2: PSRLD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xD3: PSRLQ ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xD4: PADDQ ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xD5: PMULLW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xD6: MANDATORY */ MANDATORY(0x0FD6)
	/* 0xD7: PMOVMSKB reg, ?mm */ INST(MODRM(), READ(MODRM_RM_R), WRITE(MODRM_R))
	/* 0xD8: PSUBUSB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xD9: PSUBUSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xDA: PMINUB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xDB: PAND ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xDC: PADDUSB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xDD: PADDUSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xDE: PMAXUB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xDF: PANDN ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xE0: PAVGB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xE1: PSRAW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xE2: PSRAD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xE3: PAVGW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xE4: PMULHUW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xE5: PMULHW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xE6: MANDATORY */ MANDATORY(0x0FE6)
	/* 0xE7: MANDATORY */ MANDATORY(0x0FE7)
	/* 0xE8: PSUBSB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xE9: PSUBSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xEA: PMINSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xEB: POR ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xEC: PADDSB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xED: PADDSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xEE: PMAXSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xEF: PXOR ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xF0: MANDATORY */ MANDATORY(0x0FF0)
	/* 0xF1: PSLLW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xF2: PSLLD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xF3: PSLLQ ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xF4: PMULUDQ ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xF5: PMADDWD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xF6: PSADBW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xF7: MASKMOVQ ?mm1, ?mm2 */ INST(MODRM(), READ(MODRM_R | MODRM_RM_R | REG_DI))
	/* 0xF8: PSUBB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xF9: PSUBW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xFA: PSUBD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xFB: PSUBQ ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xFC: PADDB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xFD: PADDW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xFE: PADDD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xFF: ??? */ UNKNOWN()
};

/* Instructions with 0F 38 prefix */
static const struct instruction_desc three_byte_inst_0x38[256] =
{
	/* 0x00: PSHUFB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x01: PHADDW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x02: PHADDD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x03: PHADDSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x04: PMADDUBSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x05: PHSUBW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x06: PHSUBD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x07: PHSUBSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x08: PSIGNB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x09: PSIGNW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0A: PSIGND ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0B: PMULHRSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0C: ??? */ UNKNOWN()
	/* 0x0D: ??? */ UNKNOWN()
	/* 0x0E: ??? */ UNKNOWN()
	/* 0x0F: ??? */ UNKNOWN()
	/* 0x10: PBLENDVB xmm1, xmm2/m128, <xmm0> */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_R))
	/* 0x11: ??? */ UNKNOWN()
	/* 0x12: ??? */ UNKNOWN()
	/* 0x13: ??? */ UNKNOWN()
	/* 0x14: BLENDVPS xmm1, xmm2/m128, <xmm0> */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_R))
	/* 0x15: BLENDVPD xmm1, xmm2/m128, <xmm0> */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_R))
	/* 0x16: ??? */ UNKNOWN()
	/* 0x17: PTEST xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x18: ??? */ UNKNOWN()
	/* 0x19: ??? */ UNKNOWN()
	/* 0x1A: ??? */ UNKNOWN()
	/* 0x1B: ??? */ UNKNOWN()
	/* 0x1C: PABSB ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x1D: PABSW ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x1E: PABSD ?mm1, ?mm2/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x1F: ??? */ UNKNOWN()
	/* 0x20: PMOVSXBW xmm1, xmm2/m64 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x21: PMOVSXBD xmm1, xmm2/m32 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x22: PMOVSXBQ xmm1, xmm2/m16 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x23: PMOVSXWD xmm1, xmm2/m64 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x24: PMOVSXWQ xmm1, xmm2/m32 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x25: PMOVSXDQ xmm1, xmm2/m64 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x26: ??? */ UNKNOWN()
	/* 0x27: ??? */ UNKNOWN()
	/* 0x28: PMULDQ xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x29: PCMPEQQ xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x2A: MOVNTDQA xmm1, m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM_M), WRITE(MODRM_R))
	/* 0x2B: PACKUSDW xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x2C: ??? */ UNKNOWN()
	/* 0x2D: ??? */ UNKNOWN()
	/* 0x2E: ??? */ UNKNOWN()
	/* 0x2F: ??? */ UNKNOWN()
	/* 0x30: PMOVZXBW xmm1, xmm2/m64 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x31: PMOVZXBD xmm1, xmm2/m32 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x32: PMOVZXBQ xmm1, xmm2/m16 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x33: PMOVZXWD xmm1, xmm2/m64 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x34: PMOVZXWQ xmm1, xmm2/m32 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x35: PMOVZXDQ xmm1, xmm2/m64 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x36: ??? */ UNKNOWN()
	/* 0x37: PCMPGTQ xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x38: PMINSB xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x39: PMINSD xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3A: PMINUW xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3B: PMINUD xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3C: PMAXSB xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3D: PMAXSD xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3E: PMAXUW xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3F: PMAXUD xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x40: PMULLD xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x41: PHMINPOSUW xmm1, xmm2/m128 */ INST(REQUIRE_0x66(), MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x42: ??? */ UNKNOWN()
	/* 0x43: ??? */ UNKNOWN()
	/* 0x44: ??? */ UNKNOWN()
	/* 0x45: ??? */ UNKNOWN()
	/* 0x46: ??? */ UNKNOWN()
	/* 0x47: ??? */ UNKNOWN()
	/* 0x48: ??? */ UNKNOWN()
	/* 0x49: ??? */ UNKNOWN()
	/* 0x4A: ??? */ UNKNOWN()
	/* 0x4B: ??? */ UNKNOWN()
	/* 0x4C: ??? */ UNKNOWN()
	/* 0x4D: ??? */ UNKNOWN()
	/* 0x4E: ??? */ UNKNOWN()
	/* 0x4F: ??? */ UNKNOWN()
	/* 0x50: ??? */ UNKNOWN()
	/* 0x51: ??? */ UNKNOWN()
	/* 0x52: ??? */ UNKNOWN()
	/* 0x53: ??? */ UNKNOWN()
	/* 0x54: ??? */ UNKNOWN()
	/* 0x55: ??? */ UNKNOWN()
	/* 0x56: ??? */ UNKNOWN()
	/* 0x57: ??? */ UNKNOWN()
	/* 0x58: ??? */ UNKNOWN()
	/* 0x59: ??? */ UNKNOWN()
	/* 0x5A: ??? */ UNKNOWN()
	/* 0x5B: ??? */ UNKNOWN()
	/* 0x5C: ??? */ UNKNOWN()
	/* 0x5D: ??? */ UNKNOWN()
	/* 0x5E: ??? */ UNKNOWN()
	/* 0x5F: ??? */ UNKNOWN()
	/* 0x60: ??? */ UNKNOWN()
	/* 0x61: ??? */ UNKNOWN()
	/* 0x62: ??? */ UNKNOWN()
	/* 0x63: ??? */ UNKNOWN()
	/* 0x64: ??? */ UNKNOWN()
	/* 0x65: ??? */ UNKNOWN()
	/* 0x66: ??? */ UNKNOWN()
	/* 0x67: ??? */ UNKNOWN()
	/* 0x68: ??? */ UNKNOWN()
	/* 0x69: ??? */ UNKNOWN()
	/* 0x6A: ??? */ UNKNOWN()
	/* 0x6B: ??? */ UNKNOWN()
	/* 0x6C: ??? */ UNKNOWN()
	/* 0x6D: ??? */ UNKNOWN()
	/* 0x6E: ??? */ UNKNOWN()
	/* 0x6F: ??? */ UNKNOWN()
	/* 0x70: ??? */ UNKNOWN()
	/* 0x71: ??? */ UNKNOWN()
	/* 0x72: ??? */ UNKNOWN()
	/* 0x73: ??? */ UNKNOWN()
	/* 0x74: ??? */ UNKNOWN()
	/* 0x75: ??? */ UNKNOWN()
	/* 0x76: ??? */ UNKNOWN()
	/* 0x77: ??? */ UNKNOWN()
	/* 0x78: ??? */ UNKNOWN()
	/* 0x79: ??? */ UNKNOWN()
	/* 0x7A: ??? */ UNKNOWN()
	/* 0x7B: ??? */ UNKNOWN()
	/* 0x7C: ??? */ UNKNOWN()
	/* 0x7D: ??? */ UNKNOWN()
	/* 0x7E: ??? */ UNKNOWN()
	/* 0x7F: ??? */ UNKNOWN()
	/* 0x80: ??? */ UNKNOWN()
	/* 0x81: ??? */ UNKNOWN()
	/* 0x82: ??? */ UNKNOWN()
	/* 0x83: ??? */ UNKNOWN()
	/* 0x84: ??? */ UNKNOWN()
	/* 0x85: ??? */ UNKNOWN()
	/* 0x86: ??? */ UNKNOWN()
	/* 0x87: ??? */ UNKNOWN()
	/* 0x88: ??? */ UNKNOWN()
	/* 0x89: ??? */ UNKNOWN()
	/* 0x8A: ??? */ UNKNOWN()
	/* 0x8B: ??? */ UNKNOWN()
	/* 0x8C: ??? */ UNKNOWN()
	/* 0x8D: ??? */ UNKNOWN()
	/* 0x8E: ??? */ UNKNOWN()
	/* 0x8F: ??? */ UNKNOWN()
	/* 0x90: ??? */ UNKNOWN()
	/* 0x91: ??? */ UNKNOWN()
	/* 0x92: ??? */ UNKNOWN()
	/* 0x93: ??? */ UNKNOWN()
	/* 0x94: ??? */ UNKNOWN()
	/* 0x95: ??? */ UNKNOWN()
	/* 0x96: ??? */ UNKNOWN()
	/* 0x97: ??? */ UNKNOWN()
	/* 0x98: ??? */ UNKNOWN()
	/* 0x99: ??? */ UNKNOWN()
	/* 0x9A: ??? */ UNKNOWN()
	/* 0x9B: ??? */ UNKNOWN()
	/* 0x9C: ??? */ UNKNOWN()
	/* 0x9D: ??? */ UNKNOWN()
	/* 0x9E: ??? */ UNKNOWN()
	/* 0x9F: ??? */ UNKNOWN()
	/* 0xA0: ??? */ UNKNOWN()
	/* 0xA1: ??? */ UNKNOWN()
	/* 0xA2: ??? */ UNKNOWN()
	/* 0xA3: ??? */ UNKNOWN()
	/* 0xA4: ??? */ UNKNOWN()
	/* 0xA5: ??? */ UNKNOWN()
	/* 0xA6: ??? */ UNKNOWN()
	/* 0xA7: ??? */ UNKNOWN()
	/* 0xA8: ??? */ UNKNOWN()
	/* 0xA9: ??? */ UNKNOWN()
	/* 0xAA: ??? */ UNKNOWN()
	/* 0xAB: ??? */ UNKNOWN()
	/* 0xAC: ??? */ UNKNOWN()
	/* 0xAD: ??? */ UNKNOWN()
	/* 0xAE: ??? */ UNKNOWN()
	/* 0xAF: ??? */ UNKNOWN()
	/* 0xB0: ??? */ UNKNOWN()
	/* 0xB1: ??? */ UNKNOWN()
	/* 0xB2: ??? */ UNKNOWN()
	/* 0xB3: ??? */ UNKNOWN()
	/* 0xB4: ??? */ UNKNOWN()
	/* 0xB5: ??? */ UNKNOWN()
	/* 0xB6: ??? */ UNKNOWN()
	/* 0xB7: ??? */ UNKNOWN()
	/* 0xB8: ??? */ UNKNOWN()
	/* 0xB9: ??? */ UNKNOWN()
	/* 0xBA: ??? */ UNKNOWN()
	/* 0xBB: ??? */ UNKNOWN()
	/* 0xBC: ??? */ UNKNOWN()
	/* 0xBD: ??? */ UNKNOWN()
	/* 0xBE: ??? */ UNKNOWN()
	/* 0xBF: ??? */ UNKNOWN()
	/* 0xC0: ??? */ UNKNOWN()
	/* 0xC1: ??? */ UNKNOWN()
	/* 0xC2: ??? */ UNKNOWN()
	/* 0xC3: ??? */ UNKNOWN()
	/* 0xC4: ??? */ UNKNOWN()
	/* 0xC5: ??? */ UNKNOWN()
	/* 0xC6: ??? */ UNKNOWN()
	/* 0xC7: ??? */ UNKNOWN()
	/* 0xC8: ??? */ UNKNOWN()
	/* 0xC9: ??? */ UNKNOWN()
	/* 0xCA: ??? */ UNKNOWN()
	/* 0xCB: ??? */ UNKNOWN()
	/* 0xCC: ??? */ UNKNOWN()
	/* 0xCD: ??? */ UNKNOWN()
	/* 0xCE: ??? */ UNKNOWN()
	/* 0xCF: ??? */ UNKNOWN()
	/* 0xD0: ??? */ UNKNOWN()
	/* 0xD1: ??? */ UNKNOWN()
	/* 0xD2: ??? */ UNKNOWN()
	/* 0xD3: ??? */ UNKNOWN()
	/* 0xD4: ??? */ UNKNOWN()
	/* 0xD5: ??? */ UNKNOWN()
	/* 0xD6: ??? */ UNKNOWN()
	/* 0xD7: ??? */ UNKNOWN()
	/* 0xD8: ??? */ UNKNOWN()
	/* 0xD9: ??? */ UNKNOWN()
	/* 0xDA: ??? */ UNKNOWN()
	/* 0xDB: ??? */ UNKNOWN()
	/* 0xDC: ??? */ UNKNOWN()
	/* 0xDD: ??? */ UNKNOWN()
	/* 0xDE: ??? */ UNKNOWN()
	/* 0xDF: ??? */ UNKNOWN()
	/* 0xE0: ??? */ UNKNOWN()
	/* 0xE1: ??? */ UNKNOWN()
	/* 0xE2: ??? */ UNKNOWN()
	/* 0xE3: ??? */ UNKNOWN()
	/* 0xE4: ??? */ UNKNOWN()
	/* 0xE5: ??? */ UNKNOWN()
	/* 0xE6: ??? */ UNKNOWN()
	/* 0xE7: ??? */ UNKNOWN()
	/* 0xE8: ??? */ UNKNOWN()
	/* 0xE9: ??? */ UNKNOWN()
	/* 0xEA: ??? */ UNKNOWN()
	/* 0xEB: ??? */ UNKNOWN()
	/* 0xEC: ??? */ UNKNOWN()
	/* 0xED: ??? */ UNKNOWN()
	/* 0xEE: ??? */ UNKNOWN()
	/* 0xEF: ??? */ UNKNOWN()
	/* 0xF0: MOVBE r?, m? */ INST(MODRM(), READ(MODRM_RM_M), WRITE(MODRM_R))
	/* 0xF1: MOVBE m?, r? */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM_M))
	/* 0xF2: ??? */ UNKNOWN()
	/* 0xF3: ??? */ UNKNOWN()
	/* 0xF4: ??? */ UNKNOWN()
	/* 0xF5: ??? */ UNKNOWN()
	/* 0xF6: ??? */ UNKNOWN()
	/* 0xF7: ??? */ UNKNOWN()
	/* 0xF8: ??? */ UNKNOWN()
	/* 0xF9: ??? */ UNKNOWN()
	/* 0xFA: ??? */ UNKNOWN()
	/* 0xFB: ??? */ UNKNOWN()
	/* 0xFC: ??? */ UNKNOWN()
	/* 0xFD: ??? */ UNKNOWN()
	/* 0xFE: ??? */ UNKNOWN()
	/* 0xFF: ??? */ UNKNOWN()
};

/* Instructions with 0F 3A prefix */
static const struct instruction_desc three_byte_inst_0x3A[256] =
{
	/* 0x00: ??? */ UNKNOWN()
	/* 0x01: ??? */ UNKNOWN()
	/* 0x02: ??? */ UNKNOWN()
	/* 0x03: ??? */ UNKNOWN()
	/* 0x04: ??? */ UNKNOWN()
	/* 0x05: ??? */ UNKNOWN()
	/* 0x06: ??? */ UNKNOWN()
	/* 0x07: ??? */ UNKNOWN()
	/* 0x08: ROUNDPS xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x09: ROUNDPD xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x0A: ROUNDSS xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x0B: ROUNDSD xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x0C: BLENDPS xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0D: BLENDPD xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0E: PBLENDW xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0F: PALIGNR ?mm1, ?mm2/m?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x10: ??? */ UNKNOWN()
	/* 0x11: ??? */ UNKNOWN()
	/* 0x12: ??? */ UNKNOWN()
	/* 0x13: ??? */ UNKNOWN()
	/* 0x14: PEXTRB reg/m8, xmm2, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_RM_R), WRITE(MODRM_R))
	/* 0x15: PEXTRW reg/m16, xmm2, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_RM_R), WRITE(MODRM_R))
	/* 0x16: PEXTRD/PEXTRQ reg/m?, xmm2, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_RM_R), WRITE(MODRM_R))
	/* 0x17: EXTRACTPS reg/m32, xmm2, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x18: ??? */ UNKNOWN()
	/* 0x19: ??? */ UNKNOWN()
	/* 0x1A: ??? */ UNKNOWN()
	/* 0x1B: ??? */ UNKNOWN()
	/* 0x1C: ??? */ UNKNOWN()
	/* 0x1D: ??? */ UNKNOWN()
	/* 0x1E: ??? */ UNKNOWN()
	/* 0x1F: ??? */ UNKNOWN()
	/* 0x20: PINSRB xmm1, r32/m8, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x21: INSERTPS xmm1, xmm2/m32, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x22: PINSRD/PINSRQ xmm1, r/m?, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x23: ??? */ UNKNOWN()
	/* 0x24: ??? */ UNKNOWN()
	/* 0x25: ??? */ UNKNOWN()
	/* 0x26: ??? */ UNKNOWN()
	/* 0x27: ??? */ UNKNOWN()
	/* 0x28: ??? */ UNKNOWN()
	/* 0x29: ??? */ UNKNOWN()
	/* 0x2A: ??? */ UNKNOWN()
	/* 0x2B: ??? */ UNKNOWN()
	/* 0x2C: ??? */ UNKNOWN()
	/* 0x2D: ??? */ UNKNOWN()
	/* 0x2E: ??? */ UNKNOWN()
	/* 0x2F: ??? */ UNKNOWN()
	/* 0x30: ??? */ UNKNOWN()
	/* 0x31: ??? */ UNKNOWN()
	/* 0x32: ??? */ UNKNOWN()
	/* 0x33: ??? */ UNKNOWN()
	/* 0x34: ??? */ UNKNOWN()
	/* 0x35: ??? */ UNKNOWN()
	/* 0x36: ??? */ UNKNOWN()
	/* 0x37: ??? */ UNKNOWN()
	/* 0x38: ??? */ UNKNOWN()
	/* 0x39: ??? */ UNKNOWN()
	/* 0x3A: ??? */ UNKNOWN()
	/* 0x3B: ??? */ UNKNOWN()
	/* 0x3C: ??? */ UNKNOWN()
	/* 0x3D: ??? */ UNKNOWN()
	/* 0x3E: ??? */ UNKNOWN()
	/* 0x3F: ??? */ UNKNOWN()
	/* 0x40: DPPS xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x41: DPPD xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x42: MPSADBW xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x43: ??? */ UNKNOWN()
	/* 0x44: ??? */ UNKNOWN()
	/* 0x45: ??? */ UNKNOWN()
	/* 0x46: ??? */ UNKNOWN()
	/* 0x47: ??? */ UNKNOWN()
	/* 0x48: ??? */ UNKNOWN()
	/* 0x49: ??? */ UNKNOWN()
	/* 0x4A: ??? */ UNKNOWN()
	/* 0x4B: ??? */ UNKNOWN()
	/* 0x4C: ??? */ UNKNOWN()
	/* 0x4D: ??? */ UNKNOWN()
	/* 0x4E: ??? */ UNKNOWN()
	/* 0x4F: ??? */ UNKNOWN()
	/* 0x50: ??? */ UNKNOWN()
	/* 0x51: ??? */ UNKNOWN()
	/* 0x52: ??? */ UNKNOWN()
	/* 0x53: ??? */ UNKNOWN()
	/* 0x54: ??? */ UNKNOWN()
	/* 0x55: ??? */ UNKNOWN()
	/* 0x56: ??? */ UNKNOWN()
	/* 0x57: ??? */ UNKNOWN()
	/* 0x58: ??? */ UNKNOWN()
	/* 0x59: ??? */ UNKNOWN()
	/* 0x5A: ??? */ UNKNOWN()
	/* 0x5B: ??? */ UNKNOWN()
	/* 0x5C: ??? */ UNKNOWN()
	/* 0x5D: ??? */ UNKNOWN()
	/* 0x5E: ??? */ UNKNOWN()
	/* 0x5F: ??? */ UNKNOWN()
	/* TODO: I'm not sure whether read/write flags of these 4 instructions are correct */
	/* 0x60: PCMPESTRM xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM | REG_AX | REG_DX), WRITE(REG_AX))
	/* 0x61: PCMPESTRI xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM | REG_AX | REG_CX | REG_DX), WRITE(REG_CX))
	/* 0x62: PCMPISTRM xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(REG_AX))
	/* 0x63: PCMPISTRI xmm1, xmm2/m128, imm8 */ INST(REQUIRE_0x66(), MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(REG_CX))
	/* 0x64: ??? */ UNKNOWN()
	/* 0x65: ??? */ UNKNOWN()
	/* 0x66: ??? */ UNKNOWN()
	/* 0x67: ??? */ UNKNOWN()
	/* 0x68: ??? */ UNKNOWN()
	/* 0x69: ??? */ UNKNOWN()
	/* 0x6A: ??? */ UNKNOWN()
	/* 0x6B: ??? */ UNKNOWN()
	/* 0x6C: ??? */ UNKNOWN()
	/* 0x6D: ??? */ UNKNOWN()
	/* 0x6E: ??? */ UNKNOWN()
	/* 0x6F: ??? */ UNKNOWN()
	/* 0x70: ??? */ UNKNOWN()
	/* 0x71: ??? */ UNKNOWN()
	/* 0x72: ??? */ UNKNOWN()
	/* 0x73: ??? */ UNKNOWN()
	/* 0x74: ??? */ UNKNOWN()
	/* 0x75: ??? */ UNKNOWN()
	/* 0x76: ??? */ UNKNOWN()
	/* 0x77: ??? */ UNKNOWN()
	/* 0x78: ??? */ UNKNOWN()
	/* 0x79: ??? */ UNKNOWN()
	/* 0x7A: ??? */ UNKNOWN()
	/* 0x7B: ??? */ UNKNOWN()
	/* 0x7C: ??? */ UNKNOWN()
	/* 0x7D: ??? */ UNKNOWN()
	/* 0x7E: ??? */ UNKNOWN()
	/* 0x7F: ??? */ UNKNOWN()
	/* 0x80: ??? */ UNKNOWN()
	/* 0x81: ??? */ UNKNOWN()
	/* 0x82: ??? */ UNKNOWN()
	/* 0x83: ??? */ UNKNOWN()
	/* 0x84: ??? */ UNKNOWN()
	/* 0x85: ??? */ UNKNOWN()
	/* 0x86: ??? */ UNKNOWN()
	/* 0x87: ??? */ UNKNOWN()
	/* 0x88: ??? */ UNKNOWN()
	/* 0x89: ??? */ UNKNOWN()
	/* 0x8A: ??? */ UNKNOWN()
	/* 0x8B: ??? */ UNKNOWN()
	/* 0x8C: ??? */ UNKNOWN()
	/* 0x8D: ??? */ UNKNOWN()
	/* 0x8E: ??? */ UNKNOWN()
	/* 0x8F: ??? */ UNKNOWN()
	/* 0x90: ??? */ UNKNOWN()
	/* 0x91: ??? */ UNKNOWN()
	/* 0x92: ??? */ UNKNOWN()
	/* 0x93: ??? */ UNKNOWN()
	/* 0x94: ??? */ UNKNOWN()
	/* 0x95: ??? */ UNKNOWN()
	/* 0x96: ??? */ UNKNOWN()
	/* 0x97: ??? */ UNKNOWN()
	/* 0x98: ??? */ UNKNOWN()
	/* 0x99: ??? */ UNKNOWN()
	/* 0x9A: ??? */ UNKNOWN()
	/* 0x9B: ??? */ UNKNOWN()
	/* 0x9C: ??? */ UNKNOWN()
	/* 0x9D: ??? */ UNKNOWN()
	/* 0x9E: ??? */ UNKNOWN()
	/* 0x9F: ??? */ UNKNOWN()
	/* 0xA0: ??? */ UNKNOWN()
	/* 0xA1: ??? */ UNKNOWN()
	/* 0xA2: ??? */ UNKNOWN()
	/* 0xA3: ??? */ UNKNOWN()
	/* 0xA4: ??? */ UNKNOWN()
	/* 0xA5: ??? */ UNKNOWN()
	/* 0xA6: ??? */ UNKNOWN()
	/* 0xA7: ??? */ UNKNOWN()
	/* 0xA8: ??? */ UNKNOWN()
	/* 0xA9: ??? */ UNKNOWN()
	/* 0xAA: ??? */ UNKNOWN()
	/* 0xAB: ??? */ UNKNOWN()
	/* 0xAC: ??? */ UNKNOWN()
	/* 0xAD: ??? */ UNKNOWN()
	/* 0xAE: ??? */ UNKNOWN()
	/* 0xAF: ??? */ UNKNOWN()
	/* 0xB0: ??? */ UNKNOWN()
	/* 0xB1: ??? */ UNKNOWN()
	/* 0xB2: ??? */ UNKNOWN()
	/* 0xB3: ??? */ UNKNOWN()
	/* 0xB4: ??? */ UNKNOWN()
	/* 0xB5: ??? */ UNKNOWN()
	/* 0xB6: ??? */ UNKNOWN()
	/* 0xB7: ??? */ UNKNOWN()
	/* 0xB8: ??? */ UNKNOWN()
	/* 0xB9: ??? */ UNKNOWN()
	/* 0xBA: ??? */ UNKNOWN()
	/* 0xBB: ??? */ UNKNOWN()
	/* 0xBC: ??? */ UNKNOWN()
	/* 0xBD: ??? */ UNKNOWN()
	/* 0xBE: ??? */ UNKNOWN()
	/* 0xBF: ??? */ UNKNOWN()
	/* 0xC0: ??? */ UNKNOWN()
	/* 0xC1: ??? */ UNKNOWN()
	/* 0xC2: ??? */ UNKNOWN()
	/* 0xC3: ??? */ UNKNOWN()
	/* 0xC4: ??? */ UNKNOWN()
	/* 0xC5: ??? */ UNKNOWN()
	/* 0xC6: ??? */ UNKNOWN()
	/* 0xC7: ??? */ UNKNOWN()
	/* 0xC8: ??? */ UNKNOWN()
	/* 0xC9: ??? */ UNKNOWN()
	/* 0xCA: ??? */ UNKNOWN()
	/* 0xCB: ??? */ UNKNOWN()
	/* 0xCC: ??? */ UNKNOWN()
	/* 0xCD: ??? */ UNKNOWN()
	/* 0xCE: ??? */ UNKNOWN()
	/* 0xCF: ??? */ UNKNOWN()
	/* 0xD0: ??? */ UNKNOWN()
	/* 0xD1: ??? */ UNKNOWN()
	/* 0xD2: ??? */ UNKNOWN()
	/* 0xD3: ??? */ UNKNOWN()
	/* 0xD4: ??? */ UNKNOWN()
	/* 0xD5: ??? */ UNKNOWN()
	/* 0xD6: ??? */ UNKNOWN()
	/* 0xD7: ??? */ UNKNOWN()
	/* 0xD8: ??? */ UNKNOWN()
	/* 0xD9: ??? */ UNKNOWN()
	/* 0xDA: ??? */ UNKNOWN()
	/* 0xDB: ??? */ UNKNOWN()
	/* 0xDC: ??? */ UNKNOWN()
	/* 0xDD: ??? */ UNKNOWN()
	/* 0xDE: ??? */ UNKNOWN()
	/* 0xDF: ??? */ UNKNOWN()
	/* 0xE0: ??? */ UNKNOWN()
	/* 0xE1: ??? */ UNKNOWN()
	/* 0xE2: ??? */ UNKNOWN()
	/* 0xE3: ??? */ UNKNOWN()
	/* 0xE4: ??? */ UNKNOWN()
	/* 0xE5: ??? */ UNKNOWN()
	/* 0xE6: ??? */ UNKNOWN()
	/* 0xE7: ??? */ UNKNOWN()
	/* 0xE8: ??? */ UNKNOWN()
	/* 0xE9: ??? */ UNKNOWN()
	/* 0xEA: ??? */ UNKNOWN()
	/* 0xEB: ??? */ UNKNOWN()
	/* 0xEC: ??? */ UNKNOWN()
	/* 0xED: ??? */ UNKNOWN()
	/* 0xEE: ??? */ UNKNOWN()
	/* 0xEF: ??? */ UNKNOWN()
	/* 0xF0: ??? */ UNKNOWN()
	/* 0xF1: ??? */ UNKNOWN()
	/* 0xF2: ??? */ UNKNOWN()
	/* 0xF3: ??? */ UNKNOWN()
	/* 0xF4: ??? */ UNKNOWN()
	/* 0xF5: ??? */ UNKNOWN()
	/* 0xF6: ??? */ UNKNOWN()
	/* 0xF7: ??? */ UNKNOWN()
	/* 0xF8: ??? */ UNKNOWN()
	/* 0xF9: ??? */ UNKNOWN()
	/* 0xFA: ??? */ UNKNOWN()
	/* 0xFB: ??? */ UNKNOWN()
	/* 0xFC: ??? */ UNKNOWN()
	/* 0xFD: ??? */ UNKNOWN()
	/* 0xFE: ??? */ UNKNOWN()
	/* 0xFF: ??? */ UNKNOWN()
};
