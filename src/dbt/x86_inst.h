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

#include <stdbool.h>
#include <stdint.h>

#define REG_AX		0x01 /* AL, AH, AX, EAX, RAX, R8* register */
#define REG_CX		0x02 /* CL, CH, CX, ECX, RCX, R9* register */
#define REG_DX		0x04 /* DL, DH, DX, EDX, RDX, R10* register */
#define REG_BX		0x08 /* BL, BH, BX, EBX, RBX, R11* register */
#define REG_SP		0x10 /* SPL, SP, ESP, RSP, R12* register */
#define REG_BP		0x20 /* BPL, BP, EBP, RBP, R13* register */
#define REG_SI		0x40 /* SIL, SI, ESI, RSI, R14* register */
#define REG_DI		0x80 /* DIL, DI, EDI, RDI, R15* register */
#define REG_MASK(r)	(1 << (r)) /* Generate a mask from a numeric register id */

/* Operand bit field */
/* Format: mttwbbbb
 * m: Whether this operand is from ModRM R/M field
 * tt: Register/memory usage
 * w: Register width (regular or vector)
 * bbbb: Bit set for possible register/memory sizes
 */
/* Patterns:
 * 00xxxxxx: Operand does not come from ModR/M byte, see below
 * 010wbbbb: Register from R field
 * 0110bbbb: Special register from R field
 * 0111xxxx: For future use
 * 1000bbbb: mm/m?? (?? < 64) from R/M field
 * 1001bbbb: xmm/m?? (?? < 128) from R/M field
 * 101wbbbb: Memory from R/M field
 * 110wbbbb: Register from R/M field
 * 111wbbbb: Register/memory from R/M field
 *
 * w values:
 * 0: Regular register size
 * 1: Vector register size
 */
#define Rxx		0b010'0'0000
#define SRxx	0b0110'0000
#define MMMxx	0b1000'0000
#define XMMMxx	0b1001'0000
#define Mxx		0b101'0'0000
#define RM_Rxx	0b110'0'0000
#define RMxx	0b111'0'0000

#define REGULAR		0b0'0000
#define VECTOR		0b1'0000

#define FROM_MODRM(op)		(((op) & 0b11'000000) > 0)
#define FROM_MODRM_R(op)	(((op) & 0b01'000000) > 0)
#define FROM_MODRM_RM(op)	(((op) & 0b1'0000000) > 0)

/* Bit pattern for regular register:
 * 0000: ??8  / al, cl, dl, bl, ...
 * 0xx1: ??16 / ax, cx, dx, bx, ...
 * 0x1x: ??32 / eax, ecx, edx, ebx, ...
 * 01xx: ??64 / rax, rcx, rdx, ebx, ...
 */

#define xx8		0b0000
#define xx16	0b0001
#define xx32	0b0010
#define xx64	0b0100

/* Bit pattern for vector register:
 * 0000: Size unknown
 * xxx1: vv64  / mm
 * xx1x: vv128 / xmm
 * x1xx: vv256 / ymm
 * 1xxx: vv512 / zmm
 */
#define vvUNK	0b0000
#define vv64	0b0001
#define vv128	0b0010
#define vv256	0b0100
#define vv512	0b1000

/* Register (via ModR/M r field) */
#define R8			(Rxx | REGULAR | xx8)
#define R16			(Rxx | REGULAR | xx16)
#define R32			(Rxx | REGULAR | xx32)
#define R16_32		(Rxx | REGULAR | xx16 | xx32)
#define R16_32_64	(Rxx | REGULAR | xx16 | xx32 | xx64)
#define R16_64		(Rxx | REGULAR | xx16 | xx64)
#define R32_64		(Rxx | REGULAR | xx32 | xx64)

/* Register (via ModR/M rm field */
#define RM_R8			(RM_Rxx | REGULAR | xx8)
#define RM_R16			(RM_Rxx | REGULAR | xx16)
#define RM_R32			(RM_Rxx | REGULAR | xx32)
#define RM_R16_32		(RM_Rxx | REGULAR | xx16 | xx32)
#define RM_R16_32_64	(RM_Rxx | REGULAR | xx16 | xx32 | xx64)
#define RM_R16_64		(RM_Rxx | REGULAR | xx16 | xx64)
#define RM_R32_64		(RM_Rxx | REGULAR | xx32 | xx64)

/* Register or memory (via ModR/M rm field and SIB) */
#define RM8			(RMxx | REGULAR | xx8)
#define RM16		(RMxx | REGULAR | xx16)
#define RM32		(RMxx | REGULAR | xx32)
#define RM16_32		(RMxx | REGULAR | xx16 | xx32)
#define RM16_32_64	(RMxx | REGULAR | xx32 | xx64)
#define RM16_64		(RMxx | REGULAR | xx16 | xx64)
#define RM32_64		(RMxx | REGULAR | xx32 | xx64)

/* Memory (via ModR/M rm field and SIB) */
#define M8			(Mxx | REGULAR | xx8)
#define M16			(Mxx | REGULAR | xx16)
#define M32			(Mxx | REGULAR | xx32)
#define M16_32		(Mxx | REGULAR | xx16 | xx32)
#define M16_32_64	(Mxx | REGULAR | xx16 | xx32 | xx64)
#define M16_64		(Mxx | REGULAR | xx16 | xx64)
#define M32_64		(Mxx | REGULAR | xx32 | xx64)
#define M64			(Mxx | REGULAR | xx64)
#define M			(Mxx | VECTOR | vvUNK)
#define M128		(Mxx | VECTOR | vv128)
#define M256		(Mxx | VECTOR | vv256)
#define M512		(Mxx | VECTOR | vv512)

/* Vector registers */
#define MM				(Rxx | VECTOR | vv64)
#define XMM				(Rxx | VECTOR | vv128)
#define MM_XMM			(Rxx | VECTOR | vv64 | vv128)

#define RM_MM			(RM_Rxx | VECTOR | vv64)
#define RM_XMM			(RM_Rxx | VECTOR | vv128)
#define RM_MM_XMM		(RM_Rxx | VECTOR | vv64 | vv128)

/* Vector register/memory */
#define MMM64			(RMxx | VECTOR | vv64)
#define XMMM128			(RMxx | VECTOR | vv128)
#define MMM64_XMMM128	(RMxx | VECTOR | vv64 | vv128)

/* Special r/m of vector registers */
#define MMM32		(RMxx | MMMxx | xx32)
#define XMMM16		(RMxx | XMMMxx | xx16)
#define XMMM32		(RMxx | XMMMxx | xx32)
#define XMMM64		(RMxx | XMMMxx | xx64)

/* Special registers
 * 000: Segment register (ES, CS, SS, DS, FS, GS)
 * 001 : Control register (CR0 - CR7)
 * 010 : Debug register (DR0 - DR7)
 */
#define SREG		(SRxx | 0b000)
#define CREG		(SRxx | 0b001)
#define DREG		(SRxx | 0b010)

/* 00xxxxxx: Operand does not come from ModR/M byte
 * 00xxxx: Implicit register / memory operand
 * 100iii: MOFFS
 * 101xxx: Implicit number immediate
 * 110iii: Immediate
 * 111iii: Relative address
 */
#define IMPLICIT	0b0'00000
#define MOFFS		0b100'000
#define NUM			0b101'000
#define IMMEDIATE	0b110'000
#define RELADDR		0b111'000

/* Implicit register / memory (Keep in sync with x86_inst.c) */
#define AL				(IMPLICIT | 0b00001)
#define AH				(IMPLICIT | 0b00010)
#define AX_EAX			(IMPLICIT | 0b00011)
#define AX_EAX_RAX		(IMPLICIT | 0b00100)
#define CL				(IMPLICIT | 0b00101)
#define DX				(IMPLICIT | 0b00110)
#define SI_M8			(IMPLICIT | 0b01010) /* DS:[(E)SI] (x86) or [RSI/ESI] (x64) */
#define SI_M16_32		(IMPLICIT | 0b01011) /* DS:[(E)SI] (x86) or [RSI/ESI] (x64) */
#define SI_M16_32_64	(IMPLICIT | 0b01100) /* DS:[(E)SI] (x86) or [RSI/ESI] (x64) */
#define DI_M8			(IMPLICIT | 0b01101) /* ES:[(E)DI] (x86) or [RDI/EDI] (x64) */
#define DI_M16_32		(IMPLICIT | 0b01110) /* ES:[(E)DI] (x86) or [RDI/EDI] (x64) */
#define DI_M16_32_64	(IMPLICIT | 0b01111) /* ES:[(E)DI] (x86) or [RDI/EDI] (x64) */

/* Register operand specified by last three bits of opcode */
#define OP_R8			(IMPLICIT | 0b11000)
#define OP_R16_32		(IMPLICIT | 0b11001)
#define OP_R16_32_64	(IMPLICIT | 0b11010)
#define OP_R16_64		(IMPLICIT | 0b11011)
#define OP_R32_64		(IMPLICIT | 0b11100)

/* Immediate values
 * 000: imm8
 * 001: imm16
 * 011: imm16/imm32
 * 111: imm16/imm32/imm64 (depends on address size prefix)
 */

/* Immediate */
#define IMM8		(IMMEDIATE | 0b001)
#define IMM16		(IMMEDIATE | 0b010)
#define IMM16_32	(IMMEDIATE | 0b011)
#define IMM16_32_64	(IMMEDIATE | 0b111)

/* Relative address */
#define REL8		(RELADDR | 0b001)
#define REL16_32	(RELADDR | 0b011)

/* 100iii: Direct memory offset */
#define MOFFS8			(MOFFS | 0b000)
#define MOFFS16_32_64	(MOFFS | 0b001)

/* Implicit immediate number */
#define NUM_0		(NUM | 0)
#define NUM_1		(NUM | 1)
#define NUM_2		(NUM | 2)
#define NUM_3		(NUM | 3)

/* Operand not exist */
#define __			0

struct instruction_desc
{
	union
	{
		size_t type; /* Type of this description */
		const char *mnemonic; /* Opcode mnemonic */
	};
	union
	{
		struct
		{
			uint8_t op1, op2, op3; /* Operands */
			uint8_t handler_type; /* Opcode handler type */
		};
		const struct instruction_desc *extension_table;
	};
};
/* Instruction types */
#define INST_TYPE_UNKNOWN		0	/* Unknown opcode */
#define INST_TYPE_UNSUPPORTED	1	/* Known opcode but unsupported yet */
#define INST_TYPE_INVALID		2	/* Known invalid opcode */
#define INST_TYPE_PREFIX		3	/* Prefix byte */
#define INST_TYPE_X87			4	/* X87 opcode */
#define INST_TYPE_MANDATORY		5	/* Distinguished by mandatory prefix (66, F2, F3) */
#define INST_TYPE_EXTENSION		6	/* Distinguished by ModR/M R field */
#define INST_TYPE_MODRM_MOD		7	/* Distinguished by ModR/M mod field (R or M) */
#define INST_TYPE_MAX			65535 /* <= 64K which will never be valid pointer */

/* Extended table indices for mandatory prefixes */
#define MANDATORY_NONE			0
#define MANDATORY_0x66			1
#define MANDATORY_0xF3			2
#define MANDATORY_0xF2			3

/* Extended table indices for mod */
#define MODRM_MOD_R				0
#define MODRM_MOD_M				1

/* Instruction handler types */
/* If the normal handler bit 00010000 is present.
 * The rest bits are treated as a mask indicating additional
 * registers used in the instruction, besides the registers
 * implied by the operands.
 * The value 0x10 is chosen carefully to be an alias to REG_SP,
 * because we always treat SP as not available.
 */
#define HANDLER_NORMAL			0x10
/* Other handler types */
#define HANDLER_PRIVILEGED		0x00
#define HANDLER_MOV_MOFFSET		0x01
#define HANDLER_CALL_DIRECT		0x02
#define HANDLER_CALL_INDIRECT	0x03
#define HANDLER_RET				0x04
#define HANDLER_RETN			0x05
#define HANDLER_JMP_DIRECT		0x06
#define HANDLER_JMP_INDIRECT	0x07
#define HANDLER_JCC				0x08
#define HANDLER_JCC_REL8		0x09
#define HANDLER_INT				0x0A
#define HANDLER_MOV_FROM_SEG	0x0B
#define HANDLER_MOV_TO_SEG		0x0C
#define HANDLER_CPUID			0x0D
#define HANDLER_X87				0x0E /* TODO */

const struct instruction_desc one_byte_inst[256];
const struct instruction_desc two_byte_inst[256];
const struct instruction_desc three_byte_inst_0x38[256];
const struct instruction_desc three_byte_inst_0x3A[256];

int get_imm_bytes(uint8_t op, bool opsize_prefix_present, bool addrsize_prefix_present);
uint8_t get_implicit_register_usage(uint8_t op, uint8_t opcode);
