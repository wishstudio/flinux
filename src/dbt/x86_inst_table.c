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

#include <dbt/x86_inst.h>

#define NORMAL(_mnemonic, _op1, _op2, _op3) \
	{ .mnemonic = _mnemonic, .op1 = _op1, .op2 = _op2, .op3 = _op3, .handler_type = HANDLER_NORMAL },
#define NORMAL_MOREREG(_mnemonic, _op1, _op2, _op3, _morereg) \
	{ .mnemonic = _mnemonic, .op1 = _op1, .op2 = _op2, .op3 = _op3, .handler_type = HANDLER_NORMAL | (_morereg) },
#define PRIVILEGED(_mnemonic, _op1, _op2, _op3) \
	{ .mnemonic = _mnemonic, .op1 = _op1, .op2 = _op2, .op3 = _op3, .handler_type = HANDLER_PRIVILEGED },
#define SPECIAL(_mnemonic, _op1, _op2, _op3, _handler) \
	{ .mnemonic = _mnemonic, .op1 = _op1, .op2 = _op2, .op3 = _op3, .handler_type = _handler },
#define UNKNOWN()							{ .type = INST_TYPE_UNKNOWN },
#define UNSUPPORTED()						{ .type = INST_TYPE_UNSUPPORTED },
#define INVALID()							{ .type = INST_TYPE_INVALID },
#define PREFIX()							{ .type = INST_TYPE_PREFIX },
#define MANDATORY(x)						{ .type = INST_TYPE_MANDATORY, .extension_table = mandatory_##x },
#define EXTENSION(x)						{ .type = INST_TYPE_EXTENSION, .extension_table = extension_##x },
#define MODRM_MOD(x)						{ .type = INST_TYPE_MODRM_MOD, .extension_table = modrm_mod_##x },

static const struct instruction_desc extension_C6[8] =
{
	/* 0 */ NORMAL("mov", RM8, IMM8, __)
	/* 1 */ UNKNOWN()
	/* 2 */ UNKNOWN()
	/* 3 */ UNKNOWN()
	/* 4 */ UNKNOWN()
	/* 5 */ UNKNOWN()
	/* 6 */ UNKNOWN()
	/* 7 */ UNKNOWN()
};

static const struct instruction_desc extension_C7[8] =
{
	/* 0 */ NORMAL("mov", RM16_32_64, IMM16_32, __)
	/* 1 */ UNKNOWN()
	/* 2 */ UNKNOWN()
	/* 3 */ UNKNOWN()
	/* 4 */ UNKNOWN()
	/* 5 */ UNKNOWN()
	/* 6 */ UNKNOWN()
	/* 7 */ UNKNOWN()
};

/* [GRP3]: 0/TEST, 2/NOT, 3/NEG, 4/MUL, 5/IMUL, 6/DIV, 7/IDIV */
static const struct instruction_desc extension_F6[8] =
{
	/* 0 */ NORMAL("test", RM8, IMM8, __)
	/* 1 */ NORMAL("test", RM8, IMM8, __) /* Not in intel documentation */
	/* 2 */ NORMAL("not", RM8, __, __)
	/* 3 */ NORMAL("neg", RM8, __, __)
	/* 4 */ NORMAL_MOREREG("mul", RM8, __, __, REG_AX)
	/* 5 */ NORMAL_MOREREG("imul", RM8, __, __, REG_AX)
	/* 6 */ NORMAL_MOREREG("div", RM8, __, __, REG_AX)
	/* 7 */ NORMAL_MOREREG("idiv", RM8, __, __, REG_AX)
};

static const struct instruction_desc extension_F7[8] =
{
	/* 0 */ NORMAL("test", RM16_32_64, IMM16_32, __)
	/* 1 */ NORMAL("test", RM16_32_64, IMM16_32, __) /* Not in intel documentation */
	/* 2 */ NORMAL("not", RM16_32_64, __, __)
	/* 3 */ NORMAL("neg", RM16_32_64, __, __)
	/* 4 */ NORMAL_MOREREG("mul", RM16_32_64, __, __, REG_AX | REG_DX)
	/* 5 */ NORMAL_MOREREG("imul", RM16_32_64, __, __, REG_AX | REG_DX)
	/* 6 */ NORMAL_MOREREG("div", RM16_32_64, __, __, REG_AX | REG_DX)
	/* 7 */ NORMAL_MOREREG("idiv", RM16_32_64, __, __, REG_AX | REG_DX)
};

static const struct instruction_desc extension_FE[8] =
{
	/* 0 */ NORMAL("inc", RM8, __, __)
	/* 1 */ NORMAL("dec", RM8, __, __)
	/* 2 */ UNKNOWN()
	/* 3 */ UNKNOWN()
	/* 4 */ UNKNOWN()
	/* 5 */ UNKNOWN()
	/* 6 */ UNKNOWN()
	/* 7 */ UNKNOWN()
};

static const struct instruction_desc extension_FF[8] =
{
	/* 0 */ NORMAL("inc", RM16_32_64, __, __)
	/* 1 */ NORMAL("dec", RM16_32_64, __, __)
	/* 2 */ SPECIAL("call", RM16_32_64, __, __, HANDLER_CALL_INDIRECT)
	/* 3 */ UNSUPPORTED() /* callf m16:16/32/64 */
	/* 4 */ SPECIAL("jmp", RM16_32_64, __, __, HANDLER_JMP_INDIRECT)
	/* 5 */ UNSUPPORTED() /* jmpf m16:16/32/64 */
#ifdef _WIN64
	/* 6 */ NORMAL("push", RM16_64, __, __)
#else
	/* 6 */ NORMAL("push", RM16_32, __, __)
#endif
	/* 7 */ UNKNOWN()
};

const struct instruction_desc one_byte_inst[256] =
{
	/* 0x00 */ NORMAL("add", RM8, R8, __)
	/* 0x01 */ NORMAL("add", RM16_32_64, R16_32_64, __)
	/* 0x02 */ NORMAL("add", R8, RM8, __)
	/* 0x03 */ NORMAL("add", R16_32_64, RM16_32_64, __)
	/* 0x04 */ NORMAL("add", AL, IMM8, __)
	/* 0x05 */ NORMAL("add", AX_EAX_RAX, IMM16_32, __)
#ifdef _WIN64
	/* 0x06 */ INVALID()
	/* 0x07 */ INVALID()
#else
	/* 0x06 */ UNSUPPORTED() /* PUSH ES */
	/* 0x07 */ UNSUPPORTED() /* POP ES */
#endif
	/* 0x08 */ NORMAL("or", RM8, R8, __)
	/* 0x09 */ NORMAL("or", RM16_32_64, R16_32_64, __)
	/* 0x0A */ NORMAL("or", R8, RM8, __)
	/* 0x0B */ NORMAL("or", R16_32_64, RM16_32_64, __)
	/* 0x0C */ NORMAL("or", AL, IMM8, __)
	/* 0x0D */ NORMAL("or", AX_EAX_RAX, IMM16_32, __)
#ifdef _WIN64
	/* 0x0E */ INVALID()
#else
	/* 0x0E */ UNSUPPORTED() /* PUSH CS */
#endif
	/* 0x0F */ INVALID() /* Two byte instruction */
	/* 0x10 */ NORMAL("adc", RM8, R8, __)
	/* 0x11 */ NORMAL("adc", RM16_32_64, R16_32_64, __)
	/* 0x12 */ NORMAL("adc", R8, RM8, __)
	/* 0x13 */ NORMAL("adc", R16_32_64, RM16_32_64, __)
	/* 0x14 */ NORMAL("adc", AL, IMM8, __)
	/* 0x15 */ NORMAL("adc", AX_EAX_RAX, IMM16_32, __)
#ifdef _WIN64
	/* 0x16 */ INVALID()
	/* 0x17 */ INVALID()
#else
	/* 0x16 */ UNSUPPORTED() /* PUSH SS */
	/* 0x17 */ UNSUPPORTED() /* POP SS */
#endif
	/* 0x18 */ NORMAL("sbb", RM8, R8, __)
	/* 0x19 */ NORMAL("sbb", RM16_32_64, R16_32_64, __)
	/* 0x1A */ NORMAL("sbb", R8, RM8, __)
	/* 0x1B */ NORMAL("sbb", R16_32_64, RM16_32_64, __)
	/* 0x1C */ NORMAL("sbb", AL, IMM8, __)
	/* 0x1D */ NORMAL("sbb", AX_EAX_RAX, IMM16_32, __)
#ifdef _WIN64
	/* 0x1E: INVALID */
	/* 0x1F: INVALID */
#else
	/* 0x1E */ UNSUPPORTED() /* PUSH DS */
	/* 0x1F */ UNSUPPORTED() /* POP DS */
#endif
	/* 0x20 */ NORMAL("and", RM8, R8, __)
	/* 0x21 */ NORMAL("and", RM16_32_64, R16_32_64, __)
	/* 0x22 */ NORMAL("and", R8, RM8, __)
	/* 0x23 */ NORMAL("and", R16_32_64, RM16_32_64, __)
	/* 0x24 */ NORMAL("and", AL, IMM8, __)
	/* 0x25 */ NORMAL("and", AX_EAX_RAX, IMM16_32, __)
#ifdef _WIN64
	/* 0x26 */ PREFIX() /* NULL prefix */
	/* 0x27 */ INVALID()
#else
	/* 0x26 */ PREFIX() /* ES segment prefix */
	/* 0x27 */ NORMAL("daa", AL, __, __)
#endif
	/* 0x28 */ NORMAL("sub", RM8, R8, __)
	/* 0x29 */ NORMAL("sub", RM16_32_64, R16_32_64, __)
	/* 0x2A */ NORMAL("sub", R8, RM8, __)
	/* 0x2B */ NORMAL("sub", R16_32_64, RM16_32_64, __)
	/* 0x2C */ NORMAL("sub", AL, IMM8, __)
	/* 0x2D */ NORMAL("sub", AX_EAX_RAX, IMM16_32, __)
#ifdef _WIN64
	/* 0x2E */ PREFIX() /* NULL prefix */
	/* 0x2F */ INVALID()
#else
	/* 0x2E */ PREFIX() /* CS segment prefix */
	/* 0x2F */ NORMAL("das", AL, __, __)
#endif
	/* 0x30 */ NORMAL("xor", RM8, R8, __)
	/* 0x31 */ NORMAL("xor", RM16_32_64, R16_32_64, __)
	/* 0x32 */ NORMAL("xor", R8, RM8, __)
	/* 0x33 */ NORMAL("xor", R16_32_64, RM16_32_64, __)
	/* 0x34 */ NORMAL("xor", AL, IMM8, __)
	/* 0x35 */ NORMAL("xor", AX_EAX_RAX, IMM16_32, __)
#ifdef _WIN64
	/* 0x36 */ PREFIX() /* NULL prefix */
	/* 0x37 */ INVALID()
#else
	/* 0x36 */ PREFIX() /* SS segment prefix */
	/* 0x37 */ NORMAL("aaa", AL, AH, __)
#endif
	/* 0x38 */ NORMAL("cmp", RM8, R8, __)
	/* 0x39 */ NORMAL("cmp", RM16_32_64, R16_32_64, __)
	/* 0x3A */ NORMAL("cmp", R8, RM8, __)
	/* 0x3B */ NORMAL("cmp", R16_32_64, RM16_32_64, __)
	/* 0x3C */ NORMAL("cmp", AL, IMM8, __)
	/* 0x3D */ NORMAL("cmp", AX_EAX_RAX, IMM16_32, __)
#ifdef _WIN64
	/* 0x3E */ PREFIX() /* NULL prefix */
	/* 0x3F */ INVALID()
#else
	/* 0x3E */ PREFIX() /* DS segment prefix */
	/* 0x3F */ NORMAL("aas", AL, AH, __)
#endif
#ifdef _WIN64
	/* 0x40 */ PREFIX() /* REX */
	/* 0x41 */ PREFIX() /* REX.B */
	/* 0x42 */ PREFIX() /* REX.X */
	/* 0x43 */ PREFIX() /* REX.XB */
	/* 0x44 */ PREFIX() /* REX.R */
	/* 0x45 */ PREFIX() /* REX.RB */
	/* 0x46 */ PREFIX() /* REX.RX */
	/* 0x47 */ PREFIX() /* REX.RXB */
	/* 0x48 */ PREFIX() /* REX.W */
	/* 0x49 */ PREFIX() /* REX.WB */
	/* 0x4A */ PREFIX() /* REX.WX */
	/* 0x4B */ PREFIX() /* REX.WXB */
	/* 0x4C */ PREFIX() /* REX.WR */
	/* 0x4D */ PREFIX() /* REX.WRB */
	/* 0x4E */ PREFIX() /* REX.WRX */
	/* 0x4F */ PREFIX() /* REX.WRXB */
#else
	/* 0x40 */ NORMAL("inc", OP_R16_32_64, __, __)
	/* 0x41 */ NORMAL("inc", OP_R16_32_64, __, __)
	/* 0x42 */ NORMAL("inc", OP_R16_32_64, __, __)
	/* 0x43 */ NORMAL("inc", OP_R16_32_64, __, __)
	/* 0x44 */ NORMAL("inc", OP_R16_32_64, __, __)
	/* 0x45 */ NORMAL("inc", OP_R16_32_64, __, __)
	/* 0x46 */ NORMAL("inc", OP_R16_32_64, __, __)
	/* 0x47 */ NORMAL("inc", OP_R16_32_64, __, __)
	/* 0x48 */ NORMAL("dec", OP_R16_32_64, __, __)
	/* 0x49 */ NORMAL("dec", OP_R16_32_64, __, __)
	/* 0x4A */ NORMAL("dec", OP_R16_32_64, __, __)
	/* 0x4B */ NORMAL("dec", OP_R16_32_64, __, __)
	/* 0x4C */ NORMAL("dec", OP_R16_32_64, __, __)
	/* 0x4D */ NORMAL("dec", OP_R16_32_64, __, __)
	/* 0x4E */ NORMAL("dec", OP_R16_32_64, __, __)
	/* 0x4F */ NORMAL("dec", OP_R16_32_64, __, __)
#endif
#ifdef _WIN64
	/* 0x50 */ NORMAL("push", OP_R16_64, __, __)
	/* 0x51 */ NORMAL("push", OP_R16_64, __, __)
	/* 0x52 */ NORMAL("push", OP_R16_64, __, __)
	/* 0x53 */ NORMAL("push", OP_R16_64, __, __)
	/* 0x54 */ NORMAL("push", OP_R16_64, __, __)
	/* 0x55 */ NORMAL("push", OP_R16_64, __, __)
	/* 0x56 */ NORMAL("push", OP_R16_64, __, __)
	/* 0x57 */ NORMAL("push", OP_R16_64, __, __)
	/* 0x58 */ NORMAL("pop", OP_R16_64, __, __)
	/* 0x59 */ NORMAL("pop", OP_R16_64, __, __)
	/* 0x5A */ NORMAL("pop", OP_R16_64, __, __)
	/* 0x5B */ NORMAL("pop", OP_R16_64, __, __)
	/* 0x5C */ NORMAL("pop", OP_R16_64, __, __)
	/* 0x5D */ NORMAL("pop", OP_R16_64, __, __)
	/* 0x5E */ NORMAL("pop", OP_R16_64, __, __)
	/* 0x5F */ NORMAL("pop", OP_R16_64, __, __)
#else
	/* 0x50 */ NORMAL("push", OP_R16_32, __, __)
	/* 0x51 */ NORMAL("push", OP_R16_32, __, __)
	/* 0x52 */ NORMAL("push", OP_R16_32, __, __)
	/* 0x53 */ NORMAL("push", OP_R16_32, __, __)
	/* 0x54 */ NORMAL("push", OP_R16_32, __, __)
	/* 0x55 */ NORMAL("push", OP_R16_32, __, __)
	/* 0x56 */ NORMAL("push", OP_R16_32, __, __)
	/* 0x57 */ NORMAL("push", OP_R16_32, __, __)
	/* 0x58 */ NORMAL("pop", OP_R16_32, __, __)
	/* 0x59 */ NORMAL("pop", OP_R16_32, __, __)
	/* 0x5A */ NORMAL("pop", OP_R16_32, __, __)
	/* 0x5B */ NORMAL("pop", OP_R16_32, __, __)
	/* 0x5C */ NORMAL("pop", OP_R16_32, __, __)
	/* 0x5D */ NORMAL("pop", OP_R16_32, __, __)
	/* 0x5E */ NORMAL("pop", OP_R16_32, __, __)
	/* 0x5F */ NORMAL("pop", OP_R16_32, __, __)
#endif
#ifdef _WIN64
	/* 0x60 */ INVALID()
	/* 0x61 */ INVALID()
	/* 0x62 */ INVALID()
	/* 0x63 */ NORMAL("movsxd", R32_64, RM32, __)
#else
	/* 0x60 */ NORMAL_MOREREG("pusha", __, __, __, REG_AX | REG_CX | REG_BX | REG_DX | REG_SP | REG_BP | REG_SI | REG_DI)
	/* 0x61 */ NORMAL_MOREREG("popa", __, __, __, REG_AX | REG_CX | REG_BX | REG_DX | REG_SP | REG_BP | REG_SI | REG_DI)
	/* 0x62 */ NORMAL("bound", R16_32, M16_32, __)
	/* 0x63 */ NORMAL("arpl", RM16, R16, __)
#endif
	/* 0x64 */ PREFIX() /* FS segment prefix */
	/* 0x65 */ PREFIX() /* GS segment prefix */
	/* 0x66 */ PREFIX() /* Operand size prefix */
	/* 0x67 */ PREFIX() /* Address size prefix */
	/* 0x68 */ NORMAL("push", IMM16_32, __, __)
	/* 0x69 */ NORMAL("imul", R16_32_64, RM16_32_64, IMM16_32)
	/* 0x6A */ NORMAL("push", IMM8, __, __)
	/* 0x6B */ NORMAL("imul", R16_32_64, RM16_32_64, IMM8)
	/* 0x6C */ PRIVILEGED("ins", DI_M8, DX, __)
	/* 0x6D */ PRIVILEGED("ins", DI_M16_32, DX, __)
	/* 0x6E */ PRIVILEGED("outs", SI_M8, DX, __)
	/* 0x6F */ PRIVILEGED("outs", SI_M16_32, DX, __)
	/* 0x70 */ SPECIAL("jo", REL8, __, __, HANDLER_JCC)
	/* 0x71 */ SPECIAL("jno", REL8, __, __, HANDLER_JCC)
	/* 0x72 */ SPECIAL("jb", REL8, __, __, HANDLER_JCC)
	/* 0x73 */ SPECIAL("jae", REL8, __, __, HANDLER_JCC)
	/* 0x74 */ SPECIAL("jz", REL8, __, __, HANDLER_JCC)
	/* 0x75 */ SPECIAL("jnz", REL8, __, __, HANDLER_JCC)
	/* 0x76 */ SPECIAL("jbe", REL8, __, __, HANDLER_JCC)
	/* 0x77 */ SPECIAL("ja", REL8, __, __, HANDLER_JCC)
	/* 0x78 */ SPECIAL("js", REL8, __, __, HANDLER_JCC)
	/* 0x79 */ SPECIAL("jns", REL8, __, __, HANDLER_JCC)
	/* 0x7A */ SPECIAL("jp", REL8, __, __, HANDLER_JCC)
	/* 0x7B */ SPECIAL("jnp", REL8, __, __, HANDLER_JCC)
	/* 0x7C */ SPECIAL("jl", REL8, __, __, HANDLER_JCC)
	/* 0x7D */ SPECIAL("jge", REL8, __, __, HANDLER_JCC)
	/* 0x7E */ SPECIAL("jle", REL8, __, __, HANDLER_JCC)
	/* 0x7F */ SPECIAL("jg", REL8, __, __, HANDLER_JCC)
	/* [GRP1]: 0/ADD, 1/OR, 2/ADC, 3/SBB, 4/AND, 5/SUB, 6/XOR, 7/CMP */
	/* 0x80 */ NORMAL("[GRP1]", RM8, IMM8, __)
	/* 0x81 */ NORMAL("[GRP1]", RM16_32_64, IMM16_32, __)
#ifdef _WIN64
	/* 0x82 */ INVALID()
#else
	/* 0x82 */ NORMAL("[GRP1]", RM8, IMM8, __) /* SAME AS 0x80? */
#endif
	/* 0x83 */ NORMAL("[GRP1]", RM16_32_64, IMM8, __)
	/* 0x84 */ NORMAL("test", RM8, R8, __)
	/* 0x85 */ NORMAL("test", RM16_32_64, R16_32_64, __)
	/* 0x86 */ NORMAL("xchg", R8, RM8, __)
	/* 0x87 */ NORMAL("xchg", R16_32_64, RM16_32_64, __)
	/* 0x88 */ NORMAL("mov", RM8, R8, __)
	/* 0x89 */ NORMAL("mov", RM16_32_64, R16_32_64, __)
	/* 0x8A */ NORMAL("mov", R8, RM8, __)
	/* 0x8B */ NORMAL("mov", R16_32_64, RM16_32_64, __)
	/* 0x8C */ SPECIAL("mov", RM16_64, SREG, __, HANDLER_MOV_FROM_SEG)
	/* 0x8D */ NORMAL("lea", R16_32_64, M, __)
	/* 0x8E */ SPECIAL("mov", SREG, RM16_64, __, HANDLER_MOV_TO_SEG)
#ifdef _WIN64
	/* 0x8F */ NORMAL("pop", RM16_64, __, __)
#else
	/* 0x8F */ NORMAL("pop", RM16_32, __, __)
#endif
	/* 0x90 */ NORMAL("nop", __, __, __) /* Note: this isn't the same as "xchg eax, eax" */
										 /* TODO: 0xF3, 0x90 is "PAUSE" */
	/* 0x91 */ NORMAL("xchg", AX_EAX_RAX, OP_R16_32_64, __)
	/* 0x92 */ NORMAL("xchg", AX_EAX_RAX, OP_R16_32_64, __)
	/* 0x93 */ NORMAL("xchg", AX_EAX_RAX, OP_R16_32_64, __)
	/* 0x94 */ NORMAL("xchg", AX_EAX_RAX, OP_R16_32_64, __)
	/* 0x95 */ NORMAL("xchg", AX_EAX_RAX, OP_R16_32_64, __)
	/* 0x96 */ NORMAL("xchg", AX_EAX_RAX, OP_R16_32_64, __)
	/* 0x97 */ NORMAL("xchg", AX_EAX_RAX, OP_R16_32_64, __)
	/* 0x98 */ NORMAL("cbw/cwde/cdqe", __, __, __)
	/* 0x99 */ NORMAL("cwd/cdq/cqo", __, __, __)
#ifdef _WIN64
	/* 0x9A: INVALID */ INVALID()
#else
	/* 0x9A */ UNSUPPORTED() /* CALL FAR ptr16:? */
#endif
	/* 0x9B */ NORMAL("fwait", __, __, __)
	/* 0x9C */ NORMAL("pushf/pushfd/pushfq", __, __, __)
	/* 0x9D */ NORMAL("popfd/popfd/popfq", __, __, __)
#ifdef _WIN64
	/* 0x9E */ INVALID()
	/* 0x9F */ INVALID()
#else
	/* 0x9E */ NORMAL("sahf", __, __, __)
	/* 0x9F */ NORMAL("lahf", __, __, __)
#endif
	/* 0xA0 */ SPECIAL("mov", AL, MOFFS8, __, HANDLER_MOV_MOFFSET)
	/* 0xA1 */ SPECIAL("mov", AX_EAX_RAX, MOFFS16_32_64, __, HANDLER_MOV_MOFFSET)
	/* 0xA2 */ SPECIAL("mov", MOFFS8, AL, __, HANDLER_MOV_MOFFSET)
	/* 0xA3 */ SPECIAL("mov", MOFFS16_32_64, AX_EAX_RAX, __, HANDLER_MOV_MOFFSET)
	/* 0xA4 */ NORMAL("movs", DI_M8, SI_M8, __)
	/* 0xA5 */ NORMAL("movs", DI_M16_32_64, SI_M16_32_64, __)
	/* 0xA6 */ NORMAL("cmps", DI_M8, SI_M8, __)
	/* 0xA7 */ NORMAL("cmps", DI_M16_32_64, SI_M16_32_64, __)
	/* 0xA8 */ NORMAL("test", AL, IMM8, __)
	/* 0xA9 */ NORMAL("test", AX_EAX_RAX, IMM16_32, __)
	/* 0xAA */ NORMAL("stos", DI_M8, AL, __)
	/* 0xAB */ NORMAL("stos", DI_M16_32_64, AX_EAX_RAX, __)
	/* 0xAC */ NORMAL("lods", AL, SI_M8, __)
	/* 0xAD */ NORMAL("lods", AX_EAX_RAX, SI_M16_32_64, __)
	/* 0xAE */ NORMAL("scas", DI_M8, AL, __)
	/* 0xAF */ NORMAL("scas", DI_M16_32_64, AX_EAX_RAX, __)
	/* 0xB0 */ NORMAL("mov", OP_R8, IMM8, __)
	/* 0xB1 */ NORMAL("mov", OP_R8, IMM8, __)
	/* 0xB2 */ NORMAL("mov", OP_R8, IMM8, __)
	/* 0xB3 */ NORMAL("mov", OP_R8, IMM8, __)
	/* 0xB4 */ NORMAL("mov", OP_R8, IMM8, __)
	/* 0xB5 */ NORMAL("mov", OP_R8, IMM8, __)
	/* 0xB6 */ NORMAL("mov", OP_R8, IMM8, __)
	/* 0xB7 */ NORMAL("mov", OP_R8, IMM8, __)
	/* 0xB8 */ NORMAL("mov", OP_R16_32_64, IMM16_32_64, __)
	/* 0xB9 */ NORMAL("mov", OP_R16_32_64, IMM16_32_64, __)
	/* 0xBA */ NORMAL("mov", OP_R16_32_64, IMM16_32_64, __)
	/* 0xBB */ NORMAL("mov", OP_R16_32_64, IMM16_32_64, __)
	/* 0xBC */ NORMAL("mov", OP_R16_32_64, IMM16_32_64, __)
	/* 0xBD */ NORMAL("mov", OP_R16_32_64, IMM16_32_64, __)
	/* 0xBE */ NORMAL("mov", OP_R16_32_64, IMM16_32_64, __)
	/* 0xBF */ NORMAL("mov", OP_R16_32_64, IMM16_32_64, __)
	/* [GRP2]: 0/ROL, 1/ROR, 2/RCL, 3/RCR, 4/SHL/SAL, 5/SHR, 6/SHL/SAL 7/SAR */
	/* 0xC0 */ NORMAL("[GRP2]", RM8, IMM8, __)
	/* 0xC1 */ NORMAL("[GRP2]", RM16_32_64, IMM8, __)
	/* 0xC2 */ SPECIAL("retn", IMM16, __, __, HANDLER_RETN)
	/* 0xC3 */ SPECIAL("ret", IMM16, __, __, HANDLER_RET)
#ifdef _WIN64
	/* 0xC4: INVALID */ INVALID()
	/* 0xC5: INVALID */ INVALID()
#else
	/* 0xC4 */ UNSUPPORTED() /* LES r?, m16:? */
	/* 0xC5 */ UNSUPPORTED() /* LDS r?, m16:? */
#endif
	/* 0xC6 */ EXTENSION(C6)
	/* 0xC7 */ EXTENSION(C7)
	/* 0xC8 */ UNSUPPORTED() /* ENTER */
	/* 0xC9 */ NORMAL_MOREREG("leave", __, __, __, REG_BP)
	/* 0xCA */ UNSUPPORTED() /* RETF imm16 */
	/* 0xCB */ UNSUPPORTED() /* RETF */
	/* 0xCC */ NORMAL("int", NUM_3, __, __)
	/* 0xCD */ SPECIAL("int", IMM8, __, __, HANDLER_INT)
#ifdef _WIN64
	/* 0xCE */ INVALID()
#else
	/* 0xCE */ NORMAL("into", __, __, __)
#endif
	/* 0xCF */ UNSUPPORTED() /* IRET/IRETD/IRETQ */
	/* 0xD0 */ NORMAL("[GRP2]", RM8, NUM_1, __)
	/* 0xD1 */ NORMAL("[GRP2]", RM16_32_64, NUM_1, __)
	/* 0xD2 */ NORMAL("[GRP2]", RM8, CL, __)
	/* 0xD3 */ NORMAL("[GRP2]", RM16_32_64, CL, __)
#ifdef _WIN64
	/* 0xD4 */ INVALID()
	/* 0xD5 */ INVALID()
#else
	/* 0xD4 */ NORMAL("aam", AL, AH, IMM8)
	/* 0xD5 */ NORMAL("aad", AL, AH, IMM8)
#endif
	/* 0xD6 */ NORMAL("salc", AL, __, __) /* Only for AMD */
	/* 0xD7 */ UNSUPPORTED() /* XLAT AL, DS:[EBX + AL] */
	/* 0xD8: (x87 escape) */ SPECIAL("(x87)", __, __, __, HANDLER_X87)
	/* 0xD9: (x87 escape) */ SPECIAL("(x87)", __, __, __, HANDLER_X87)
	/* 0xDA: (x87 escape) */ SPECIAL("(x87)", __, __, __, HANDLER_X87)
	/* 0xDB: (x87 escape) */ SPECIAL("(x87)", __, __, __, HANDLER_X87)
	/* 0xDC: (x87 escape) */ SPECIAL("(x87)", __, __, __, HANDLER_X87)
	/* 0xDD: (x87 escape) */ SPECIAL("(x87)", __, __, __, HANDLER_X87)
	/* 0xDE: (x87 escape) */ SPECIAL("(x87)", __, __, __, HANDLER_X87)
	/* 0xDF: (x87 escape) */ SPECIAL("(x87)", __, __, __, HANDLER_X87)
	/* 0xE0 */ SPECIAL("loopnz", REL8, __, __, HANDLER_JCC_REL8)
	/* 0xE1 */ SPECIAL("loopz", REL8, __, __, HANDLER_JCC_REL8)
	/* 0xE2 */ SPECIAL("loop", REL8, __, __, HANDLER_JCC_REL8)
	/* 0xE3 */ SPECIAL("jcxz", REL8, __, __, HANDLER_JCC_REL8)
	/* 0xE4 */ PRIVILEGED("in", AL, IMM8, __)
	/* 0xE5 */ PRIVILEGED("in", AX_EAX, IMM8, __)
	/* 0xE6 */ PRIVILEGED("out", IMM8, AL, __)
	/* 0xE7 */ PRIVILEGED("out", IMM8, AX_EAX, __)
	/* 0xE8 */ SPECIAL("call", REL16_32, __, __, HANDLER_CALL_DIRECT)
	/* 0xE9 */ SPECIAL("jmp", REL16_32, __, __, HANDLER_JMP_DIRECT)
#ifdef _WIN64
	/* 0xEA */ INVALID()
#else
	/* 0xEA */ INVALID() /* JMPF ptr16:? */
#endif
	/* 0xEB */ SPECIAL("jmp", REL8, __, __, HANDLER_JMP_DIRECT)
	/* 0xEC */ PRIVILEGED("in", AL, DX, __)
	/* 0xED */ PRIVILEGED("in", AX_EAX, DX, __)
	/* 0xEE */ PRIVILEGED("out", DX, AL, __)
	/* 0xEF */ PRIVILEGED("out", DX, AX_EAX, __)
	/* 0xF0 */ INVALID() /* LOCK prefix */
	/* 0xF1 */ NORMAL("int", NUM_1, __, __) /* Only for AMD */
	/* 0xF2 */ PREFIX() /* Scalar double-precision prefix / repeat string operation prefix */
	/* 0xF3 */ PREFIX() /* Scalar single-precision prefix / repeat string operation prefix */
	/* 0xF4 */ PRIVILEGED("hlt", __, __, __)
	/* 0xF5 */ NORMAL("cmc", __, __, __)
	/* 0xF6 */ EXTENSION(F6)
	/* 0xF7 */ EXTENSION(F7)
	/* 0xF8 */ NORMAL("clc", __, __, __)
	/* 0xF9 */ NORMAL("stc", __, __, __)
	/* 0xFA */ NORMAL("cli", __, __, __)
	/* 0xFB */ NORMAL("sti", __, __, __)
	/* 0xFC */ NORMAL("cld", __, __, __)
	/* 0xFD */ NORMAL("std", __, __, __)
	/* 0xFE */ EXTENSION(FE)
	/* 0xFF */ EXTENSION(FF)
};

static const struct instruction_desc extension_0F0D[8] =
{
	/* 0 */ NORMAL("nop", RM16_32, __, __)
	/* 1 */ NORMAL("prefetchw", M8, __, __)
	/* 2 */ NORMAL("prefetchwt1", M8, __, __)
	/* 3 */ NORMAL("nop", RM16_32, __, __)
	/* 4 */ NORMAL("nop", RM16_32, __, __)
	/* 5 */ NORMAL("nop", RM16_32, __, __)
	/* 6 */ NORMAL("nop", RM16_32, __, __)
	/* 7 */ NORMAL("nop", RM16_32, __, __)
};

static const struct instruction_desc mandatory_0F10[4] =
{
	/* 00 */ NORMAL("movups", XMM, XMMM128, __)
	/* 66 */ NORMAL("movupd", XMM, XMMM128, __)
	/* F3 */ NORMAL("movss", XMM, XMMM32, __)
	/* F2 */ NORMAL("movsd", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F11[4] =
{
	/* 00 */ NORMAL("movups", XMMM128, XMM, __)
	/* 66 */ NORMAL("movupd", XMMM128, XMM, __)
	/* F3 */ NORMAL("movss", XMMM32, XMM, __)
	/* F2 */ NORMAL("movsd", XMMM64, XMM, __)
};

static const struct instruction_desc mandatory_0F12[4] =
{
	/* 00 */ NORMAL("mov(h)lps", XMM, XMMM64, __) /* MOVLPS xmm, m64; MOVHLPS xmm1, xmm2 */
	/* 66 */ NORMAL("movlpd", XMM, M64, __)
	/* F3 */ NORMAL("movsldup", XMM, XMMM128, __)
	/* F2 */ NORMAL("movddup", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F13[4] =
{
	/* 00 */ NORMAL("movlps", M64, XMM, __)
	/* 66 */ NORMAL("movlpd", M64, XMM, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F14[4] =
{
	/* 00 */ NORMAL("unpcklps", XMM, XMMM128, __)
	/* 66 */ NORMAL("unpcklpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F15[4] =
{
	/* 00 */ NORMAL("unpckhps", XMM, XMMM128, __)
	/* 66 */ NORMAL("unpckhpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F16[4] =
{
	/* 00 */ NORMAL("mov(l)hps", XMM, XMMM64, __) /* MOVHPS xmm, m64; MOVLHPS xmm1, xmm2 */
	/* 66 */ NORMAL("movhpd", XMM, M64, __)
	/* F3 */ NORMAL("movshdup", XMM, XMMM128, __)
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F17[4] =
{
	/* 00 */ NORMAL("movhps", M64, XMM, __)
	/* 66 */ NORMAL("movhpd", M64, XMM, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc extension_0F18[8] =
{
	/* 0 */ NORMAL("prefetchnta", M8, __, __)
	/* 1 */ NORMAL("prefetcht0", M8, __, __)
	/* 2 */ NORMAL("prefetcht1", M8, __, __)
	/* 3 */ NORMAL("prefetcht2", M8, __, __)
	/* 4 */ NORMAL("nop", RM16_32, __, __)
	/* 5 */ NORMAL("nop", RM16_32, __, __)
	/* 6 */ NORMAL("nop", RM16_32, __, __)
	/* 7 */ NORMAL("nop", RM16_32, __, __)
};

static const struct instruction_desc mandatory_0F28[4] =
{
	/* 00 */ NORMAL("movaps", XMM, XMMM128, __)
	/* 66 */ NORMAL("movapd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F29[4] =
{
	/* 00 */ NORMAL("movaps", XMMM128, XMM, __)
	/* 66 */ NORMAL("movapd", XMMM128, XMM, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F2A[4] =
{
	/* 00 */ NORMAL("cvtpi2ps", XMM, MMM64, __)
	/* 66 */ NORMAL("cvtpi2pd", XMM, MMM64, __)
	/* F3 */ NORMAL("cvtsi2ss", XMM, RM32_64, __)
	/* F2 */ NORMAL("cvtsi2sd", XMM, RM32_64, __)
};

static const struct instruction_desc mandatory_0F2B[4] =
{
	/* 00 */ NORMAL("movntps", M128, XMM, __)
	/* 66 */ NORMAL("movntpd", M128, XMM, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F2C[4] =
{
	/* 00 */ NORMAL("cvttps2pi", MM, XMMM64, __)
	/* 66 */ NORMAL("cvttpd2pi", MM, XMMM128, __)
	/* F3 */ NORMAL("cvttss2si", R32_64, XMMM32, __)
	/* F2 */ NORMAL("cvttsd2si", R32_64, XMMM64, __)
};

static const struct instruction_desc mandatory_0F2D[4] =
{
	/* 00 */ NORMAL("cvtps2pi", MM, XMMM64, __)
	/* 66 */ NORMAL("cvtpd2pi", MM, XMMM128, __)
	/* F3 */ NORMAL("cvtss2si", R32_64, XMMM32, __)
	/* F2 */ NORMAL("cvtsd2si", R32_64, XMMM64, __)
};

static const struct instruction_desc mandatory_0F2E[4] =
{
	/* 00 */ NORMAL("ucomiss", XMM, XMMM32, __)
	/* 66 */ NORMAL("ucomisd", XMM, XMMM64, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F2F[4] =
{
	/* 00 */ NORMAL("comiss", XMM, XMMM32, __)
	/* 66 */ NORMAL("comisd", XMM, XMMM64, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F50[4] =
{
	/* 00 */ NORMAL("movmskps", R32_64, RM_XMM, __)
	/* 66 */ NORMAL("movmskpd", R32_64, RM_XMM, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F51[4] =
{
	/* 00 */ NORMAL("sqrtps", XMM, XMMM128, __)
	/* 66 */ NORMAL("sqrtpd", XMM, XMMM128, __)
	/* F3 */ NORMAL("sqrtss", XMM, XMMM32, __)
	/* F2 */ NORMAL("sqrtsd", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F52[4] =
{
	/* 00 */ NORMAL("rsqrtps", XMM, XMMM128, __)
	/* 66 */ UNKNOWN()
	/* F3 */ NORMAL("rsqrtss", XMM, XMMM32, __)
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F53[4] =
{
	/* 00 */ NORMAL("rcpps", XMM, XMMM128, __)
	/* 66 */ UNKNOWN()
	/* F3 */ NORMAL("rcpss", XMM, XMMM32, __)
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F54[4] =
{
	/* 00 */ NORMAL("andps", XMM, XMMM128, __)
	/* 66 */ NORMAL("andpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F55[4] =
{
	/* 00 */ NORMAL("andnps", XMM, XMMM128, __)
	/* 66 */ NORMAL("andnpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F56[4] =
{
	/* 00 */ NORMAL("orps", XMM, XMMM128, __)
	/* 66 */ NORMAL("orpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F57[4] =
{
	/* 00 */ NORMAL("xorps", XMM, XMMM128, __)
	/* 66 */ NORMAL("xorpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F58[4] =
{
	/* 00 */ NORMAL("addps", XMM, XMMM128, __)
	/* 66 */ NORMAL("addpd", XMM, XMMM128, __)
	/* F3 */ NORMAL("addss", XMM, XMMM32, __)
	/* F2 */ NORMAL("addsd", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F59[4] =
{
	/* 00 */ NORMAL("mulps", XMM, XMMM128, __)
	/* 66 */ NORMAL("mulpd", XMM, XMMM128, __)
	/* F3 */ NORMAL("mulss", XMM, XMMM32, __)
	/* F2 */ NORMAL("mulsd", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F5A[4] =
{
	/* 00 */ NORMAL("cvtps2pd", XMM, XMMM128, __)
	/* 66 */ NORMAL("cvtpd2ps", XMM, XMMM128, __)
	/* F3 */ NORMAL("cvtss2sd", XMM, XMMM32, __)
	/* F2 */ NORMAL("cvtsd2ss", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F5B[4] =
{
	/* 00 */ NORMAL("cvtdq2ps", XMM, XMMM128, __)
	/* 66 */ NORMAL("cvtps2dq", XMM, XMMM128, __)
	/* F3 */ NORMAL("cvttps2dq", XMM, XMMM128, __)
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F5C[4] =
{
	/* 00 */ NORMAL("subps", XMM, XMMM128, __)
	/* 66 */ NORMAL("subpd", XMM, XMMM128, __)
	/* F3 */ NORMAL("subss", XMM, XMMM32, __)
	/* F2 */ NORMAL("subsd", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F5D[4] =
{
	/* 00 */ NORMAL("minps", XMM, XMMM128, __)
	/* 66 */ NORMAL("minpd", XMM, XMMM128, __)
	/* F3 */ NORMAL("minss", XMM, XMMM32, __)
	/* F2 */ NORMAL("minsd", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F5E[4] =
{
	/* 00 */ NORMAL("divps", XMM, XMMM128, __)
	/* 66 */ NORMAL("divpd", XMM, XMMM128, __)
	/* F3 */ NORMAL("divss", XMM, XMMM32, __)
	/* F2 */ NORMAL("divsd", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F5F[4] =
{
	/* 00 */ NORMAL("maxps", XMM, XMMM128, __)
	/* 66 */ NORMAL("maxpd", XMM, XMMM128, __)
	/* F3 */ NORMAL("maxss", XMM, XMMM32, __)
	/* F2 */ NORMAL("maxsd", XMM, XMMM64, __)
};

static const struct instruction_desc mandatory_0F60[4] =
{
	/* 00 */ NORMAL("punpcklbw", MM, MMM32, __)
	/* 66 */ NORMAL("punpcklbw", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F61[4] =
{
	/* 00 */ NORMAL("punpcklwd", MM, MMM32, __)
	/* 66 */ NORMAL("punpcklwd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F62[4] =
{
	/* 00 */ NORMAL("punpckldq", MM, MMM32, __)
	/* 66 */ NORMAL("punpckldq", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F6F[4] =
{
	/* 00 */ NORMAL("movq", MM, MMM64, __)
	/* 66 */ NORMAL("movdqa", XMM, XMMM128, __)
	/* F3 */ NORMAL("movdqu", XMM, XMMM128, __)
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F70[4] =
{
	/* 00 */ NORMAL("pshufw", MM, MMM64, IMM8)
	/* 66 */ NORMAL("pshufd", XMM, XMMM128, IMM8)
	/* F3 */ NORMAL("pshufhw", XMM, XMMM128, IMM8)
	/* F2 */ NORMAL("pshuflw", XMM, XMMM128, IMM8)
};

static const struct instruction_desc extension_0F71[8] =
{
	/* 0 */ UNKNOWN()
	/* 1 */ UNKNOWN()
	/* 2 */ NORMAL("psrlw", RM_MM_XMM, IMM8, __)
	/* 3 */ UNKNOWN()
	/* 4 */ NORMAL("psraw", RM_MM_XMM, IMM8, __)
	/* 5 */ UNKNOWN()
	/* 6 */ NORMAL("psllw", RM_MM_XMM, IMM8, __)
	/* 7 */ UNKNOWN()
};

static const struct instruction_desc extension_0F72[8] =
{
	/* 0 */ UNKNOWN()
	/* 1 */ UNKNOWN()
	/* 2 */ NORMAL("psrld", RM_MM_XMM, IMM8, __)
	/* 3 */ UNKNOWN()
	/* 4 */ NORMAL("psrad", RM_MM_XMM, IMM8, __)
	/* 5 */ UNKNOWN()
	/* 6 */ NORMAL("pslld", RM_MM_XMM, IMM8, __)
	/* 7 */ UNKNOWN()
};

static const struct instruction_desc extension_0F73[8] =
{
	/* 0 */ UNKNOWN()
	/* 1 */ UNKNOWN()
	/* 2 */ NORMAL("psrlq", RM_MM_XMM, IMM8, __)
	/* 3 */ NORMAL("psrldq", RM_XMM, IMM8, __)
	/* 4 */ UNKNOWN()
	/* 5 */ UNKNOWN()
	/* 6 */ NORMAL("psllq", RM_MM_XMM, IMM8, __)
	/* 7 */ NORMAL("pslldq", RM_XMM, IMM8, __)
};

static const struct instruction_desc mandatory_0F7C[4] =
{
	/* 00 */ UNKNOWN()
	/* 66 */ NORMAL("haddpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ NORMAL("haddps", XMM, XMMM128, __)
};

static const struct instruction_desc mandatory_0F7D[4] =
{
	/* 00 */ UNKNOWN()
	/* 66 */ NORMAL("hsubpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ NORMAL("hsubps", XMM, XMMM128, __)
};

static const struct instruction_desc mandatory_0F7E[4] =
{
	/* 00 */ NORMAL("movd", RM32_64, MM, __) /* movq for r/m64 */
	/* 66 */ NORMAL("movd", RM32_64, XMM, __) /* movq for r/m64 */
	/* F3 */ NORMAL("movq", XMM, XMMM64, __)
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F7F[4] =
{
	/* 00 */ NORMAL("movq", MMM64, MM, __)
	/* 66 */ NORMAL("movdqa", XMMM128, XMM, __)
	/* F3 */ NORMAL("movdqu", XMMM128, XMM, __)
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc modrm_mod_0FAE_5[2] =
{
	/* R */ NORMAL("lfence", __, __, __)
	/* M */ NORMAL_MOREREG("xrstor", M, __, __, REG_AX | REG_DX)
};

static const struct instruction_desc modrm_mod_0FAE_6[2] =
{
	/* R */ NORMAL("mfence", __, __, __)
	/* M */ NORMAL_MOREREG("xsaveopt", M, __, __, REG_AX | REG_DX)
};

static const struct instruction_desc modrm_mod_0FAE_7[2] =
{
	/* R */ NORMAL("sfence", __, __, __)
	/* M */ NORMAL("clflush", M8, __, __)
};

static const struct instruction_desc extension_0FAE[8] =
{
	/* 0 */ NORMAL("fsave", M512, __, __)
	/* 1 */ NORMAL("fxrstor", M512, __, __)
	/* 2 */ NORMAL("ldmxcsr", M32, __, __)
	/* 3 */ NORMAL("stmxcsr", M32, __, __)
	/* 4 */ NORMAL_MOREREG("xsave", M, __, __, REG_AX | REG_DX)
	/* 5 */ MODRM_MOD(0FAE_5)
	/* 6 */ MODRM_MOD(0FAE_6)
	/* 7 */ MODRM_MOD(0FAE_7)
};

static const struct instruction_desc mandatory_0FB8[4] =
{
	/* 00 */ UNKNOWN()
	/* 66 */ UNKNOWN()
	/* F3 */ NORMAL("popcnt", R16_32_64, RM16_32_64, __)
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc extension_0FBA[8] =
{
	/* 0 */ UNKNOWN()
	/* 1 */ UNKNOWN()
	/* 2 */ UNKNOWN()
	/* 3 */ UNKNOWN()
	/* 4 */ NORMAL("bt", RM16_32_64, IMM8, __)
	/* 5 */ NORMAL("bts", RM16_32_64, IMM8, __)
	/* 6 */ NORMAL("btr", RM16_32_64, IMM8, __)
	/* 7 */ NORMAL("btc", RM16_32_64, IMM8, __)
};

static const struct instruction_desc mandatory_0FC2[4] =
{
	/* 00 */ NORMAL("cmpps", XMM, XMMM128, IMM8)
	/* 66 */ NORMAL("cmppd", XMM, XMMM128, IMM8)
	/* F3 */ NORMAL("cmpss", XMM, XMMM32, IMM8)
	/* F2 */ NORMAL("cmpsd", XMM, XMMM64, IMM8)
};

static const struct instruction_desc modrm_mod_0FC4[2] =
{
	/* R */ NORMAL("pinsrw", MM_XMM, RM_R32_64, IMM8)
	/* M */ NORMAL("pinsrw", MM_XMM, M16, IMM8)
};

static const struct instruction_desc mandatory_0FC6[4] =
{
	/* 00 */ NORMAL("shufps", XMM, XMMM128, IMM8)
	/* 66 */ NORMAL("shufpd", XMM, XMMM128, IMM8)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc extension_0FC7[8] =
{
	/* 0 */ UNKNOWN()
	/* 1 */ NORMAL_MOREREG("cmpxchg8b", M32_64, __, __, REG_AX | REG_CX | REG_DX | REG_BX) /* Actually M64_M128 */
	/* 2 */ UNKNOWN()
	/* 3 */ UNKNOWN()
	/* 4 */ UNKNOWN()
	/* 5 */ UNKNOWN()
	/* 6 */ UNSUPPORTED() /* vmx instructions */
	/* 7 */ UNSUPPORTED() /* vmx instructions */
};

static const struct instruction_desc mandatory_0FD0[4] =
{
	/* 00 */ UNKNOWN()
	/* 66 */ NORMAL("addsubpd", XMM, XMMM128, __)
	/* F3 */ UNKNOWN()
	/* F2 */ NORMAL("addsubps", XMM, XMMM128, __)
};

static const struct instruction_desc mandatory_0FD6[4] =
{
	/* 00 */ UNKNOWN()
	/* 66 */ NORMAL("movq", XMMM64, XMM, __)
	/* F3 */ NORMAL("movq2dq", XMM, RM_MM, __)
	/* F2 */ NORMAL("movdq2q", MM, RM_XMM, __)
};

static const struct instruction_desc mandatory_0FE6[4] =
{
	/* 00 */ UNKNOWN()
	/* 66 */ NORMAL("cvttpd2dq", XMM, XMMM128, __)
	/* F3 */ NORMAL("cvtdq2pd", XMM, XMMM128, __)
	/* F2 */ NORMAL("cvtpd2dq", XMM, XMMM128, __)
};

static const struct instruction_desc mandatory_0FE7[4] =
{
	/* 00 */ NORMAL("movntq", M64, MM, __)
	/* 66 */ NORMAL("movntdq", M128, XMM, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

static const struct instruction_desc mandatory_0FF0[4] =
{
	/* 00 */ UNKNOWN()
	/* 66 */ UNKNOWN()
	/* F3 */ UNKNOWN()
	/* F2 */ NORMAL("lddqu", XMM, M128, __)
};

static const struct instruction_desc mandatory_0FF7[4] =
{
	/* 00 */ NORMAL("maskmovq", MM, RM_MM, __)
	/* 66 */ NORMAL("maskmovdqu", XMM, RM_XMM, __)
	/* F3 */ UNKNOWN()
	/* F2 */ UNKNOWN()
};

/* Instructions with 0F prefix */
const struct instruction_desc two_byte_inst[256] =
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
	/* 0x02 */ UNSUPPORTED() /* LAR r16, r16/m16; LAR reg, r32/m16 */
	/* 0x03 */ UNSUPPORTED() /* LSL r?, r?/m16 */
	/* 0x04 */ UNKNOWN()
	/* 0x05 */ UNSUPPORTED() /* SYSCALL */
	/* 0x06 */ PRIVILEGED("clts", __, __, __)
	/* 0x07 */ UNSUPPORTED() /* SYSRET */
	/* 0x08 */ PRIVILEGED("invd", __, __, __)
	/* 0x09 */ PRIVILEGED("wbinvd", __, __, __)
	/* 0x0A */ UNKNOWN()
	/* 0x0B */ PRIVILEGED("ud2", __, __, __)
	/* 0x0C */ UNKNOWN()
	/* 0x0D */ EXTENSION(0F0D)
	/* 1: PREFETCHW m8
	2: PREFETCHWT1 m8 */
	/* 0x0E */ UNSUPPORTED()
	/* 0x0F */ UNSUPPORTED()
	/* 0x10 */ MANDATORY(0F10)
	/* 0x11 */ MANDATORY(0F11)
	/* 0x12 */ MANDATORY(0F12)
	/* 0x13 */ MANDATORY(0F13)
	/* 0x14 */ MANDATORY(0F14)
	/* 0x15 */ MANDATORY(0F15)
	/* 0x16 */ MANDATORY(0F16)
	/* 0x17 */ MANDATORY(0F17)
	/* 0x18 */ EXTENSION(0F18)
	/* 0x19 */ UNKNOWN()
	/* 0x1A */ UNKNOWN()
	/* 0x1B */ UNKNOWN()
	/* 0x1C */ UNKNOWN()
	/* 0x1D */ UNKNOWN()
	/* 0x1E */ UNKNOWN()
	/* 0x1F */ NORMAL("nop", RM16_32, __, __)
#ifdef _WIN64
	/* 0x20 */ NORMAL("mov", RM_R64, CREG, __)
	/* 0x21 */ NORMAL("mov", RM_R64, DREG, __)
	/* 0x22 */ NORMAL("mov", CREG, RM_R64, __)
	/* 0x23 */ NORMAL("mov", DREG, RM_R64, __)
#else
	/* 0x20 */ NORMAL("mov", RM_R32, CREG, __)
	/* 0x21 */ NORMAL("mov", RM_R32, DREG, __)
	/* 0x22 */ NORMAL("mov", CREG, RM_R32, __)
	/* 0x23 */ NORMAL("mov", DREG, RM_R32, __)
#endif
	/* 0x24 */ UNKNOWN()
	/* 0x25 */ UNKNOWN()
	/* 0x26 */ UNKNOWN()
	/* 0x27 */ UNKNOWN()
	/* 0x28 */ MANDATORY(0F28)
	/* 0x29 */ MANDATORY(0F29)
	/* 0x2A */ MANDATORY(0F2A)
	/* 0x2B */ MANDATORY(0F2B)
	/* 0x2C */ MANDATORY(0F2C)
	/* 0x2D */ MANDATORY(0F2D)
	/* 0x2E */ MANDATORY(0F2E)
	/* 0x2F */ MANDATORY(0F2F)
	/* 0x30 */ UNSUPPORTED() /* WRMSR ECX, EDX:EAX */
	/* 0x31 */ NORMAL_MOREREG("rdtsc", __, __, __, REG_AX | REG_DX)
	/* 0x32 */ UNSUPPORTED() /* RDMSR EDX:EAX, ECX */
	/* 0x33 */ NORMAL_MOREREG("rdpmc", __, __, __, REG_AX | REG_CX | REG_DX)
	/* 0x34 */ UNSUPPORTED() /* SYSENTER */
	/* 0x35 */ UNSUPPORTED() /* SYSEXIT */
	/* 0x36 */ UNKNOWN()
	/* 0x37 */ UNSUPPORTED() /* SMX: GETSEC */
	/* 0x38 */ INVALID() /* Three byte instructions */
	/* 0x39 */ UNKNOWN()
	/* 0x3A */ INVALID() /* Three byte instructions */
	/* 0x3B */ UNKNOWN()
	/* 0x3C */ UNKNOWN()
	/* 0x3D */ UNKNOWN()
	/* 0x3E */ UNKNOWN()
	/* 0x3F */ UNKNOWN()
	/* 0x40 */ NORMAL("cmovo", R16_32_64, RM16_32_64, __)
	/* 0x41 */ NORMAL("cmovno", R16_32_64, RM16_32_64, __)
	/* 0x42 */ NORMAL("cmovb", R16_32_64, RM16_32_64, __)
	/* 0x43 */ NORMAL("cmovae", R16_32_64, RM16_32_64, __)
	/* 0x44 */ NORMAL("cmovz", R16_32_64, RM16_32_64, __)
	/* 0x45 */ NORMAL("cmovnz", R16_32_64, RM16_32_64, __)
	/* 0x46 */ NORMAL("cmovbe", R16_32_64, RM16_32_64, __)
	/* 0x47 */ NORMAL("cmova", R16_32_64, RM16_32_64, __)
	/* 0x48 */ NORMAL("cmovs", R16_32_64, RM16_32_64, __)
	/* 0x49 */ NORMAL("cmovns", R16_32_64, RM16_32_64, __)
	/* 0x4A */ NORMAL("cmovp", R16_32_64, RM16_32_64, __)
	/* 0x4B */ NORMAL("cmovnp", R16_32_64, RM16_32_64, __)
	/* 0x4C */ NORMAL("cmovl", R16_32_64, RM16_32_64, __)
	/* 0x4D */ NORMAL("cmovge", R16_32_64, RM16_32_64, __)
	/* 0x4E */ NORMAL("cmovle", R16_32_64, RM16_32_64, __)
	/* 0x4F */ NORMAL("cmovg", R16_32_64, RM16_32_64, __)
	/* 0x50 */ MANDATORY(0F50)
	/* 0x51 */ MANDATORY(0F51)
	/* 0x52 */ MANDATORY(0F52)
	/* 0x53 */ MANDATORY(0F53)
	/* 0x54 */ MANDATORY(0F54)
	/* 0x55 */ MANDATORY(0F55)
	/* 0x56 */ MANDATORY(0F56)
	/* 0x57 */ MANDATORY(0F57)
	/* 0x58 */ MANDATORY(0F58)
	/* 0x59 */ MANDATORY(0F59)
	/* 0x5A */ MANDATORY(0F5A)
	/* 0x5B */ MANDATORY(0F5B)
	/* 0x5C */ MANDATORY(0F5C)
	/* 0x5D */ MANDATORY(0F5D)
	/* 0x5E */ MANDATORY(0F5E)
	/* 0x5F */ MANDATORY(0F5F)
	/* 0x60 */ MANDATORY(0F60)
	/* 0x61 */ MANDATORY(0F61)
	/* 0x62 */ MANDATORY(0F62)
	/* 0x63 */ NORMAL("packsswb", MM_XMM, MMM64_XMMM128, __)
	/* 0x64 */ NORMAL("pcmpgtb", MM_XMM, MMM64_XMMM128, __)
	/* 0x65 */ NORMAL("pcmpgtw", MM_XMM, MMM64_XMMM128, __)
	/* 0x66 */ NORMAL("pcmpgtd", MM_XMM, MMM64_XMMM128, __)
	/* 0x67 */ NORMAL("packuswb", MM_XMM, MMM64_XMMM128, __)
	/* 0x68 */ NORMAL("punpckhbw", MM_XMM, MMM64_XMMM128, __)
	/* 0x69 */ NORMAL("punpckhwd", MM_XMM, MMM64_XMMM128, __)
	/* 0x6A */ NORMAL("punpckhdq", MM_XMM, MMM64_XMMM128, __)
	/* 0x6B */ NORMAL("packssdw", MM_XMM, MMM64_XMMM128, __)
	/* 0x6C */ NORMAL("punpcklqdq", XMM, XMMM128, __) /* Mandatory 66 prefix */
	/* 0x6D */ NORMAL("punpckhqdq", XMM, XMMM128, __) /* Mandatory 66 prefix */
	/* 0x6E */ NORMAL("movd", MM_XMM, RM32_64, __) /* Or movq */
	/* 0x6F */ MANDATORY(0F6F)
	/* 0x70 */ MANDATORY(0F70)
	/* 0x71 */ EXTENSION(0F71)
	/* 0x72 */ EXTENSION(0F72)
	/* 0x73 */ EXTENSION(0F73)
	/* 0x74 */ NORMAL("pcmpeqb", MM_XMM, MMM64_XMMM128, __)
	/* 0x75 */ NORMAL("pcmpeqw", MM_XMM, MMM64_XMMM128, __)
	/* 0x76 */ NORMAL("pcmpeqd", MM_XMM, MMM64_XMMM128, __)
	/* 0x77 */ NORMAL("emms", __, __, __)
	/* 0x78 */ UNSUPPORTED()
	/* 0x79 */ UNSUPPORTED()
	/* 0x7A */ UNKNOWN()
	/* 0x7B */ UNKNOWN()
	/* 0x7C */ MANDATORY(0F7C)
	/* 0x7D */ MANDATORY(0F7D)
	/* 0x7E */ MANDATORY(0F7E)
	/* 0x7F */ MANDATORY(0F7F)
	/* 0x80 */ SPECIAL("jo", REL16_32, __, __, HANDLER_JCC)
	/* 0x81 */ SPECIAL("jno", REL16_32, __, __, HANDLER_JCC)
	/* 0x82 */ SPECIAL("jb", REL16_32, __, __, HANDLER_JCC)
	/* 0x83 */ SPECIAL("jae", REL16_32, __, __, HANDLER_JCC)
	/* 0x84 */ SPECIAL("jz", REL16_32, __, __, HANDLER_JCC)
	/* 0x85 */ SPECIAL("jnz", REL16_32, __, __, HANDLER_JCC)
	/* 0x86 */ SPECIAL("jbe", REL16_32, __, __, HANDLER_JCC)
	/* 0x87 */ SPECIAL("ja", REL16_32, __, __, HANDLER_JCC)
	/* 0x88 */ SPECIAL("js", REL16_32, __, __, HANDLER_JCC)
	/* 0x89 */ SPECIAL("jns", REL16_32, __, __, HANDLER_JCC)
	/* 0x8A */ SPECIAL("jp", REL16_32, __, __, HANDLER_JCC)
	/* 0x8B */ SPECIAL("jnp", REL16_32, __, __, HANDLER_JCC)
	/* 0x8C */ SPECIAL("jl", REL16_32, __, __, HANDLER_JCC)
	/* 0x8D */ SPECIAL("jge", REL16_32, __, __, HANDLER_JCC)
	/* 0x8E */ SPECIAL("jle", REL16_32, __, __, HANDLER_JCC)
	/* 0x8F */ SPECIAL("jg", REL16_32, __, __, HANDLER_JCC)
	/* 0x90 */ NORMAL("seto", RM8, __, __)
	/* 0x91 */ NORMAL("setno", RM8, __, __)
	/* 0x92 */ NORMAL("setb", RM8, __, __)
	/* 0x93 */ NORMAL("setae", RM8, __, __)
	/* 0x94 */ NORMAL("setz", RM8, __, __)
	/* 0x95 */ NORMAL("setnz", RM8, __, __)
	/* 0x96 */ NORMAL("setbe", RM8, __, __)
	/* 0x97 */ NORMAL("seta", RM8, __, __)
	/* 0x98 */ NORMAL("sets", RM8, __, __)
	/* 0x99 */ NORMAL("setns", RM8, __, __)
	/* 0x9A */ NORMAL("setp", RM8, __, __)
	/* 0x9B */ NORMAL("setnp", RM8, __, __)
	/* 0x9C */ NORMAL("setl", RM8, __, __)
	/* 0x9D */ NORMAL("setge", RM8, __, __)
	/* 0x9E */ NORMAL("setle", RM8, __, __)
	/* 0x9F */ NORMAL("setg", RM8, __, __)
	/* 0xA0 */ UNSUPPORTED() /* PUSH FS */
	/* 0xA1 */ UNSUPPORTED() /* POP FS */
	/* 0xA2 */ SPECIAL("cpuid", __, __, __, HANDLER_CPUID)
	/* 0xA3 */ NORMAL("bt", RM16_32_64, R16_32_64, __)
	/* 0xA4 */ NORMAL("shld", RM16_32_64, R16_32_64, IMM8)
	/* 0xA5 */ NORMAL("shld", RM16_32_64, R16_32_64, CL)
	/* 0xA6 */ UNKNOWN()
	/* 0xA7 */ UNKNOWN()
	/* 0xA8 */ UNSUPPORTED() /* PUSH GS */
	/* 0xA9 */ UNSUPPORTED() /* POP GS */
#ifdef _WIN64
	/* 0xAA: INVALID */ INVALID()
#else
	/* 0xAA */ PRIVILEGED("rsm", __, __, __)
#endif
	/* 0xAB */ NORMAL("bts", RM16_32_64, R16_32_64, __)
	/* 0xAC */ NORMAL("shrd", RM16_32_64, R16_32_64, IMM8)
	/* 0xAD */ NORMAL("shrd", RM16_32_64, R16_32_64, CL)
	/* 0xAE */ EXTENSION(0FAE)
	/* 0xAF */ NORMAL("imul", R16_32_64, RM16_32_64, __)
	/* 0xB0 */ NORMAL("cmpxchg", RM8, AL, R8)
	/* 0xB1 */ NORMAL("cmpxchg", RM16_32_64, AX_EAX_RAX, R16_32_64)
	/* 0xB2 */ UNSUPPORTED() /* LSS r?, m16:? */
	/* 0xB3 */ NORMAL("btr", RM16_32_64, R16_32_64, __)
	/* 0xB4 */ UNSUPPORTED() /* LFS r?, m16:? */
	/* 0xB5 */ UNSUPPORTED() /* LGS r?, m16:? */
	/* 0xB6 */ NORMAL("movzx", R16_32_64, RM8, __)
	/* 0xB7 */ NORMAL("movzx", R16_32_64, RM16, __)
	/* 0xB8 */ MANDATORY(0FB8)
	/* 0xB9 */ PRIVILEGED("ud", __, __, __)
	/* 0xBA */ EXTENSION(0FBA)
	/* 0xBB */ NORMAL("btc", RM16_32_64, R16_32_64, __)
	/* 0xBC */ NORMAL("bsf", R16_32_64, RM16_32_64, __)
	/* 0xBD */ NORMAL("bsr", R16_32_64, RM16_32_64, __)
	/* 0xBE */ NORMAL("movsx", R16_32_64, RM8, __)
	/* 0xBF */ NORMAL("movsx", R16_32_64, RM16, __)
	/* 0xC0 */ NORMAL("xadd", RM8, R8, __)
	/* 0xC1 */ NORMAL("xadd", RM16_32_64, R16_32_64, __)
	/* 0xC2 */ MANDATORY(0FC2)
	/* 0xC3 */ NORMAL("movnti", M32_64, R32_64, __)
	/* 0xC4 */ MODRM_MOD(0FC4)
	/* 0xC5 */ NORMAL("pextrw", R32_64, RM_MM_XMM, IMM8)
	/* 0xC6 */ MANDATORY(0FC6)
	/* 0xC7 */ EXTENSION(0FC7)
	/* 0xC8 */ NORMAL("bswap", OP_R32_64, __, __)
	/* 0xC9 */ NORMAL("bswap", OP_R32_64, __, __)
	/* 0xCA */ NORMAL("bswap", OP_R32_64, __, __)
	/* 0xCB */ NORMAL("bswap", OP_R32_64, __, __)
	/* 0xCC */ NORMAL("bswap", OP_R32_64, __, __)
	/* 0xCD */ NORMAL("bswap", OP_R32_64, __, __)
	/* 0xCE */ NORMAL("bswap", OP_R32_64, __, __)
	/* 0xCF */ NORMAL("bswap", OP_R32_64, __, __)
	/* 0xD0 */ MANDATORY(0FD0)
	/* 0xD1 */ NORMAL("psrlw", MM_XMM, MMM64_XMMM128, __)
	/* 0xD2 */ NORMAL("psrld", MM_XMM, MMM64_XMMM128, __)
	/* 0xD3 */ NORMAL("psrlq", MM_XMM, MMM64_XMMM128, __)
	/* 0xD4 */ NORMAL("paddq", MM_XMM, MMM64_XMMM128, __)
	/* 0xD5 */ NORMAL("pmullw", MM_XMM, MMM64_XMMM128, __)
	/* 0xD6 */ MANDATORY(0FD6)
	/* 0xD7 */ NORMAL("pmovmskb", R32_64, RM_MM_XMM, __)
	/* 0xD8 */ NORMAL("psubusb", MM_XMM, MMM64_XMMM128, __)
	/* 0xD9 */ NORMAL("psubusw", MM_XMM, MMM64_XMMM128, __)
	/* 0xDA */ NORMAL("pminub", MM_XMM, MMM64_XMMM128, __)
	/* 0xDB */ NORMAL("pand", MM_XMM, MMM64_XMMM128, __)
	/* 0xDC */ NORMAL("paddusb", MM_XMM, MMM64_XMMM128, __)
	/* 0xDD */ NORMAL("paddusw", MM_XMM, MMM64_XMMM128, __)
	/* 0xDE */ NORMAL("pmaxub", MM_XMM, MMM64_XMMM128, __)
	/* 0xDF */ NORMAL("pandn", MM_XMM, MMM64_XMMM128, __)
	/* 0xE0 */ NORMAL("pavgb", MM_XMM, MMM64_XMMM128, __)
	/* 0xE1 */ NORMAL("psraw", MM_XMM, MMM64_XMMM128, __)
	/* 0xE2 */ NORMAL("psrad", MM_XMM, MMM64_XMMM128, __)
	/* 0xE3 */ NORMAL("pavgw", MM_XMM, MMM64_XMMM128, __)
	/* 0xE4 */ NORMAL("pmulhuw", MM_XMM, MMM64_XMMM128, __)
	/* 0xE5 */ NORMAL("pmulhw", MM_XMM, MMM64_XMMM128, __)
	/* 0xE6 */ MANDATORY(0FE6)
	/* 0xE7 */ MANDATORY(0FE7)
	/* 0xE8 */ NORMAL("psubsb", MM_XMM, MMM64_XMMM128, __)
	/* 0xE9 */ NORMAL("psubsw", MM_XMM, MMM64_XMMM128, __)
	/* 0xEA */ NORMAL("pminsw", MM_XMM, MMM64_XMMM128, __)
	/* 0xEB */ NORMAL("por", MM_XMM, MMM64_XMMM128, __)
	/* 0xEC */ NORMAL("paddsb", MM_XMM, MMM64_XMMM128, __)
	/* 0xED */ NORMAL("paddsw", MM_XMM, MMM64_XMMM128, __)
	/* 0xEE */ NORMAL("pmaxsw", MM_XMM, MMM64_XMMM128, __)
	/* 0xEF */ NORMAL("pxor", MM_XMM, MMM64_XMMM128, __)
	/* 0xF0 */ MANDATORY(0FF0)
	/* 0xF1 */ NORMAL("psllw", MM_XMM, MMM64_XMMM128, __)
	/* 0xF2 */ NORMAL("pslld", MM_XMM, MMM64_XMMM128, __)
	/* 0xF3 */ NORMAL("psllq", MM_XMM, MMM64_XMMM128, __)
	/* 0xF4 */ NORMAL("pmuludq", MM_XMM, MMM64_XMMM128, __)
	/* 0xF5 */ NORMAL("pmaddwd", MM_XMM, MMM64_XMMM128, __)
	/* 0xF6 */ NORMAL("psadbw", MM_XMM, MMM64_XMMM128, __)
	/* 0xF7 */ MANDATORY(0FF7)
	/* 0xF8 */ NORMAL("psubb", MM_XMM, MMM64_XMMM128, __)
	/* 0xF9 */ NORMAL("psubw", MM_XMM, MMM64_XMMM128, __)
	/* 0xFA */ NORMAL("psubd", MM_XMM, MMM64_XMMM128, __)
	/* 0xFB */ NORMAL("psubq", MM_XMM, MMM64_XMMM128, __)
	/* 0xFC */ NORMAL("paddb", MM_XMM, MMM64_XMMM128, __)
	/* 0xFD */ NORMAL("paddw", MM_XMM, MMM64_XMMM128, __)
	/* 0xFE */ NORMAL("paddd", MM_XMM, MMM64_XMMM128, __)
	/* 0xFF */ UNKNOWN()
};

static const struct instruction_desc mandatory_0F38F0[4] =
{
	/* 00 */ NORMAL("movbe", R16_32_64, M16_32_64, __)
	/* 66 */ NORMAL("movbe", R16_32_64, M16_32_64, __)
	/* F3 */ UNKNOWN()
	/* F2 */ NORMAL("crc32", R32_64, RM8, __)
};

static const struct instruction_desc mandatory_0F38F1[4] =
{
	/* 00 */ NORMAL("movbe", R16_32_64, M16_32_64, __)
	/* 66 */ NORMAL("movbe", R16_32_64, M16_32_64, __)
	/* F3 */ UNKNOWN()
	/* F2 */ NORMAL("crc32", R32_64, RM16_32_64, __)
};

/* Instructions with 0F 38 prefix */
const struct instruction_desc three_byte_inst_0x38[256] =
{
	/* 0x00 */ NORMAL("pshufb", MM_XMM, MMM64_XMMM128, __)
	/* 0x01 */ NORMAL("phaddw", MM_XMM, MMM64_XMMM128, __)
	/* 0x02 */ NORMAL("phaddd", MM_XMM, MMM64_XMMM128, __)
	/* 0x03 */ NORMAL("phaddsw", MM_XMM, MMM64_XMMM128, __)
	/* 0x04 */ NORMAL("pmaddubsw", MM_XMM, MMM64_XMMM128, __)
	/* 0x05 */ NORMAL("phsubw", MM_XMM, MMM64_XMMM128, __)
	/* 0x06 */ NORMAL("phsubd", MM_XMM, MMM64_XMMM128, __)
	/* 0x07 */ NORMAL("phsubsw", MM_XMM, MMM64_XMMM128, __)
	/* 0x08 */ NORMAL("psignb", MM_XMM, MMM64_XMMM128, __)
	/* 0x09 */ NORMAL("psignw", MM_XMM, MMM64_XMMM128, __)
	/* 0x0A */ NORMAL("psignd", MM_XMM, MMM64_XMMM128, __)
	/* 0x0B */ NORMAL("pmulhrsw", MM_XMM, MMM64_XMMM128, __)
	/* 0x0C */ UNKNOWN()
	/* 0x0D */ UNKNOWN()
	/* 0x0E */ UNKNOWN()
	/* 0x0F */ UNKNOWN()
	/* 0x10 */ NORMAL("pblendvb", XMM, XMMM128, __)
	/* 0x11 */ UNKNOWN()
	/* 0x12 */ UNKNOWN()
	/* 0x13 */ UNKNOWN()
	/* 0x14 */ NORMAL("blendvps", XMM, XMMM128, __)
	/* 0x15 */ NORMAL("blendvpd", XMM, XMMM128, __)
	/* 0x16 */ UNKNOWN()
	/* 0x17 */ NORMAL("ptest", XMM, XMMM128, __)
	/* 0x18 */ UNKNOWN()
	/* 0x19 */ UNKNOWN()
	/* 0x1A */ UNKNOWN()
	/* 0x1B */ UNKNOWN()
	/* 0x1C */ NORMAL("pabsb", MM_XMM, MMM64_XMMM128, __)
	/* 0x1D */ NORMAL("pabsw", MM_XMM, MMM64_XMMM128, __)
	/* 0x1E */ NORMAL("pabsd", MM_XMM, MMM64_XMMM128, __)
	/* 0x1F */ UNKNOWN()
	/* 0x20 */ NORMAL("pmovsxbw", XMM, XMMM64, __)
	/* 0x21 */ NORMAL("pmovsxbd", XMM, XMMM32, __)
	/* 0x22 */ NORMAL("pmovsxbq", XMM, XMMM16, __)
	/* 0x23 */ NORMAL("pmovsxwd", XMM, XMMM64, __)
	/* 0x24 */ NORMAL("pmovsxwq", XMM, XMMM32, __)
	/* 0x25 */ NORMAL("pmovsxdq", XMM, XMMM64, __)
	/* 0x26 */ UNKNOWN()
	/* 0x27 */ UNKNOWN()
	/* 0x28 */ NORMAL("pmuldq", XMM, XMMM128, __)
	/* 0x29 */ NORMAL("pcmpeqq", XMM, XMMM128, __)
	/* 0x2A */ NORMAL("movntdqa", XMM, M128, __)
	/* 0x2B */ NORMAL("packusdw", XMM, XMMM128, __)
	/* 0x2C */ UNKNOWN()
	/* 0x2D */ UNKNOWN()
	/* 0x2E */ UNKNOWN()
	/* 0x2F */ UNKNOWN()
	/* 0x30 */ NORMAL("pmovzxbw", XMM, XMMM64, __)
	/* 0x31 */ NORMAL("pmovzxbd", XMM, XMMM32, __)
	/* 0x32 */ NORMAL("pmovzxbq", XMM, XMMM16, __)
	/* 0x33 */ NORMAL("pmovzxwd", XMM, XMMM64, __)
	/* 0x34 */ NORMAL("pmovzxwq", XMM, XMMM32, __)
	/* 0x35 */ NORMAL("pmovzxdq", XMM, XMMM64, __)
	/* 0x36 */ UNKNOWN()
	/* 0x37 */ NORMAL("pcmpgtq", XMM, XMMM128, __)
	/* 0x38 */ NORMAL("pminsb", XMM, XMMM128, __)
	/* 0x39 */ NORMAL("pminsd", XMM, XMMM128, __)
	/* 0x3A */ NORMAL("pminuw", XMM, XMMM128, __)
	/* 0x3B */ NORMAL("pminud", XMM, XMMM128, __)
	/* 0x3C */ NORMAL("pmaxsb", XMM, XMMM128, __)
	/* 0x3D */ NORMAL("pmaxsd", XMM, XMMM128, __)
	/* 0x3E */ NORMAL("pmaxuw", XMM, XMMM128, __)
	/* 0x3F */ NORMAL("pmaxud", XMM, XMMM128, __)
	/* 0x40 */ NORMAL("pmulld", XMM, XMMM128, __)
	/* 0x41 */ NORMAL("phminposuw", XMM, XMMM128, __)
	/* 0x42 */ UNKNOWN()
	/* 0x43 */ UNKNOWN()
	/* 0x44 */ UNKNOWN()
	/* 0x45 */ UNKNOWN()
	/* 0x46 */ UNKNOWN()
	/* 0x47 */ UNKNOWN()
	/* 0x48 */ UNKNOWN()
	/* 0x49 */ UNKNOWN()
	/* 0x4A */ UNKNOWN()
	/* 0x4B */ UNKNOWN()
	/* 0x4C */ UNKNOWN()
	/* 0x4D */ UNKNOWN()
	/* 0x4E */ UNKNOWN()
	/* 0x4F */ UNKNOWN()
	/* 0x50 */ UNKNOWN()
	/* 0x51 */ UNKNOWN()
	/* 0x52 */ UNKNOWN()
	/* 0x53 */ UNKNOWN()
	/* 0x54 */ UNKNOWN()
	/* 0x55 */ UNKNOWN()
	/* 0x56 */ UNKNOWN()
	/* 0x57 */ UNKNOWN()
	/* 0x58 */ UNKNOWN()
	/* 0x59 */ UNKNOWN()
	/* 0x5A */ UNKNOWN()
	/* 0x5B */ UNKNOWN()
	/* 0x5C */ UNKNOWN()
	/* 0x5D */ UNKNOWN()
	/* 0x5E */ UNKNOWN()
	/* 0x5F */ UNKNOWN()
	/* 0x60 */ UNKNOWN()
	/* 0x61 */ UNKNOWN()
	/* 0x62 */ UNKNOWN()
	/* 0x63 */ UNKNOWN()
	/* 0x64 */ UNKNOWN()
	/* 0x65 */ UNKNOWN()
	/* 0x66 */ UNKNOWN()
	/* 0x67 */ UNKNOWN()
	/* 0x68 */ UNKNOWN()
	/* 0x69 */ UNKNOWN()
	/* 0x6A */ UNKNOWN()
	/* 0x6B */ UNKNOWN()
	/* 0x6C */ UNKNOWN()
	/* 0x6D */ UNKNOWN()
	/* 0x6E */ UNKNOWN()
	/* 0x6F */ UNKNOWN()
	/* 0x70 */ UNKNOWN()
	/* 0x71 */ UNKNOWN()
	/* 0x72 */ UNKNOWN()
	/* 0x73 */ UNKNOWN()
	/* 0x74 */ UNKNOWN()
	/* 0x75 */ UNKNOWN()
	/* 0x76 */ UNKNOWN()
	/* 0x77 */ UNKNOWN()
	/* 0x78 */ UNKNOWN()
	/* 0x79 */ UNKNOWN()
	/* 0x7A */ UNKNOWN()
	/* 0x7B */ UNKNOWN()
	/* 0x7C */ UNKNOWN()
	/* 0x7D */ UNKNOWN()
	/* 0x7E */ UNKNOWN()
	/* 0x7F */ UNKNOWN()
	/* 0x80 */ UNKNOWN()
	/* 0x81 */ UNKNOWN()
	/* 0x82 */ UNKNOWN()
	/* 0x83 */ UNKNOWN()
	/* 0x84 */ UNKNOWN()
	/* 0x85 */ UNKNOWN()
	/* 0x86 */ UNKNOWN()
	/* 0x87 */ UNKNOWN()
	/* 0x88 */ UNKNOWN()
	/* 0x89 */ UNKNOWN()
	/* 0x8A */ UNKNOWN()
	/* 0x8B */ UNKNOWN()
	/* 0x8C */ UNKNOWN()
	/* 0x8D */ UNKNOWN()
	/* 0x8E */ UNKNOWN()
	/* 0x8F */ UNKNOWN()
	/* 0x90 */ UNKNOWN()
	/* 0x91 */ UNKNOWN()
	/* 0x92 */ UNKNOWN()
	/* 0x93 */ UNKNOWN()
	/* 0x94 */ UNKNOWN()
	/* 0x95 */ UNKNOWN()
	/* 0x96 */ UNKNOWN()
	/* 0x97 */ UNKNOWN()
	/* 0x98 */ UNKNOWN()
	/* 0x99 */ UNKNOWN()
	/* 0x9A */ UNKNOWN()
	/* 0x9B */ UNKNOWN()
	/* 0x9C */ UNKNOWN()
	/* 0x9D */ UNKNOWN()
	/* 0x9E */ UNKNOWN()
	/* 0x9F */ UNKNOWN()
	/* 0xA0 */ UNKNOWN()
	/* 0xA1 */ UNKNOWN()
	/* 0xA2 */ UNKNOWN()
	/* 0xA3 */ UNKNOWN()
	/* 0xA4 */ UNKNOWN()
	/* 0xA5 */ UNKNOWN()
	/* 0xA6 */ UNKNOWN()
	/* 0xA7 */ UNKNOWN()
	/* 0xA8 */ UNKNOWN()
	/* 0xA9 */ UNKNOWN()
	/* 0xAA */ UNKNOWN()
	/* 0xAB */ UNKNOWN()
	/* 0xAC */ UNKNOWN()
	/* 0xAD */ UNKNOWN()
	/* 0xAE */ UNKNOWN()
	/* 0xAF */ UNKNOWN()
	/* 0xB0 */ UNKNOWN()
	/* 0xB1 */ UNKNOWN()
	/* 0xB2 */ UNKNOWN()
	/* 0xB3 */ UNKNOWN()
	/* 0xB4 */ UNKNOWN()
	/* 0xB5 */ UNKNOWN()
	/* 0xB6 */ UNKNOWN()
	/* 0xB7 */ UNKNOWN()
	/* 0xB8 */ UNKNOWN()
	/* 0xB9 */ UNKNOWN()
	/* 0xBA */ UNKNOWN()
	/* 0xBB */ UNKNOWN()
	/* 0xBC */ UNKNOWN()
	/* 0xBD */ UNKNOWN()
	/* 0xBE */ UNKNOWN()
	/* 0xBF */ UNKNOWN()
	/* 0xC0 */ UNKNOWN()
	/* 0xC1 */ UNKNOWN()
	/* 0xC2 */ UNKNOWN()
	/* 0xC3 */ UNKNOWN()
	/* 0xC4 */ UNKNOWN()
	/* 0xC5 */ UNKNOWN()
	/* 0xC6 */ UNKNOWN()
	/* 0xC7 */ UNKNOWN()
	/* 0xC8 */ UNKNOWN()
	/* 0xC9 */ UNKNOWN()
	/* 0xCA */ UNKNOWN()
	/* 0xCB */ UNKNOWN()
	/* 0xCC */ UNKNOWN()
	/* 0xCD */ UNKNOWN()
	/* 0xCE */ UNKNOWN()
	/* 0xCF */ UNKNOWN()
	/* 0xD0 */ UNKNOWN()
	/* 0xD1 */ UNKNOWN()
	/* 0xD2 */ UNKNOWN()
	/* 0xD3 */ UNKNOWN()
	/* 0xD4 */ UNKNOWN()
	/* 0xD5 */ UNKNOWN()
	/* 0xD6 */ UNKNOWN()
	/* 0xD7 */ UNKNOWN()
	/* 0xD8 */ UNKNOWN()
	/* 0xD9 */ UNKNOWN()
	/* 0xDA */ UNKNOWN()
	/* 0xDB */ UNKNOWN()
	/* 0xDC */ UNKNOWN()
	/* 0xDD */ UNKNOWN()
	/* 0xDE */ UNKNOWN()
	/* 0xDF */ UNKNOWN()
	/* 0xE0 */ UNKNOWN()
	/* 0xE1 */ UNKNOWN()
	/* 0xE2 */ UNKNOWN()
	/* 0xE3 */ UNKNOWN()
	/* 0xE4 */ UNKNOWN()
	/* 0xE5 */ UNKNOWN()
	/* 0xE6 */ UNKNOWN()
	/* 0xE7 */ UNKNOWN()
	/* 0xE8 */ UNKNOWN()
	/* 0xE9 */ UNKNOWN()
	/* 0xEA */ UNKNOWN()
	/* 0xEB */ UNKNOWN()
	/* 0xEC */ UNKNOWN()
	/* 0xED */ UNKNOWN()
	/* 0xEE */ UNKNOWN()
	/* 0xEF */ UNKNOWN()
	/* 0xF0 */ MANDATORY(0F38F0)
	/* 0xF1 */ MANDATORY(0F38F1)
	/* 0xF2 */ UNKNOWN()
	/* 0xF3 */ UNKNOWN()
	/* 0xF4 */ UNKNOWN()
	/* 0xF5 */ UNKNOWN()
	/* 0xF6 */ UNKNOWN()
	/* 0xF7 */ UNKNOWN()
	/* 0xF8 */ UNKNOWN()
	/* 0xF9 */ UNKNOWN()
	/* 0xFA */ UNKNOWN()
	/* 0xFB */ UNKNOWN()
	/* 0xFC */ UNKNOWN()
	/* 0xFD */ UNKNOWN()
	/* 0xFE */ UNKNOWN()
	/* 0xFF */ UNKNOWN()
};

static const struct instruction_desc modrm_mod_0F3A14[2] =
{
	/* R */ NORMAL("pextrb", RM_R32_64, XMM, IMM8)
	/* M */ NORMAL("pextrb", M8, XMM, IMM8)
};

static const struct instruction_desc modrm_mod_0F3A15[2] =
{
	/* R */ NORMAL("pextrw", RM_R32_64, XMM, IMM8)
	/* M */ NORMAL("pextrw", M16, XMM, IMM8)
};

static const struct instruction_desc modrm_mod_0F3A20[2] =
{
	/* R */ NORMAL("pinsrb", XMM, RM_R32_64, IMM8)
	/* M */ NORMAL("pinsrb", XMM, M8, IMM8)
};

/* Instructions with 0F 3A prefix */
const struct instruction_desc three_byte_inst_0x3A[256] =
{
	/* 0x00 */ UNKNOWN()
	/* 0x01 */ UNKNOWN()
	/* 0x02 */ UNKNOWN()
	/* 0x03 */ UNKNOWN()
	/* 0x04 */ UNKNOWN()
	/* 0x05 */ UNKNOWN()
	/* 0x06 */ UNKNOWN()
	/* 0x07 */ UNKNOWN()
	/* 0x08 */ NORMAL("roundps", XMM, XMMM128, IMM8)
	/* 0x09 */ NORMAL("roundpd", XMM, XMMM128, IMM8)
	/* 0x0A */ NORMAL("roundss", XMM, XMMM32, IMM8)
	/* 0x0B */ NORMAL("roundsd", XMM, XMMM64, IMM8)
	/* 0x0C */ NORMAL("blendps", XMM, XMMM128, IMM8)
	/* 0x0D */ NORMAL("blendpd", XMM, XMMM128, IMM8)
	/* 0x0E */ NORMAL("pblendw", XMM, XMMM128, IMM8)
	/* 0x0F */ NORMAL("palignr", MM_XMM, MMM64_XMMM128, IMM8)
	/* 0x10 */ UNKNOWN()
	/* 0x11 */ UNKNOWN()
	/* 0x12 */ UNKNOWN()
	/* 0x13 */ UNKNOWN()
	/* 0x14 */ MODRM_MOD(0F3A14)
	/* 0x15 */ MODRM_MOD(0F3A15)
	/* 0x16 */ NORMAL("pextrd", RM32_64, XMM, IMM8) /* PEXTRQ */
	/* 0x17 */ NORMAL("extractps", RM32, XMM, IMM8)
	/* 0x18 */ UNKNOWN()
	/* 0x19 */ UNKNOWN()
	/* 0x1A */ UNKNOWN()
	/* 0x1B */ UNKNOWN()
	/* 0x1C */ UNKNOWN()
	/* 0x1D */ UNKNOWN()
	/* 0x1E */ UNKNOWN()
	/* 0x1F */ UNKNOWN()
	/* 0x20 */ MODRM_MOD(0F3A20)
	/* 0x21 */ NORMAL("insertps", XMM, XMMM32, IMM8)
	/* 0x22 */ NORMAL("pinsrd", XMM, RM32_64, IMM8) /* PINSRQ */
	/* 0x23 */ UNKNOWN()
	/* 0x24 */ UNKNOWN()
	/* 0x25 */ UNKNOWN()
	/* 0x26 */ UNKNOWN()
	/* 0x27 */ UNKNOWN()
	/* 0x28 */ UNKNOWN()
	/* 0x29 */ UNKNOWN()
	/* 0x2A */ UNKNOWN()
	/* 0x2B */ UNKNOWN()
	/* 0x2C */ UNKNOWN()
	/* 0x2D */ UNKNOWN()
	/* 0x2E */ UNKNOWN()
	/* 0x2F */ UNKNOWN()
	/* 0x30 */ UNKNOWN()
	/* 0x31 */ UNKNOWN()
	/* 0x32 */ UNKNOWN()
	/* 0x33 */ UNKNOWN()
	/* 0x34 */ UNKNOWN()
	/* 0x35 */ UNKNOWN()
	/* 0x36 */ UNKNOWN()
	/* 0x37 */ UNKNOWN()
	/* 0x38 */ UNKNOWN()
	/* 0x39 */ UNKNOWN()
	/* 0x3A */ UNKNOWN()
	/* 0x3B */ UNKNOWN()
	/* 0x3C */ UNKNOWN()
	/* 0x3D */ UNKNOWN()
	/* 0x3E */ UNKNOWN()
	/* 0x3F */ UNKNOWN()
	/* 0x40 */ NORMAL("dpps", XMM, XMMM128, IMM8)
	/* 0x41 */ NORMAL("dppd", XMM, XMMM128, IMM8)
	/* 0x42 */ NORMAL("mpsadbw", XMM, XMMM128, IMM8)
	/* 0x43 */ UNKNOWN()
	/* 0x44 */ UNKNOWN()
	/* 0x45 */ UNKNOWN()
	/* 0x46 */ UNKNOWN()
	/* 0x47 */ UNKNOWN()
	/* 0x48 */ UNKNOWN()
	/* 0x49 */ UNKNOWN()
	/* 0x4A */ UNKNOWN()
	/* 0x4B */ UNKNOWN()
	/* 0x4C */ UNKNOWN()
	/* 0x4D */ UNKNOWN()
	/* 0x4E */ UNKNOWN()
	/* 0x4F */ UNKNOWN()
	/* 0x50 */ UNKNOWN()
	/* 0x51 */ UNKNOWN()
	/* 0x52 */ UNKNOWN()
	/* 0x53 */ UNKNOWN()
	/* 0x54 */ UNKNOWN()
	/* 0x55 */ UNKNOWN()
	/* 0x56 */ UNKNOWN()
	/* 0x57 */ UNKNOWN()
	/* 0x58 */ UNKNOWN()
	/* 0x59 */ UNKNOWN()
	/* 0x5A */ UNKNOWN()
	/* 0x5B */ UNKNOWN()
	/* 0x5C */ UNKNOWN()
	/* 0x5D */ UNKNOWN()
	/* 0x5E */ UNKNOWN()
	/* 0x5F */ UNKNOWN()
	/* TODO: I'm not sure whether read/write flags of these 4 instructions are correct */
	/* 0x60 */ NORMAL("pcmpestrm", XMM, XMMM128, IMM8)
	/* 0x61 */ NORMAL("pcmpestri", XMM, XMMM128, IMM8)
	/* 0x62 */ NORMAL("pcmpistrm", XMM, XMMM128, IMM8)
	/* 0x63 */ NORMAL("pcmpistri", XMM, XMMM128, IMM8)
	/* 0x64 */ UNKNOWN()
	/* 0x65 */ UNKNOWN()
	/* 0x66 */ UNKNOWN()
	/* 0x67 */ UNKNOWN()
	/* 0x68 */ UNKNOWN()
	/* 0x69 */ UNKNOWN()
	/* 0x6A */ UNKNOWN()
	/* 0x6B */ UNKNOWN()
	/* 0x6C */ UNKNOWN()
	/* 0x6D */ UNKNOWN()
	/* 0x6E */ UNKNOWN()
	/* 0x6F */ UNKNOWN()
	/* 0x70 */ UNKNOWN()
	/* 0x71 */ UNKNOWN()
	/* 0x72 */ UNKNOWN()
	/* 0x73 */ UNKNOWN()
	/* 0x74 */ UNKNOWN()
	/* 0x75 */ UNKNOWN()
	/* 0x76 */ UNKNOWN()
	/* 0x77 */ UNKNOWN()
	/* 0x78 */ UNKNOWN()
	/* 0x79 */ UNKNOWN()
	/* 0x7A */ UNKNOWN()
	/* 0x7B */ UNKNOWN()
	/* 0x7C */ UNKNOWN()
	/* 0x7D */ UNKNOWN()
	/* 0x7E */ UNKNOWN()
	/* 0x7F */ UNKNOWN()
	/* 0x80 */ UNKNOWN()
	/* 0x81 */ UNKNOWN()
	/* 0x82 */ UNKNOWN()
	/* 0x83 */ UNKNOWN()
	/* 0x84 */ UNKNOWN()
	/* 0x85 */ UNKNOWN()
	/* 0x86 */ UNKNOWN()
	/* 0x87 */ UNKNOWN()
	/* 0x88 */ UNKNOWN()
	/* 0x89 */ UNKNOWN()
	/* 0x8A */ UNKNOWN()
	/* 0x8B */ UNKNOWN()
	/* 0x8C */ UNKNOWN()
	/* 0x8D */ UNKNOWN()
	/* 0x8E */ UNKNOWN()
	/* 0x8F */ UNKNOWN()
	/* 0x90 */ UNKNOWN()
	/* 0x91 */ UNKNOWN()
	/* 0x92 */ UNKNOWN()
	/* 0x93 */ UNKNOWN()
	/* 0x94 */ UNKNOWN()
	/* 0x95 */ UNKNOWN()
	/* 0x96 */ UNKNOWN()
	/* 0x97 */ UNKNOWN()
	/* 0x98 */ UNKNOWN()
	/* 0x99 */ UNKNOWN()
	/* 0x9A */ UNKNOWN()
	/* 0x9B */ UNKNOWN()
	/* 0x9C */ UNKNOWN()
	/* 0x9D */ UNKNOWN()
	/* 0x9E */ UNKNOWN()
	/* 0x9F */ UNKNOWN()
	/* 0xA0 */ UNKNOWN()
	/* 0xA1 */ UNKNOWN()
	/* 0xA2 */ UNKNOWN()
	/* 0xA3 */ UNKNOWN()
	/* 0xA4 */ UNKNOWN()
	/* 0xA5 */ UNKNOWN()
	/* 0xA6 */ UNKNOWN()
	/* 0xA7 */ UNKNOWN()
	/* 0xA8 */ UNKNOWN()
	/* 0xA9 */ UNKNOWN()
	/* 0xAA */ UNKNOWN()
	/* 0xAB */ UNKNOWN()
	/* 0xAC */ UNKNOWN()
	/* 0xAD */ UNKNOWN()
	/* 0xAE */ UNKNOWN()
	/* 0xAF */ UNKNOWN()
	/* 0xB0 */ UNKNOWN()
	/* 0xB1 */ UNKNOWN()
	/* 0xB2 */ UNKNOWN()
	/* 0xB3 */ UNKNOWN()
	/* 0xB4 */ UNKNOWN()
	/* 0xB5 */ UNKNOWN()
	/* 0xB6 */ UNKNOWN()
	/* 0xB7 */ UNKNOWN()
	/* 0xB8 */ UNKNOWN()
	/* 0xB9 */ UNKNOWN()
	/* 0xBA */ UNKNOWN()
	/* 0xBB */ UNKNOWN()
	/* 0xBC */ UNKNOWN()
	/* 0xBD */ UNKNOWN()
	/* 0xBE */ UNKNOWN()
	/* 0xBF */ UNKNOWN()
	/* 0xC0 */ UNKNOWN()
	/* 0xC1 */ UNKNOWN()
	/* 0xC2 */ UNKNOWN()
	/* 0xC3 */ UNKNOWN()
	/* 0xC4 */ UNKNOWN()
	/* 0xC5 */ UNKNOWN()
	/* 0xC6 */ UNKNOWN()
	/* 0xC7 */ UNKNOWN()
	/* 0xC8 */ UNKNOWN()
	/* 0xC9 */ UNKNOWN()
	/* 0xCA */ UNKNOWN()
	/* 0xCB */ UNKNOWN()
	/* 0xCC */ UNKNOWN()
	/* 0xCD */ UNKNOWN()
	/* 0xCE */ UNKNOWN()
	/* 0xCF */ UNKNOWN()
	/* 0xD0 */ UNKNOWN()
	/* 0xD1 */ UNKNOWN()
	/* 0xD2 */ UNKNOWN()
	/* 0xD3 */ UNKNOWN()
	/* 0xD4 */ UNKNOWN()
	/* 0xD5 */ UNKNOWN()
	/* 0xD6 */ UNKNOWN()
	/* 0xD7 */ UNKNOWN()
	/* 0xD8 */ UNKNOWN()
	/* 0xD9 */ UNKNOWN()
	/* 0xDA */ UNKNOWN()
	/* 0xDB */ UNKNOWN()
	/* 0xDC */ UNKNOWN()
	/* 0xDD */ UNKNOWN()
	/* 0xDE */ UNKNOWN()
	/* 0xDF */ UNKNOWN()
	/* 0xE0 */ UNKNOWN()
	/* 0xE1 */ UNKNOWN()
	/* 0xE2 */ UNKNOWN()
	/* 0xE3 */ UNKNOWN()
	/* 0xE4 */ UNKNOWN()
	/* 0xE5 */ UNKNOWN()
	/* 0xE6 */ UNKNOWN()
	/* 0xE7 */ UNKNOWN()
	/* 0xE8 */ UNKNOWN()
	/* 0xE9 */ UNKNOWN()
	/* 0xEA */ UNKNOWN()
	/* 0xEB */ UNKNOWN()
	/* 0xEC */ UNKNOWN()
	/* 0xED */ UNKNOWN()
	/* 0xEE */ UNKNOWN()
	/* 0xEF */ UNKNOWN()
	/* 0xF0 */ UNKNOWN()
	/* 0xF1 */ UNKNOWN()
	/* 0xF2 */ UNKNOWN()
	/* 0xF3 */ UNKNOWN()
	/* 0xF4 */ UNKNOWN()
	/* 0xF5 */ UNKNOWN()
	/* 0xF6 */ UNKNOWN()
	/* 0xF7 */ UNKNOWN()
	/* 0xF8 */ UNKNOWN()
	/* 0xF9 */ UNKNOWN()
	/* 0xFA */ UNKNOWN()
	/* 0xFB */ UNKNOWN()
	/* 0xFC */ UNKNOWN()
	/* 0xFD */ UNKNOWN()
	/* 0xFE */ UNKNOWN()
	/* 0xFF */ UNKNOWN()
};
