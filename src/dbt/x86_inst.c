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

int get_imm_bytes(uint8_t op, bool opsize_prefix_present, bool addrsize_prefix_present)
{
	if (op == IMM8 || op == REL8)
		return 1;
	else if (op == IMM16)
		return 2;
	else if (op == IMM16_32 || op == REL16_32 || op == IMM16_32_64)
		return opsize_prefix_present ? 2 : 4;
	else if (op == MOFFS8 || op == MOFFS16_32_64)
		return addrsize_prefix_present ? 2 : 4;
	else
		return 0;
}

/* Keep in sync with implicit register / memory definitions in x86_inst.h */
const uint8_t implicit_register_usage[16] =
{
	/* __ */ 0,
	/* AL */ REG_AX,
	/* AH */ REG_AX,
	/* AX_EAX */ REG_AX,
	/* AX_EAX_RAX */ REG_AX,
	/* CL */ REG_CX,
	/* DX */ REG_DX,
	/* Undefined */ 0,
	/* Undefined */ 0,
	/* Undefined */ 0,
	/* SI_M8 */ REG_SI,
	/* SI_M16_32 */ REG_SI,
	/* SI_M16_32_64 */ REG_SI,
	/* DI_M8 */ REG_DI,
	/* DI_M16_32 */ REG_DI,
	/* DI_M16_32_64 */ REG_DI,
};

uint8_t get_implicit_register_usage(uint8_t op, uint8_t opcode)
{
	if (!FROM_MODRM(op))
	{
		if (op < 16)
			return implicit_register_usage[op];
		else /* OP_Rxx */
			return REG_MASK(op & 8);
	}
	return 0;
}
