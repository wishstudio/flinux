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

#pragma once

#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct syscall_context
{
	/* Note: should be kept consistent with syscall trampoline in x86_trampoline.asm */
	DWORD ebx;
	DWORD ecx;
	DWORD edx;
	DWORD esi;
	DWORD edi;
	DWORD ebp;
	DWORD esp;
	DWORD eip;
};

void dbt_init();
void dbt_reset();
void dbt_shutdown();

void __declspec(noreturn) dbt_run(size_t pc, size_t sp);
void __declspec(noreturn) dbt_restore_fork_context(struct syscall_context *context);
