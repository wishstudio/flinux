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

#include <common/signal.h>
#include <common/sigcontext.h>

#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct syscall_context
{
	/* DO NOT REORDER */
	/* Context for fork() */
	DWORD ebx;
	DWORD ecx;
	DWORD edx;
	DWORD esi;
	DWORD edi;
	DWORD ebp;
	DWORD esp;
	DWORD eip;

	/* The following are not used by fork() */
	DWORD eax;
	DWORD eflags;
};

void dbt_init();
void dbt_reset();
void dbt_shutdown();

void __declspec(noreturn) dbt_run(size_t pc, size_t sp);
void __declspec(noreturn) dbt_restore_fork_context(struct syscall_context *context);

/* Deliver the signal to the main thread's context
 * This function can only called from the signal thread */
void dbt_deliver_signal(HANDLE thread, CONTEXT *context);

/* Return from signal */
void __declspec(noreturn) dbt_sigreturn(struct sigcontext *context);
