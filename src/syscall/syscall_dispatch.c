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

#include <syscall/process.h>
#include <syscall/syscall.h>
#include <syscall/syscall_dispatch.h>
#include <log.h>

#include <stdint.h>

#ifdef _WIN64

typedef int64_t syscall_fn(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, intptr_t r8, intptr_t r9, PCONTEXT context);

#define SYSCALL_COUNT 323
#define SYSCALL(name) extern int64_t sys_##name(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, intptr_t r8, intptr_t r9, PCONTEXT context);
SYSCALL(read) /* syscall 0 */
#include "syscall_table_x64.h"
#undef SYSCALL

#define SYSCALL(name) sys_##name,
static syscall_fn* syscall_table[SYSCALL_COUNT] =
{
	SYSCALL(read) /* syscall 0 */
#include "syscall_table_x64.h"
};
#undef SYSCALL

#else

typedef int syscall_fn(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context);

#define SYSCALL_COUNT 359
#define SYSCALL(name) extern int sys_##name(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context);
#include "syscall_table_x86.h"
#undef SYSCALL

#define SYSCALL(name) sys_##name,
syscall_fn* syscall_table[SYSCALL_COUNT] =
{
	SYSCALL(unimplemented) /* syscall 0 */
#include "syscall_table_x86.h"
};
#undef SYSCALL
#endif

void sys_unimplemented_imp(intptr_t id)
{
	log_error("FATAL: Unimplemented syscall: %d\n", id);
	__debugbreak();
	process_exit(1, 0);
}

void dispatch_syscall(PCONTEXT context)
{
#ifdef _WIN64
	context->Rax = (*syscall_table[context->Rax])(context->Rdi, context->Rsi, context->Rdx, context->R10, context->R8, context->R9, context);
#endif
}
