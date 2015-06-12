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

#include <common/types.h>
#include <common/utsname.h>
#include <lib/slist.h>

#include <stdbool.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define STACK_SIZE	1048576

void process_init();
void process_after_fork(void *stack_base, pid_t pid);
void process_shutdown();
void *process_get_stack_base();
pid_t process_init_child(DWORD win_pid, DWORD win_tid, HANDLE process_handle);

__declspec(noreturn) void process_exit(int exit_code, int exit_signal);
bool process_pid_exist(pid_t pid);
pid_t process_get_pid();
pid_t process_get_ppid();
pid_t process_get_tgid(pid_t pid);
pid_t process_get_pgid(pid_t pid);
pid_t process_get_sid();

enum
{
	PROCESS_QUERY_STAT,		/* /proc/[pid]/stat */
};
int process_query(int query_type, char *buf);
int process_query_pid(pid_t pid, int query_type, char *buf);
