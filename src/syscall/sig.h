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
#include <common/signal.h>
#include <dbt/x86.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

HANDLE signal_get_process_wait_semaphore();
HANDLE signal_get_process_sigwrite();
HANDLE signal_get_process_query_mutex();
void signal_init_child(struct child_process *proc);

void signal_setup_handler(struct syscall_context *context);

void signal_init();
int signal_fork(HANDLE process);
void signal_afterfork_parent();
void signal_afterfork_child();
void signal_shutdown();
void signal_init_thread(struct thread *thread);
int signal_kill(pid_t pid, siginfo_t *siginfo);
DWORD signal_wait(int count, HANDLE *handles, DWORD milliseconds);
void signal_before_pwait(const sigset_t *sigmask, sigset_t *oldmask);
void signal_after_pwait(const sigset_t *oldmask);

/* signal_wait() is interrupted by an incoming signal */
#define WAIT_INTERRUPTED	0x80000000

int signal_query(DWORD win_pid, HANDLE sigwrite, HANDLE query_mutex, int query_type, char *buf);
