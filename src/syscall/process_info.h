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
#include <lib/list.h>
#include <lib/slist.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct child_process
{
	struct slist list;
	pid_t pid;
	HANDLE hProcess, hPipe;
	OVERLAPPED overlapped;
	bool terminated;
};

struct thread
{
	/* Thread list of a process */
	struct list_node list;
	/* pid of thread */
	pid_t pid;
	/* Handle to the thread */
	HANDLE handle;
	/* Stack base of the thread */
	void *stack_base;
	/*********** Signal related information ***********/
	/* Signal mask */
	sigset_t sigmask;
	/* Signal event: set when a signal is arrived.
	 * Used in signal_wait() to detect EINTR conditions */
	HANDLE sigevent;
	/* Current siginfo, this is used as temporary storage when delivering a signal */
	siginfo_t current_siginfo;
	/* Whether the thread can receive signals now
	 * A thread cannot receive signals if a signal ism being delivered to the thread
	 */
	bool can_accept_signal;
};

extern __declspec(thread) struct thread *current_thread;

#define MAX_PROCESS_COUNT		4096
#define MAX_CHILD_COUNT			1024

struct process_data
{
	/* RW lock guard */
	SRWLOCK rw_lock;
	/* pid of this process */
	pid_t pid;
	/* Information of threads of this process */
	int thread_count;
	struct list thread_list, thread_freelist;
	struct thread threads[MAX_PROCESS_COUNT];
	/* Information of child processes */
	int child_count;
	struct slist child_list, child_freelist;
	struct child_process child[MAX_CHILD_COUNT];
	/* Mutex for process_shared_data */
	/* You have to lock this mutex on the following scenarios:
	* 1. When writing to shared area
	* 2. When reading process slots other than the current process
	*
	* TODO: It's better to have a lightweight interprocess RW lock.
	* Windows only provides an intraprocess one.
	*/
	HANDLE shared_mutex;
};

extern struct process_data *const process;

#define PROCESS_NOTEXIST		0 /* The process does not exist */
#define PROCESS_RUNNING			1 /* The process is running normally */
#define PROCESS_ZOMBIE			2 /* The process is a zombie */
struct process_info
{
	/* Status for current slot */
	int status;
	/* Exit code */
	int exit_code : 8;
	/* Exit signal */
	int exit_signal : 8;
	/* Windows process and thread identifier */
	DWORD win_pid, win_tid;
	/* Thread group id (= pid of main thread) */
	pid_t tgid;
	/* Process group id */
	pid_t pgid;
	/* Parent process id */
	pid_t ppid;
	/* Session id */
	pid_t sid;
	/* Handle to sigwrite pipe in the process */
	HANDLE sigwrite;
	/* Handle to information query mutex in the process */
	HANDLE query_mutex;
};
