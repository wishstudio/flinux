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

#include <common/sched.h>
#include <common/types.h>
#include <common/ptrace.h>
#include <dbt/x86.h>
#include <syscall/fork.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/syscall.h>
#include <syscall/tls.h>
#include <heap.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/* Fork process
 *
 * 1. Create a process using CreateProcessW() and set command line to the special "/?/fork"
 * 2. Call mm_fork() to initialize memory mappings in the child process
 * 3. Set up fork_info
 * 4. Copy thread stack
 * 5. Wake up child process, it will use fork_info to restore context
 */

struct fork_info
{
	struct syscall_context context;
	void *stack_base;
	void *ctid;
	pid_t pid;
} _fork;

static struct fork_info *fork = &_fork;

__declspec(noreturn) static void fork_child()
{
	install_syscall_handler();
	mm_afterfork();
	heap_afterfork();
	signal_afterfork();
	process_afterfork(fork->stack_base, fork->pid);
	tls_afterfork();
	vfs_afterfork();
	dbt_init();
	if (fork->ctid)
		*(pid_t *)fork->ctid = fork->pid;
	dbt_restore_fork_context(&fork->context);
}

void fork_init()
{
	if (!strcmp(GetCommandLineA(), "/?/fork"))
	{
		/* We're a fork child */
		log_info("We're a fork child.\n");
		fork_child();
	}
	else
	{
#ifdef _WIN64
		/* On Win64, the default base address for ET_EXEC executable is 0x400000
		 * which is problematic that sometimes win32 dlls will allocate memory there
		 * To workaround this issue, we first check if the address space there is
		 * occupied. If so, we create a suspended child process and pre-reserve
		 * the memory region, then transfer control to the child process.
		 * The child process detects such circumstances and release the preserved
		 * memory before use.
		 */
		size_t region_start = 0x400000;
		size_t region_size = 0x10000000; /* 256MB maximum executable size */
		MEMORY_BASIC_INFORMATION info;
		VirtualQuery(region_start, &info, sizeof(MEMORY_BASIC_INFORMATION));
		if (info.State == MEM_FREE && info.RegionSize >= region_size)
		{
			/* That's good, reserve the space now */
			VirtualAlloc(region_start, region_size, MEM_RESERVE, PAGE_NOACCESS);
		}
		else if (info.State == MEM_RESERVE && info.RegionSize == region_size)
		{
			/* We're a child who has the pages protected by the parent, nothing to do here */
		}
		else
		{
			/* Not good, create a child process and hope this time we can do it better */
			log_warning("The address %p is occupied, we have to create another process to proceed.\n", region_start);
			wchar_t filename[MAX_PATH];
			GetModuleFileNameW(NULL, filename, sizeof(filename) / sizeof(filename[0]));
			PROCESS_INFORMATION info;
			STARTUPINFOW si = { 0 };
			si.cb = sizeof(si);
			if (!CreateProcessW(filename, GetCommandLineW(), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
			{
				log_error("CreateProcessW() failed, error code: %d\n", GetLastError());
				ExitProcess(1);
			}
			/* Pre-reserve the memory */
			if (!VirtualAllocEx(info.hProcess, region_start, region_size, MEM_RESERVE, PAGE_NOACCESS))
			{
				log_error("VirtualAllocEx() failed, error code: %d\n", GetLastError());
				ExitProcess(1);
			}
			/* All done */
			log_shutdown();
			ResumeThread(info.hThread);
			ExitProcess(0);
		}
#endif
		/* Return control flow to main() */
	}
}

/* Currently supported flags (see sched.h):
 o CLONE_VM
 o CLONE_FS
 o CLONE_SIGHAND
 o CLONE_PTRACE
 o CLONE_VFORK
 o CLONE_PARENT
 o CLONE_THREAD
 o CLONE_NEWNS
 o CLONE_SYSVSEM
 o CLONE_SETTLS
 o CLONE_PARENT_SETTID
 o CLONE_CHILD_CLEARTID
 o CLONE_DETACHED
 o CLONE_UNTRACED
 * CLONE_CHILD_SETTID
 o CLONE_NEWUTS
 o CLONE_NEWIPC
 o CLONE_NEWUSER
 o CLONE_NEWPID
 o CLONE_NEWNET
 o CLONE_IO
*/
static pid_t fork_process(struct syscall_context *context, unsigned long flags, void *ptid, void *ctid)
{
	wchar_t filename[MAX_PATH];
	GetModuleFileNameW(NULL, filename, sizeof(filename) / sizeof(filename[0]));

	tls_beforefork();
	
	PROCESS_INFORMATION info;
	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	if (!CreateProcessW(filename, L"/?/fork", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
	{
		log_warning("fork(): CreateProcessW() failed.\n");
		return -1;
	}

	if (!mm_fork(info.hProcess))
		goto fail;

	if (!vfs_fork(info.hProcess))
		goto fail;

	if (!exec_fork(info.hProcess))
		goto fail;

	pid_t pid = process_add_child(info.dwProcessId, info.hProcess);

	/* Set up fork_info in child process */
	void *stack_base = process_get_stack_base();
	WriteProcessMemory(info.hProcess, &fork->context, context, sizeof(struct syscall_context), NULL);
	WriteProcessMemory(info.hProcess, &fork->stack_base, &stack_base, sizeof(stack_base), NULL);
	WriteProcessMemory(info.hProcess, &fork->pid, &pid, sizeof(pid_t), NULL);
	if (flags & CLONE_CHILD_SETTID)
		WriteProcessMemory(info.hProcess, &fork->ctid, &ctid, sizeof(void*), NULL);

	/* Copy stack */
	VirtualAllocEx(info.hProcess, stack_base, STACK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(info.hProcess, (LPVOID)context->esp, (LPCVOID)context->esp,
		(SIZE_T)((char *)stack_base + STACK_SIZE - context->esp), NULL);
	ResumeThread(info.hThread);
	CloseHandle(info.hThread);

	log_info("Child pid: %d, win_pid: %d\n", pid, info.dwProcessId);
	return pid;

fail:
	TerminateProcess(info.hProcess, 0);
	CloseHandle(info.hThread);
	CloseHandle(info.hProcess);
	return -1;
}

int sys_fork_imp(struct syscall_context *context)
{
	log_info("fork()\n");
	return fork_process(context, 0, NULL, NULL);
}

int sys_vfork_imp(struct syscall_context *context)
{
	log_info("vfork()\n");
	return fork_process(context, 0, NULL, NULL);
}

#ifdef _WIN64
int sys_clone_imp(struct syscall_context *context, unsigned long flags, void *child_stack, void *ptid, void *ctid)
#else
int sys_clone_imp(struct syscall_context *context, unsigned long flags, void *child_stack, void *ptid, int tls, void *ctid)
#endif
{
	log_info("sys_clone(flags=%x, child_stack=%p, ptid=%p, ctid=%p)\n", flags, child_stack, ptid, ctid);
	if (flags & CLONE_THREAD)
	{
		log_error("Threads not supported.\n");
		return -1;
	}
	else
		return fork_process(context, flags, ptid, ctid);
}
