#include "fork.h"
#include "mm.h"
#include "process.h"
#include "syscall.h"
#include <log.h>
#include <common/sched.h>

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
	CONTEXT context;
	void *stack_base;
};

static struct fork_info * const fork = FORK_INFO_BASE;

__declspec(noreturn) static void restore_fork_context()
{
	install_syscall_handler();
	process_init(fork->stack_base);
	__asm
	{
		mov ecx, [FORK_INFO_BASE + CONTEXT.Ecx]
		mov edx, [FORK_INFO_BASE + CONTEXT.Edx]
		mov ebx, [FORK_INFO_BASE + CONTEXT.Ebx]
		mov esi, [FORK_INFO_BASE + CONTEXT.Esi]
		mov edi, [FORK_INFO_BASE + CONTEXT.Edi]
		mov esp, [FORK_INFO_BASE + CONTEXT.Esp]
		mov ebp, [FORK_INFO_BASE + CONTEXT.Ebp]
		xor eax, eax
		mov gs, ax
		push [FORK_INFO_BASE + CONTEXT.Eip]
		ret
	}
}

void fork_init()
{
	if (!strcmp(GetCommandLineA(), "/?/fork"))
	{
		/* We're a fork child */
		restore_fork_context();
	}
	else
	{
		/* Allocate fork_info memory to avoid possible VirtualAlloc() collision */
		VirtualAlloc(FORK_INFO_BASE, BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		/* Return control flow to main() */
	}
}

static pid_t fork_process(PCONTEXT context)
{
	wchar_t filename[MAX_PATH];
	GetModuleFileNameW(NULL, filename, sizeof(filename));

	PROCESS_INFORMATION info;
	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	if (!CreateProcessW(filename, L"/?/fork", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
	{
		log_debug("fork(): CreateProcessW() failed.\n");
		return -1;
	}

	if (!mm_fork(info.hProcess))
		goto fail;

	/* Set up fork_info in child process */
	void *stack_base = process_get_stack_base();
	VirtualAllocEx(info.hProcess, FORK_INFO_BASE, BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(info.hProcess, FORK_INFO_BASE, context, sizeof(CONTEXT), NULL);
	WriteProcessMemory(info.hProcess, FORK_INFO_BASE + sizeof(CONTEXT), &stack_base, sizeof(stack_base), NULL);

	/* Copy stack */
	VirtualAllocEx(info.hProcess, stack_base, STACK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(info.hProcess, context->Esp, context->Esp, (char *)stack_base + STACK_SIZE - context->Esp, NULL);

	ResumeThread(info.hThread);

	CloseHandle(info.hThread);
	CloseHandle(info.hProcess);
	return info.dwProcessId;

fail:
	TerminateProcess(info.hProcess, 0);
	CloseHandle(info.hThread);
	CloseHandle(info.hProcess);
	return -1;
}

pid_t sys_fork(int _1, int _2, int _3, int _4, int _5, PCONTEXT context)
{
	log_debug("fork()\n");
	return fork_process(context);
}

pid_t sys_clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, struct pt_regs *_regs, PCONTEXT context)
{
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
	   o CLONE_CHILD_SETTID
	   o CLONE_NEWUTS
	   o CLONE_NEWIPC
	   o CLONE_NEWUSER
	   o CLONE_NEWPID
	   o CLONE_NEWNET
	   o CLONE_IO
	 */
	log_debug("sys_clone(flags=%x, child_stack=%x, ptid=%x, ctid=%x)\n", flags, child_stack, ptid, ctid);
	if (flags & CLONE_THREAD)
	{
		log_debug("Threads not supported.\n");
		return -1;
	}
	else
		return fork_process(context);
}
