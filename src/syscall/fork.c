#include "fork.h"
#include "mm.h"
#include "process.h"
#include "syscall.h"
#include <log.h>

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
	process_set_stack_base(fork->stack_base);
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

pid_t sys_fork(int _1, int _2, int _3, int _4, int _5, PCONTEXT context)
{
	log_debug("fork()\n");
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

	mm_fork(info.hProcess);

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
}
