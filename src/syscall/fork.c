#include <common/sched.h>
#include <syscall/fork.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/syscall.h>
#include <syscall/tls.h>
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
	void *ctid;
};

static struct fork_info * const fork = FORK_INFO_BASE;

__declspec(noreturn) static void restore_fork_context()
{
	install_syscall_handler();
	tls_afterfork();
	process_init(fork->stack_base);
	if (fork->ctid)
		*(pid_t *)fork->ctid = GetCurrentProcessId();
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
		log_info("We're a fork child.\n");
		restore_fork_context();
	}
	else
	{
		/* Allocate fork_info memory to avoid possible VirtualAlloc() collision */
		VirtualAlloc(FORK_INFO_BASE, BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
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
static pid_t fork_process(PCONTEXT context, unsigned long flags, void *ptid, void *ctid)
{
	wchar_t filename[MAX_PATH];
	GetModuleFileNameW(NULL, filename, sizeof(filename));

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

	/* Set up fork_info in child process */
	void *stack_base = process_get_stack_base();
	VirtualAllocEx(info.hProcess, FORK_INFO_BASE, BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(info.hProcess, FORK_INFO_BASE, context, sizeof(CONTEXT), NULL);
	WriteProcessMemory(info.hProcess, FORK_INFO_BASE + sizeof(CONTEXT), &stack_base, sizeof(stack_base), NULL);
	if (flags & CLONE_CHILD_SETTID) /* TODO: Why not directly do it here? */
		WriteProcessMemory(info.hProcess, FORK_INFO_BASE + sizeof(CONTEXT) + sizeof(stack_base), &ctid, sizeof(void*), NULL);

	/* Copy stack */
	VirtualAllocEx(info.hProcess, stack_base, STACK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#ifdef _WIN64
	WriteProcessMemory(info.hProcess, context->Rsp, context->Rsp, (char *)stack_base + STACK_SIZE - context->Rsp, NULL);
#else
	WriteProcessMemory(info.hProcess, context->Esp, context->Esp, (char *)stack_base + STACK_SIZE - context->Esp, NULL);
#endif

	ResumeThread(info.hThread);

	CloseHandle(info.hThread);
	/* Process handled will be used for wait() */
	log_info("Child pid: %d\n", info.dwProcessId);
	process_add_child(info.dwProcessId, info.hProcess);
	return info.dwProcessId;

fail:
	TerminateProcess(info.hProcess, 0);
	CloseHandle(info.hThread);
	CloseHandle(info.hProcess);
	return -1;
}

pid_t sys_fork(int _1, int _2, int _3, int _4, int _5, int _6, PCONTEXT context)
{
	log_info("fork()\n");
	return fork_process(context, 0, NULL, NULL);
}

pid_t sys_vfork(int _1, int _2, int _3, int _4, int _5, int _6, PCONTEXT context)
{
	log_info("vfork()\n");
	return fork_process(context, 0, NULL, NULL);
}

pid_t sys_clone(unsigned long flags, void *child_stack, void *ptid, int tls, void *ctid, int _6, PCONTEXT context)
{
	log_info("sys_clone(flags=%x, child_stack=%x, ptid=%x, ctid=%x)\n", flags, child_stack, ptid, ctid);
	if (flags & CLONE_THREAD)
	{
		log_error("Threads not supported.\n");
		return -1;
	}
	else
		return fork_process(context, flags, ptid, ctid);
}
