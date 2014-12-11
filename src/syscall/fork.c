#include <common/sched.h>
#include <common/types.h>
#include <common/ptrace.h>
#include <syscall/fork.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/syscall.h>
#include <syscall/tls.h>
#include <log.h>

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
	CONTEXT context;
	void *stack_base;
	void *ctid;
};

static struct fork_info * const fork = FORK_INFO_BASE;

__declspec(noreturn) void restore_context(CONTEXT *context);

__declspec(noreturn) static void fork_child()
{
	install_syscall_handler();
	tls_afterfork();
	process_init(fork->stack_base);
	if (fork->ctid)
		*(pid_t *)fork->ctid = GetCurrentProcessId();
	restore_context(&fork->context);
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
			GetModuleFileNameW(NULL, filename, sizeof(filename));
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
		/* Allocate fork_info memory early to avoid possible VirtualAlloc() collision */
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
#ifdef _WIN64
	context->Rax = 0;
#else
	context->Eax = 0;
#endif

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

DEFINE_SYSCALL(fork, int, _1, int, _2, int, _3, int, _4, int, _5, int, _6, PCONTEXT, context)
{
	log_info("fork()\n");
	return fork_process(context, 0, NULL, NULL);
}

DEFINE_SYSCALL(vfork, int, _1, int, _2, int, _3, int, _4, int, _5, int, _6, PCONTEXT, context)
{
	log_info("vfork()\n");
	return fork_process(context, 0, NULL, NULL);
}

#ifdef _WIN64
DEFINE_SYSCALL(clone, unsigned long, flags, void *, child_stack, void *, ptid, void *, ctid, int, _5, int, _6, PCONTEXT, context)
#else
DEFINE_SYSCALL(clone, unsigned long, flags, void *, child_stack, void *, ptid, int, tls, void *, ctid, int, _6, PCONTEXT, context)
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
