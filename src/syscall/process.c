#include <common/errno.h>
#include <common/futex.h>
#include <common/resource.h>
#include <common/wait.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/vfs.h>
#include <syscall/syscall.h>
#include <datetime.h>
#include <log.h>
#include <ntdll.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct child_info
{
	pid_t pid;
	HANDLE handle;
};

#define MAX_CHILD_COUNT 1024
struct process_data
{
	void *stack_base;
	int child_count;
	pid_t child_pids[MAX_CHILD_COUNT];
	/* Use a separated array for handles allows direct WaitForMultipleObjects() invocation */
	HANDLE child_handles[MAX_CHILD_COUNT];
};

static struct process_data *const process = PROCESS_DATA_BASE;

void process_init(void *stack_base)
{
	VirtualAlloc(PROCESS_DATA_BASE, sizeof(struct process_data), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	process->child_count = 0;
	/* TODO: Avoid VirtualAlloc() to reduce potential virtual address space collision */
	if (stack_base)
		process->stack_base = stack_base;
	else
		process->stack_base = VirtualAlloc(NULL, STACK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	log_info("Stack base: 0x%p\n", process->stack_base);
	log_info("Stack top: 0x%p\n", (uint32_t)process->stack_base + STACK_SIZE);
}

void *process_get_stack_base()
{
	return process->stack_base;
}

void process_add_child(pid_t pid, HANDLE handle)
{
	int i = process->child_count++;
	process->child_pids[i] = pid;
	process->child_handles[i] = handle;
}

static pid_t process_wait(pid_t pid, int *status, int options, struct rusage *rusage)
{
	if (options & WNOHANG)
		log_error("Unhandled option WNOHANG\n");
	if (options & WUNTRACED)
		log_error("Unhandled option WUNTRACED\n");
	if (options & WCONTINUED)
		log_error("Unhandled option WCONTINUED\n");
	if (rusage)
		log_error("rusage not supported.\n");
	int id = -1;
	if (pid > 0)
	{
		for (int i = 0; i < process->child_count; i++)
			if (process->child_pids[i] == pid)
			{
				DWORD result = WaitForSingleObject(process->child_handles[i], INFINITE);
				id = i;
				break;
			}
		if (id == -1)
		{
			log_warning("pid %d is not a child.\n", pid);
			return -ECHILD;
		}
	}
	else if (pid == -1)
	{
		if (process->child_count == 0)
		{
			log_warning("No childs.\n");
			return -ECHILD;
		}
		DWORD result = WaitForMultipleObjects(process->child_count, process->child_handles, FALSE, INFINITE);
		if (result < WAIT_OBJECT_0 || result >= WAIT_OBJECT_0 + process->child_count)
		{
			log_error("WaitForMultipleObjects(): Unexpected return.\n");
			return -1;
		}
		id = result - WAIT_OBJECT_0;
	}
	else
	{
		log_error("pid != %d unhandled\n");
		return -EINVAL;
	}
	DWORD exitCode;
	GetExitCodeProcess(process->child_handles[id], &exitCode);
	CloseHandle(process->child_handles[id]);
	pid = process->child_pids[id];
	for (int i = id; i + 1 < process->child_count; i++)
	{
		process->child_pids[i] = process->child_pids[i + 1];
		process->child_handles[i] = process->child_handles[i + 1];
	}
	process->child_count--;
	if (status)
		*status = W_EXITCODE(exitCode, 0);
	return pid;
}

DEFINE_SYSCALL(waitpid, pid_t, pid, int *, status, int, options)
{
	log_info("sys_waitpid(%d, %p, %d)\n", pid, status, options);
	return process_wait(pid, status, options, NULL);
}

DEFINE_SYSCALL(wait4, pid_t, pid, int *, status, int, options, struct rusage *, rusage)
{
	log_info("sys_wait4(%d, %p, %d, %p)\n", pid, status, options, rusage);
	if (rusage)
		log_error("rusage != NULL\n");
	return process_wait(pid, status, options, rusage);
}

DEFINE_SYSCALL(getpid)
{
	log_info("getpid(): %d\n", GetCurrentProcessId());
	return GetCurrentProcessId();
}

DEFINE_SYSCALL(getppid)
{
	log_info("getppid(): %d\n", 0);
	return 0;
}

DEFINE_SYSCALL(setpgid, pid_t, pid, pid_t, pgid)
{
	log_info("setpgid(%d, %d)\n", pid, pgid);
	return 0;
}

DEFINE_SYSCALL(getpgid, pid_t, pid)
{
	log_info("getpgid(%d): %d\n", pid, 0);
	return 0;
}

DEFINE_SYSCALL(getpgrp)
{
	pid_t pgrp = GetCurrentProcessId();
	log_info("getpgrp(): %d\n", pgrp);
	return pgrp;
}

DEFINE_SYSCALL(gettid)
{
	pid_t tid = GetCurrentThreadId();
	log_info("gettid(): %d\n", tid);
	return tid;
}

DEFINE_SYSCALL(setsid)
{
	log_info("setsid().\n");
	log_error("setsid() not implemented.\n");
	return 0;
}

DEFINE_SYSCALL(getuid)
{
	log_info("getuid(): %d\n", 0);
	return 0;
}

DEFINE_SYSCALL(getgid)
{
	log_info("getgid(): %d\n", 0);
	return 0;
}

DEFINE_SYSCALL(geteuid)
{
	log_info("geteuid(): %d\n", 0);
	return 0;
}

DEFINE_SYSCALL(getegid)
{
	log_info("getegid(): %d\n", 0);
	return 0;
}

DEFINE_SYSCALL(setuid, uid_t, uid)
{
	log_info("setuid(%d)\n", uid);
	return -EPERM;
}

DEFINE_SYSCALL(exit, int, status)
{
	log_info("exit(%d)\n", status);
	/* TODO: Gracefully shutdown mm, vfs, etc. */
	log_shutdown();
	ExitProcess(status);
}

DEFINE_SYSCALL(exit_group, int, status)
{
	log_info("exit_group(%d)\n", status);
	/* TODO: Gracefully shutdown mm, vfs, etc. */
	log_shutdown();
	ExitProcess(status);
}

DEFINE_SYSCALL(uname, struct utsname *, buf)
{
	log_info("sys_uname(%p)\n", buf);
	if (!mm_check_write(buf, sizeof(struct utsname)))
		return -EFAULT;
	/* Just mimic a reasonable Linux uname */
	strcpy(buf->sysname, "Linux");
	strcpy(buf->nodename, "ForeignLinux");
	strcpy(buf->release, "3.15.0");
	strcpy(buf->version, "3.15.0");
#ifdef _WIN64
	strcpy(buf->machine, "x86_64");
#else
	strcpy(buf->machine, "i686");
#endif
	strcpy(buf->domainname, "GNU/Linux");
	return 0;
}

DEFINE_SYSCALL(olduname, struct old_utsname *, buf)
{
	if (!mm_check_write(buf, sizeof(struct old_utsname)))
		return -EFAULT;
	struct utsname newbuf;
	sys_uname(&newbuf);
	strcpy(buf->sysname, newbuf.sysname);
	strcpy(buf->nodename, newbuf.nodename);
	strcpy(buf->release, newbuf.release);
	strcpy(buf->version, newbuf.version);
	strcpy(buf->machine, newbuf.machine);
	return 0;
}

DEFINE_SYSCALL(oldolduname, struct oldold_utsname *, buf)
{
	if (!mm_check_write(buf, sizeof(struct oldold_utsname)))
		return -EFAULT;
	struct utsname newbuf;
	sys_uname(&newbuf);
	strncpy(buf->sysname, newbuf.sysname, __OLD_UTS_LEN + 1);
	strncpy(buf->nodename, newbuf.nodename, __OLD_UTS_LEN + 1);
	strncpy(buf->release, newbuf.release, __OLD_UTS_LEN + 1);
	strncpy(buf->version, newbuf.version, __OLD_UTS_LEN + 1);
	strncpy(buf->machine, newbuf.machine, __OLD_UTS_LEN + 1);
	return 0;
}

DEFINE_SYSCALL(getrlimit, int, resource, struct rlimit *, rlim)
{
	log_info("getrlimit(%d, %p)\n", resource, rlim);
	if (!mm_check_write(rlim, sizeof(struct rlimit)))
		return -EFAULT;
	switch (resource)
	{
	case RLIMIT_STACK:
		rlim->rlim_cur = STACK_SIZE;
		rlim->rlim_max = STACK_SIZE;
		break;

	case RLIMIT_NPROC:
		log_info("RLIMIT_NPROC: return fake result.\n");
		rlim->rlim_cur = 65536;
		rlim->rlim_max = 65536;
		break;

	case RLIMIT_NOFILE:
		rlim->rlim_cur = MAX_FD_COUNT;
		rlim->rlim_max = MAX_FD_COUNT;
		break;

	default:
		log_error("Unsupported resource: %d\n", resource);
		return -EINVAL;
	}
	return 0;
}

DEFINE_SYSCALL(setrlimit, int, resource, const struct rlimit *, rlim)
{
	log_info("setrlimit(%d, %p)\n", resource, rlim);
	if (!mm_check_read(rlim, sizeof(struct rlimit)))
		return -EFAULT;
	switch (resource)
	{
	default:
		log_error("Unsupported resource: %d\n", resource);
		return -EINVAL;
	}
}

DEFINE_SYSCALL(getrusage, int, who, struct rusage *, usage)
{
	log_info("getrusage(%d, %p)\n", who, usage);
	if (!mm_check_write(usage, sizeof(struct rusage)))
		return -EFAULT;
	ZeroMemory(usage, sizeof(struct rusage));
	switch (who)
	{
	default:
		log_error("Unhandled who: %d.\n", who);
		return -EINVAL;
	}
}

DEFINE_SYSCALL(getpriority, int, which, int, who)
{
	log_info("getpriority(which=%d, who=%d)\n", which, who);
	log_error("getpriority() not implemented. Fake returning 0.\n");
	return 0;
}

DEFINE_SYSCALL(setpriority, int, which, int, who, int, prio)
{
	log_info("setpriority(which=%d, who=%d, prio=%d)\n", which, who, prio);
	log_error("setpriority() not implemented. Fake returning 0.\n");
	return 0;
}

DEFINE_SYSCALL(prctl, int, option, uintptr_t, arg2, uintptr_t, arg3, uintptr_t, arg4, uintptr_t, arg5)
{
	log_info("prctl(%d)\n", option);
	log_error("prctl() not implemented.\n");
	return -ENOSYS;
}

DEFINE_SYSCALL(prlimit64, pid_t, pid, int, resource, const struct rlimit64 *, new_limit, struct rlimit64 *, old_limit)
{
	log_info("prlimit64(pid=%d, resource=%d, new_limit=%p, old_limit=%p)\n", pid, resource, new_limit, old_limit);
	log_error("prlimit64() not implemented.\n");
	return -ENOSYS;
}

DEFINE_SYSCALL(getcpu, unsigned int *, cpu, unsigned int *, node, void *, tcache)
{
	log_info("getcpu(%p, %p, %p)\n", cpu, node, tcache);
	if (cpu)
		*cpu = 0;
	if (node)
		*node = 0;
	return 0;
}

DEFINE_SYSCALL(set_tid_address, int *, tidptr)
{
	log_info("set_tid_address(tidptr=%p)\n", tidptr);
	log_error("clear_child_tid not supported.\n");
	return GetCurrentThreadId();
}

DEFINE_SYSCALL(futex, int *, uaddr, int, op, int, val, const struct timespec *, timeout, int *, uaddr2, int, val3)
{
	log_info("futex(%p, %d, %d, %p, %p, %d)\n", uaddr, op, val, timeout, uaddr2, val3);
	log_error("Unsupported futex operation, returning -ENOSYS\n");
	return -ENOSYS;
}

DEFINE_SYSCALL(set_robust_list, struct robust_list_head *, head, int, len)
{
	log_info("set_robust_list(head=%p, len=%d)\n", head, len);
	if (len != sizeof(struct robust_list_head))
		log_error("len (%d) != sizeof(struct robust_list_head)\n", len);
	log_error("set_robust_list() not supported.\n");
	return 0;
}
