#include <common/errno.h>
#include <common/resource.h>
#include <common/wait.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <datetime.h>
#include <log.h>

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

pid_t sys_waitpid(pid_t pid, int *status, int options)
{
	log_debug("sys_waitpid(%d, %x, %d)\n", pid, status, options);
	if (options & WNOHANG)
		log_debug("Unhandled option WNOHANG\n");
	if (options & WUNTRACED)
		log_debug("Unhandled option WUNTRACED\n");
	if (options & WCONTINUED)
		log_debug("Unhandled option WCONTINUED\n");
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
			log_debug("pid %d is not a child.\n", pid);
			return -ECHILD;
		}
	}
	else if (pid == -1)
	{
		if (process->child_count == 0)
		{
			log_debug("No childs.\n");
			return -ECHILD;
		}
		DWORD result = WaitForMultipleObjects(process->child_count, process->child_handles, FALSE, INFINITE);
		if (result < WAIT_OBJECT_0 || result >= WAIT_OBJECT_0 + process->child_count)
		{
			log_debug("WaitForMultipleObjects(): Unexpected return.\n");
			return -1;
		}
		id = result - WAIT_OBJECT_0;
	}
	else
	{
		log_debug("pid != %d unhandled\n");
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
	*status = W_EXITCODE(exitCode, 0);
	return pid;
}

pid_t sys_getpid()
{
	log_debug("getpid(): %d\n", GetCurrentProcessId());
	return GetCurrentProcessId();
}

pid_t sys_getppid()
{
	log_debug("getppid(): %d\n", 0);
	return 0;
}

int sys_setpgid(pid_t pid, pid_t pgid)
{
	log_debug("setpgid(%d, %d)\n", pid, pgid);
	return 0;
}

pid_t sys_getpgid(pid_t pid)
{
	log_debug("getpgid(%d): %d\n", pid, 0);
	return 0;
}

pid_t sys_getpgrp()
{
	log_debug("getpgrp(): %d\n", 0);
	return 0;
}

uid_t sys_getuid()
{
	log_debug("getuid(): %d\n", 0);
	return 0;
}

gid_t sys_getgid()
{
	log_debug("getgid(): %d\n", 0);
	return 0;
}

uid_t sys_geteuid()
{
	log_debug("geteuid(): %d\n", 0);
	return 0;
}

gid_t sys_getegid()
{
	log_debug("getegid(): %d\n", 0);
	return 0;
}

void sys_exit(int status)
{
	log_debug("exit(%d)\n", status);
	/* TODO: Gracefully shutdown mm, vfs, etc. */
	log_shutdown();
	ExitProcess(status);
}

void sys_exit_group(int status)
{
	log_debug("exit_group(%d)\n", status);
	/* TODO: Gracefully shutdown mm, vfs, etc. */
	log_shutdown();
	ExitProcess(status);
}

int sys_oldolduname(struct oldold_utsname *buf)
{
	struct utsname newbuf;
	sys_uname(&newbuf);
	strncpy(buf->sysname, newbuf.sysname, __OLD_UTS_LEN + 1);
	strncpy(buf->nodename, newbuf.nodename, __OLD_UTS_LEN + 1);
	strncpy(buf->release, newbuf.release, __OLD_UTS_LEN + 1);
	strncpy(buf->version, newbuf.version, __OLD_UTS_LEN + 1);
	strncpy(buf->machine, newbuf.machine, __OLD_UTS_LEN + 1);
	return 0;
}

int sys_olduname(struct old_utsname *buf)
{
	struct utsname newbuf;
	sys_uname(&newbuf);
	strcpy(buf->sysname, newbuf.sysname);
	strcpy(buf->nodename, newbuf.nodename);
	strcpy(buf->release, newbuf.release);
	strcpy(buf->version, newbuf.version);
	strcpy(buf->machine, newbuf.machine);
	return 0;
}

int sys_uname(struct utsname *buf)
{
	log_debug("sys_uname(%x)\n", buf);
	/* Just mimic a reasonable Linux uname */
	strcpy(buf->sysname, "Linux");
	strcpy(buf->nodename, "ForeignLinux");
	strcpy(buf->release, "3.15.0");
	strcpy(buf->version, "3.15.0");
	strcpy(buf->machine, "i386");
	strcpy(buf->domainname, "GNU/Linux");
	return 0;
}

int sys_time(int *c)
{
	log_debug("time(%x)\n", c);
	SYSTEMTIME systime;
	GetSystemTime(&systime);
	uint64_t t = (uint64_t)systime.wSecond + (uint64_t)systime.wMinute * 60
		+ (uint64_t)systime.wHour * 3600 + (uint64_t) systime.wDay * 86400
		+ ((uint64_t)systime.wYear - 70) * 31536000 + (((uint64_t)systime.wYear - 69) / 4) * 86400
		- (((uint64_t)systime.wYear - 1) / 100) * 86400 + (((uint64_t)systime.wYear + 299) / 400) * 86400;

	if (c)
		*c = (int)t;
	return t;
}

int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	log_debug("gettimeofday(0x%x, 0x%x)\n", tv, tz);
	if (tz)
		log_debug("warning: timezone is not NULL\n");
	if (tv)
	{
		/* TODO: Use GetSystemTimePreciseAsFileTime() on Windows 8 */
		FILETIME system_time;
		GetSystemTimeAsFileTime(&system_time);
		filetime_to_unix_timeval(&system_time, tv);
	}
	return 0;
}

int sys_getrlimit(int resource, struct rlimit *rlim)
{
	log_debug("getrlimit(%d, %x)\n", resource, rlim);
	switch (resource)
	{
	case RLIMIT_STACK:
		rlim->rlim_cur = STACK_SIZE;
		rlim->rlim_max = STACK_SIZE;
		break;

	default:
		log_debug("Unsupported resource: %d\n", resource);
		return -EINVAL;
	}
	return 0;
}

int sys_setrlimit(int resource, const struct rlimit *rlim)
{
	log_debug("setrlimit(%d, %x)\n", resource, rlim);
	switch (resource)
	{
	default:
		log_debug("Unsupported resource: %d\n", resource);
		return -EINVAL;
	}
}
