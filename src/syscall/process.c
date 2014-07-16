#include "process.h"
#include "err.h"
#include "../log.h"

#include <Windows.h>

pid_t sys_getpid()
{
	log_debug("getpid(): %d\n", GetCurrentProcessId());
	return GetCurrentProcessId();
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
	exit(status);
}
