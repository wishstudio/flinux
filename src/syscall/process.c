#include "process.h"
#include "err.h"
#include "../log.h"

#include <Windows.h>
#include <time.h>

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

void sys_exit_group(int status)
{
	log_debug("exit_group(%d)\n", status);
	/* TODO: Gracefully shutdown mm, vfs, etc. */
	exit(status);
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
	time_t t = time(NULL);
	if (c)
		*c = (int)t;
	return t;
}
