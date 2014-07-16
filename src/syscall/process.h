#ifndef _SYSCALL_PROCESS_H
#define _SYSCALL_PROCESS_H

#include <common/types.h>
#include <common/utsname.h>

pid_t sys_getpid();

uid_t sys_getuid();
gid_t sys_getgid();
uid_t sys_geteuid();
gid_t sys_getegid();

void sys_exit(int status);
int sys_oldolduname(struct oldold_utsname *buf);
int sys_olduname(struct old_utsname *buf);
int sys_uname(struct utsname *buf);

#endif
