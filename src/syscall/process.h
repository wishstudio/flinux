#ifndef _SYSCALL_PROCESS_H
#define _SYSCALL_PROCESS_H

#include <common/types.h>
#include <common/utsname.h>

pid_t sys_getpid();
pid_t sys_getppid();
gid_t sys_getpgrp();
gid_t sys_getpgid(pid_t pid);

uid_t sys_getuid();
gid_t sys_getgid();
uid_t sys_geteuid();
gid_t sys_getegid();

void sys_exit(int status);
void sys_exit_group(int status);
int sys_oldolduname(struct oldold_utsname *buf);
int sys_olduname(struct old_utsname *buf);
int sys_uname(struct utsname *buf);

int sys_time(int *r);

#endif
