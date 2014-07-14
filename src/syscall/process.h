#ifndef _SYSCALL_PROCESS_H
#define _SYSCALL_PROCESS_H

#include <common/types.h>

pid_t sys_getpid();

uid_t sys_getuid();
gid_t sys_getgid();
uid_t sys_geteuid();
gid_t sys_getegid();

#endif
