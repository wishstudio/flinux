#pragma once

#include <common/types.h>
#include <common/utsname.h>

#include <Windows.h>

#define STACK_SIZE	1048576

void process_init(void *stack_base);
void process_shutdown();
void *process_get_stack_base();
void process_add_child(pid_t pid, HANDLE handle);

pid_t sys_waitpid(pid_t pid, int *status, int options);

pid_t sys_getpid();
pid_t sys_getppid();
int setpgid(pid_t pid, pid_t pgid);
pid_t sys_getpgid(pid_t pid);
pid_t sys_getpgrp();

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
int sys_gettimeofday(struct timeval *tv, struct timezone *tz);

int sys_getrlimit(int resource, struct rlimit *rlim);
int sys_setrlimit(int resource, const struct rlimit *rlim);
