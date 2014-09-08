#pragma once

#include <common/signal.h>

int sys_alarm(unsigned int seconds);
int sys_kill(pid_t pid, int sig);
int sys_personality(unsigned long persona);

int sys_rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int sys_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
