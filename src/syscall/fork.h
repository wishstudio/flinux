#pragma once

#include <common/types.h>
#include <common/ptrace.h>

#include <Windows.h>

void fork_init();

pid_t sys_fork(int, int, int, int, int, PCONTEXT context);
pid_t sys_clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, struct pt_regs *_regs, PCONTEXT context);
