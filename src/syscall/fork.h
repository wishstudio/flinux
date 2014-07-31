#pragma once

#include <common/types.h>

#include <Windows.h>

void fork_init();

pid_t sys_fork(int, int, int, int, int, PCONTEXT context);
