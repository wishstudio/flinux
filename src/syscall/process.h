#pragma once

#include <common/types.h>
#include <common/utsname.h>

#include <Windows.h>

#define STACK_SIZE	1048576

void process_init(void *stack_base);
void process_shutdown();
void *process_get_stack_base();
void process_add_child(pid_t pid, HANDLE handle);
