#pragma once

#include <stdint.h>

#define DEFINE_SYSCALL(name) intptr_t sys_##name

void install_syscall_handler();
