#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void dispatch_syscall(PCONTEXT context);
