#pragma once

#include <Windows.h>

int do_execve(const char *filename, int argc, char *argv[], int env_size, char *envp[], PCONTEXT context);
