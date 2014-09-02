#pragma once

#include <Windows.h>

int do_execve(const char *filename, int argc, char *argv[], int env_size, char *envp[], PCONTEXT context);

int sys_execve(const char *filename, char *argv[], char *envp[], int _4, int _5, int _6, PCONTEXT context);
