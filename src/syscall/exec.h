#pragma once

#include <Windows.h>

void do_execve(const char *filename, int argc, char *const argv[], char *const envp[], PCONTEXT context);

int sys_execve(const char *filename, char *const argv[], char *const envp[], int _4, int _5, PCONTEXT context);
