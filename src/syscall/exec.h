#pragma once

int do_execve(const char *filename, char *const argv[], char *const envp[]);

int sys_execve(const char *filename, char *const argv[], char *const envp[]);
