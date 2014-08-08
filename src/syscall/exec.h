#pragma once

void do_execve(const char *filename, int argc, char *const argv[], char *const envp[]);

int sys_execve(const char *filename, char *const argv[], char *const envp[]);
