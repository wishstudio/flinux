#pragma once

#include <fs/file.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void console_init();
int console_fork(HANDLE process);

int console_alloc(struct file **in_file, struct file **out_file);
