#pragma once

#include <fs/file.h>

#include <Windows.h>

struct file *pipe_alloc(HANDLE handle, int is_read, int flags);
