#pragma once

#include <fs/file.h>

#include <Windows.h>

int pipe_alloc(struct file **fread, struct file **fwrite, int flags);
