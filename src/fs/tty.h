#pragma once

#include <fs/file.h>

#include <Windows.h>

struct tty_file
{
	struct file base_file;
	HANDLE file_handle;
};

struct file *tty_alloc(HANDLE file_handle);
