#ifndef _FS_TTY_H
#define _FS_TTY_H

#include "fp.h"
#include <Windows.h>

struct tty_fp
{
	struct fp base_fp;
	HANDLE file_handle;
};

struct fp *tty_alloc(HANDLE file_handle);

#endif
