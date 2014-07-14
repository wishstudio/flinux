#include "vfs.h"
#include "err.h"
#include "../log.h"

#include <Windows.h>

int sys_stat(const char *pathname, struct stat *buf)
{
	/* TODO */
}

int sys_lstat(const char *pathname, struct stat *buf)
{
	/* TODO */
}

int sys_fstat(int fd, struct stat *buf)
{
	log_debug("fstat(%d, %x)\n", fd, buf);
	/* TODO */
	return EINVAL;
}
