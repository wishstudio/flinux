#ifndef _FS_FILE_H
#define _FS_FILE_H

#include <common/types.h>
#include <common/stat.h>
#include <common/dirent.h>

struct file_ops
{
	int (*fn_close)(struct file *f);
	size_t (*fn_read)(struct file *f, char *buf, size_t count);
	size_t (*fn_write)(struct file *f, const char *buf, size_t count);
	int (*fn_stat)(struct file *f, struct stat64 *buf);
	int (*fn_getdents)(struct file *f, struct linux_dirent64 *dirent, int count);
	int (*fn_ioctl)(struct file *f, unsigned int cmd, unsigned long arg);
};

struct file
{
	struct file_ops *op_vtable;
	uint32_t ref;
	off_t offset;
};

struct file_system
{
	struct file_system *next;
	char *mountpoint;
	struct file *(*open)(const char *path, int flags, int mode);
};

#endif
