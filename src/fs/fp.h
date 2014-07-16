#ifndef _FS_FP_H
#define _FS_FP_H

#include <common/types.h>
#include <common/stat.h>

struct file_ops
{
	size_t (*fn_read)(struct fp *f, char *buf, size_t count);
	size_t (*fn_write)(struct fp *f, const char *buf, size_t count);
	int (*fn_stat)(struct fp *f, struct stat64 *buf);
	int (*fn_ioctl)(struct fp *f, unsigned int cmd, unsigned long arg);
};

struct fp
{
	struct file_ops *op_vtable;
	off_t offset;
};

#endif
