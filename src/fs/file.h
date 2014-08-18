#pragma once

#include <common/types.h>
#include <common/stat.h>
#include <common/dirent.h>

#include <Windows.h>

struct file_ops
{
	HANDLE (*get_handle)(struct file *f);
	int (*close)(struct file *f);
	size_t (*read)(struct file *f, char *buf, size_t count);
	size_t (*write)(struct file *f, const char *buf, size_t count);
	int (*stat)(struct file *f, struct stat64 *buf);
	int (*getdents)(struct file *f, struct linux_dirent64 *dirent, int count);
	int (*ioctl)(struct file *f, unsigned int cmd, unsigned long arg);
};

struct file
{
	struct file_ops *op_vtable;
	uint32_t ref;
};

struct file_system
{
	struct file_system *next;
	char *mountpoint;
	int (*open)(const char *path, int flags, int mode, struct file **fp, char *target, int buflen);
	int (*symlink)(const char *target, const char *linkpath);
	size_t (*readlink)(const char *pathname, char *buf, size_t bufsize);
	int (*is_symlink)(const char *pathname, char *target, int buflen);
	int (*unlink)(const char *pathname);
};
