#pragma once

#include <common/dirent.h>
#include <common/stat.h>
#include <common/statfs.h>
#include <common/types.h>
#include <common/utime.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef intptr_t getdents_callback(void *buffer, uint64_t inode, const wchar_t *name, int namelen, char type, size_t size);

struct file_ops
{
	int (*get_poll_status)(struct file *f);
	HANDLE (*get_poll_handle)(struct file *f, int *poll_events);
	int (*close)(struct file *f);
	size_t (*read)(struct file *f, char *buf, size_t count);
	size_t (*write)(struct file *f, const char *buf, size_t count);
	size_t (*pread)(struct file *f, char *buf, size_t count, loff_t offset);
	size_t (*pwrite)(struct file *f, const char *buf, size_t count, loff_t offset);
	int (*llseek)(struct file *f, loff_t offset, loff_t *newoffset, int whence);
	int (*stat)(struct file *f, struct newstat *buf);
	int (*utimes)(struct file *f, const struct timeval times[2]);
	int (*getdents)(struct file *f, void *dirent, size_t count, getdents_callback *fill_callback);
	int (*ioctl)(struct file *f, unsigned int cmd, unsigned long arg);
	int (*statfs)(struct file *f, struct statfs64 *buf);
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
	int (*link)(struct file *f, const char *newpath);
	int (*unlink)(const char *pathname);
	int (*rename)(struct file *f, const char *newpath);
	int (*mkdir)(const char *pathname, int mode);
	int (*rmdir)(const char *pathname);
};
