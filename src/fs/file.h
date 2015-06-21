/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <common/dirent.h>
#include <common/stat.h>
#include <common/statfs.h>
#include <common/types.h>
#include <common/utime.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define GETDENTS_UTF8	1
#define GETDENTS_UTF16	2

#define GETDENTS_ERR_BUFFER_OVERFLOW	-100
typedef intptr_t getdents_callback(void *buffer, uint64_t inode, const void *name, int namelen, char type, size_t size, int flags);

struct file_ops
{
	int (*get_poll_status)(struct file *f);
	HANDLE (*get_poll_handle)(struct file *f, int *poll_events);
	void (*after_fork)(struct file *f);
	int (*close)(struct file *f);
	int (*getpath)(struct file *f, char *buf);
	size_t (*read)(struct file *f, void *buf, size_t count);
	size_t (*write)(struct file *f, const void *buf, size_t count);
	size_t (*pread)(struct file *f, void *buf, size_t count, loff_t offset);
	size_t (*pwrite)(struct file *f, const void *buf, size_t count, loff_t offset);
	size_t (*readlink)(struct file *f, char *buf, size_t bufsize);
	int (*truncate)(struct file *f, loff_t length);
	int (*fsync)(struct file *f);
	int (*llseek)(struct file *f, loff_t offset, loff_t *newoffset, int whence);
	int (*stat)(struct file *f, struct newstat *buf);
	int (*utimens)(struct file *f, const struct timespec *times);
	int (*getdents)(struct file *f, void *dirent, size_t count, getdents_callback *fill_callback);
	int (*ioctl)(struct file *f, unsigned int cmd, unsigned long arg);
	int (*statfs)(struct file *f, struct statfs64 *buf);
};

struct file
{
	const struct file_ops *op_vtable;
	int flags;
	uint32_t ref;
	SRWLOCK rw_lock;
};

static void file_init(struct file *f, const struct file_ops *op_vtable, int flags)
{
	f->op_vtable = op_vtable;
	f->flags = flags;
	f->ref = 1;
	InitializeSRWLock(&f->rw_lock);
}

struct file_system
{
	struct file_system *next;
	const char *mountpoint;
	int (*open)(struct file_system *fs, const char *path, int flags, int mode, struct file **fp, char *target, int buflen);
	int (*symlink)(struct file_system *fs, const char *target, const char *linkpath);
	int (*link)(struct file_system *fs, struct file *f, const char *newpath);
	int (*unlink)(struct file_system *fs, const char *pathname);
	int (*rename)(struct file_system *fs, struct file *f, const char *newpath);
	int (*mkdir)(struct file_system *fs, const char *pathname, int mode);
	int (*rmdir)(struct file_system *fs, const char *pathname);
};
