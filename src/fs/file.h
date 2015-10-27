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

#include <stdbool.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define GETDENTS_UTF8	1
#define GETDENTS_UTF16	2

#define GETDENTS_ERR_BUFFER_OVERFLOW	-100
typedef intptr_t getdents_callback(void *buffer, uint64_t inode, const void *name, int namelen, char type, size_t size, int flags);

struct file_ops
{
	/* Polling functions */
	int (*get_poll_status)(struct file *f);
	HANDLE (*get_poll_handle)(struct file *f, int *poll_events);
	/* After fork handler */
	void (*after_fork)(struct file *f);
	/* General file operations */
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
	/* Socket functions */
	int (*bind)(struct file *f, const struct sockaddr *addr, int addrlen);
	int (*connect)(struct file *f, const struct sockaddr *addr, size_t addrlen);
	int (*listen)(struct file *f, int backlog);
	int (*accept)(struct file *f, struct sockaddr *addr, int *addrlen);
	int (*getsockname)(struct file *f, struct sockaddr *addr, int *addrlen);
	int (*getpeername)(struct file *f, struct sockaddr *addr, int *addrlen);
	size_t (*sendto)(struct file *f, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, int addrlen);
	size_t (*recvfrom)(struct file *f, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen);
	int (*shutdown)(struct file *f, int how);
	int (*setsockopt)(struct file *f, int level, int optname, const void *optval, int optlen);
	int (*getsockopt)(struct file *f, int level, int optname, void *optval, int *optlen);
	size_t (*sendmsg)(struct file *f, const struct msghdr *msg, int flags);
	size_t (*recvmsg)(struct file *f, struct msghdr *msg, int flags);
	int (*sendmmsg)(struct file *f, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags);
	int (*recvmmsg)(struct file *f, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout);
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
	int (*open)(struct mount_point *mp, const char *path, int flags, int internal_flags, int mode, struct file **fp, char *target, int buflen);
	int (*symlink)(struct mount_point *mp, const char *target, const char *linkpath);
	int (*link)(struct mount_point *mp, struct file *f, const char *newpath);
	int (*unlink)(struct mount_point *mp, const char *pathname);
	int (*rename)(struct mount_point *mp, struct file *f, const char *newpath);
	int (*mkdir)(struct mount_point *mp, const char *pathname, int mode);
	int (*rmdir)(struct mount_point *mp, const char *pathname);
};

struct mount_point
{
	union
	{
		/* This struct is used in shared storage of mount points.
		 * Due to the reason that the shared storage may be mapped to different
		 * virtual addresses in different processes, only relative offsets can be
		 * used here.
		 */
		struct
		{
			volatile bool used; /* Whether this entry is used */
			volatile int next; /* Id of next entry in shared storage */
			int fs_id; /* Id of file system in */
		};
		/* The pointer to the actual file system object.
		 * This is only used on passing mount point info to vfs functions,
		 * Since the individual file system implementations do not have access to
		 * vfs file system table.
		 */
		struct file_system *fs;
	};
	int key; /* Global id which can be used to uniquely identify this mount point */
	bool is_system;
	int win_path_len;
	WCHAR win_path[MAX_PATH];
	int mountpoint_len;
	char mountpoint[MAX_PATH];
};
