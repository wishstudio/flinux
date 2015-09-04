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

#include <common/inotify.h>
#include <fs/file.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/vfs.h>
#include <heap.h>
#include <log.h>

struct inotify_file
{
	struct file base_file;
};

static int inotify_close(struct file *f)
{
	struct inotify_file *inotify = (struct inotify_file *)f;
	kfree(inotify, sizeof(struct inotify_file));
	return 0;
}

static int inotify_get_poll_status(struct file *f)
{
	return 0;
}

static int inotify_stat(struct file *f, struct newstat *buf)
{
	struct inotify_file *inotify = (struct inotify_file *)f;
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = 0;
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0644;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = 0;
	buf->st_size = 0;
	buf->st_blksize = PAGE_SIZE;
	buf->st_blocks = 0;
	buf->st_atime = 0;
	buf->st_atime_nsec = 0;
	buf->st_mtime = 0;
	buf->st_mtime_nsec = 0;
	buf->st_ctime = 0;
	buf->st_ctime_nsec = 0;
	return 0;
}

static struct file_ops inotify_ops =
{
	.get_poll_status = inotify_get_poll_status,
	.close = inotify_close,
	.stat = inotify_stat,
};

static int inotify_init1(int flags)
{
	struct inotify_file *inotify = (struct inotify_file *)kmalloc(sizeof(struct inotify_file));
	int fl = 0;
	if (flags & IN_NONBLOCK)
		fl |= O_NONBLOCK;
	file_init(&inotify->base_file, &inotify_ops, fl);
	int fd = vfs_store_file((struct file *)inotify, flags & IN_CLOEXEC);
	if (fd < 0)
		vfs_release((struct file *)inotify);
	return fd;
}

DEFINE_SYSCALL(inotify_init)
{
	log_info("inotify_init()\n");
	return inotify_init1(0);
}

DEFINE_SYSCALL(inotify_init1, int, flags)
{
	log_info("inotify_init1(%d)\n", flags);
	return inotify_init1(flags);
}

DEFINE_SYSCALL(inotify_add_watch, int, fd, const char *, pathname, uint32_t, mask)
{
	log_info("inotify_add_watch(%d, \"%s\", %x)\n", fd, pathname, mask);
	return 0;
}

DEFINE_SYSCALL(inotify_rm_watch, int, fd, int, wd)
{
	log_info("inotify_rm_watch(%d, %d)\n", fd, wd);
	return 0;
}
