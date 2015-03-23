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

#include <common/fcntl.h>
#include <fs/null.h>
#include <heap.h>
#include <log.h>

static int null_dev_close(struct file *f)
{
	kfree(f, sizeof(struct file));
	return 0;
}

static size_t null_dev_read(struct file *f, char *buf, size_t count)
{
	return 0;
}

static size_t null_dev_write(struct file *f, const char *buf, size_t count)
{
	return count;
}

static int null_dev_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0666;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = mkdev(1, 3);
	buf->st_size = 0;
	buf->st_blksize = 4096;
	buf->st_blocks = 0;
	buf->st_atime = 0;
	buf->st_atime_nsec = 0;
	buf->st_mtime = 0;
	buf->st_mtime_nsec = 0;
	buf->st_ctime = 0;
	buf->st_ctime_nsec = 0;
	return 0;
}

static const struct file_ops null_dev_ops =
{
	.get_poll_status = fhelper_get_poll_status_inout,
	.close = null_dev_close,
	.read = null_dev_read,
	.write = null_dev_write,
	.stat = null_dev_stat,
};

struct file *null_dev_alloc()
{
	struct file *f = kmalloc(sizeof(struct file));
	f->op_vtable = &null_dev_ops;
	f->ref = 1;
	f->flags = O_RDWR;
	return f;
}
