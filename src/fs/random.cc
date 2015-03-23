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
#include <fs/file.h>
#include <syscall/syscall.h>
#include <syscall/mm.h>
#include <errno.h>
#include <heap.h>
#include <log.h>

#define SystemFunction036 NTAPI SystemFunction036
#include <NTSecAPI.h>
#undef SystemFunction036

DEFINE_SYSCALL(getrandom, void *, buf, size_t, buflen, unsigned int, flags)
{
	log_info("getrandom(%p, %d, %x)\n", buf, buflen, flags);
	if (!mm_check_write(buf, buflen))
		return -EFAULT;
	if (!RtlGenRandom(buf, buflen))
		return 0;
	return buflen;
}

static int random_dev_close(struct file *f)
{
	kfree(f, sizeof(struct file));
	return 0;
}

static size_t random_dev_read(struct file *f, char *buf, size_t count)
{
	if (!RtlGenRandom(buf, count))
		return 0;
	return count;
}

static size_t random_dev_write(struct file *f, const char *buf, size_t count)
{
	return count;
}

static int random_dev_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0666;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = mkdev(1, 8);
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

static int urandom_dev_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0666;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = mkdev(1, 9);
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

static const struct file_ops random_dev_ops =
{
	.get_poll_status = fhelper_get_poll_status_inout,
	.close = random_dev_close,
	.read = random_dev_read,
	.write = random_dev_write,
	.stat = random_dev_stat,
};

static const struct file_ops urandom_dev_ops =
{
	.get_poll_status = fhelper_get_poll_status_inout,
	.close = random_dev_close,
	.read = random_dev_read,
	.write = random_dev_write,
	.stat = urandom_dev_stat,
};

struct file *random_dev_alloc()
{
	struct file *f = kmalloc(sizeof(struct file));
	f->op_vtable = &random_dev_ops;
	f->ref = 1;
	f->flags = O_RDWR;
	return f;
}

struct file *urandom_dev_alloc()
{
	struct file *f = kmalloc(sizeof(struct file));
	f->op_vtable = &urandom_dev_ops;
	f->ref = 1;
	f->flags = O_RDWR;
	return f;
}
