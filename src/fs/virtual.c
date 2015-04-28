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
#include <common/poll.h>
#include <fs/virtual.h>
#include <syscall/mm.h>
#include <errno.h>
#include <heap.h>
#include <log.h>

int virtualfs_get_poll_status_inout(struct file *f)
{
	return LINUX_POLLIN | LINUX_POLLOUT;
}

void virtualfs_init_custom(void *f, struct virtualfs_desc *desc)
{
	struct virtualfs_custom *file = (struct virtualfs_custom *)f;
	file->desc = desc;
}

int virtualfs_custom_stat(struct file *f, struct newstat *buf)
{
	struct virtualfs_custom *file = (struct virtualfs_custom *)f;
	struct virtualfs_custom_desc *desc = (struct virtualfs_custom_desc *)file->desc;
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0644;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = desc->device;
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

struct virtualfs_char
{
	struct file base_file;
	struct virtualfs_char_desc *desc;
};

static int virtualfs_char_close(struct file *f)
{
	kfree(f, sizeof(struct virtualfs_char));
	return 0;
}

static size_t virtualfs_char_read(struct file *f, void *buf, size_t count)
{
	struct virtualfs_char *file = (struct virtualfs_char *)f;
	return file->desc->read(buf, count);
}

static size_t virtualfs_char_write(struct file *f, const void *buf, size_t count)
{
	struct virtualfs_char *file = (struct virtualfs_char *)f;
	return file->desc->write(buf, count);
}

static int virtualfs_char_stat(struct file *f, struct newstat *buf)
{
	struct virtualfs_char *file = (struct virtualfs_char *)f;
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0644;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = file->desc->device;
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

static const struct file_ops virtualfs_char_ops =
{
	.get_poll_status = virtualfs_get_poll_status_inout,
	.close = virtualfs_char_close,
	.read = virtualfs_char_read,
	.write = virtualfs_char_write,
	.stat = virtualfs_char_stat,
};

static struct file *virtualfs_char_alloc(struct virtualfs_char_desc *desc)
{
	struct virtualfs_char *file = (struct virtualfs_char *)kmalloc(sizeof(struct virtualfs_char));
	file->base_file.op_vtable = &virtualfs_char_ops;
	file->base_file.flags = O_RDWR;
	file->base_file.ref = 1;
	file->desc = desc;
	return (struct file *)file;
}

struct virtualfs
{
	struct file_system base_fs;
	const struct virtualfs_directory_desc *dir;
};

static int virtualfs_open(struct file_system *fs, const char *path, int flags, int mode, struct file **p, char *target, int buflen)
{
	if (*path == 0 || !strcmp(path, "."))
	{
		if (p)
		{
			log_error("Opening virtual fs directory unsupported.\n");
			return -ENOENT;
		}
		else
			return 0;
	}
	const struct virtualfs_directory_desc *dir = ((struct virtualfs *)fs)->dir;
	for (int i = 0; dir->entries[i].desc; i++)
	{
		if (!strcmp(dir->entries[i].name, path))
		{
			if (flags & O_DIRECTORY)
				return -ENOTDIR;
			if (!p) /* Don't need allocate file */
				return 0;
			switch (dir->entries[i].desc->type)
			{
			case VIRTUALFS_TYPE_INVALID:
				log_error("Invalid virtual fs file type. Corrupted internal data structure.\n");
				__debugbreak();
				return -ENOENT;

			case VIRTUALFS_TYPE_CUSTOM:
			{
				struct virtualfs_custom_desc *desc = (struct virtualfs_custom_desc *)dir->entries[i].desc;
				*p = desc->alloc();
				return 0;
			}
				
			case VIRTUALFS_TYPE_CHAR: {
				struct virtualfs_char_desc *desc = (struct virtualfs_char_desc *)dir->entries[i].desc;
				*p = virtualfs_char_alloc(desc);
				return 0;
			}
			}
		}
	}
	log_warning("File not found in virtual fs.\n");
	return -ENOENT;
}

struct file_system *virtualfs_alloc(char *mountpoint, const struct virtualfs_directory_desc *dir)
{
	struct virtualfs *fs = (struct virtualfs *)kmalloc(sizeof(struct virtualfs));
	fs->base_fs.mountpoint = mountpoint;
	fs->base_fs.open = virtualfs_open;
	fs->dir = dir;
	return (struct file_system *)fs;
}
