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

#include <common/errno.h>
#include <common/fcntl.h>
#include <common/fs.h>
#include <common/poll.h>
#include <fs/virtual.h>
#include <syscall/mm.h>
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

struct virtualfs_text
{
	struct file base_file;
	int position;
	int textlen;
	char text[];
};

static int virtualfs_text_close(struct file *f)
{
	struct virtualfs_text *file = (struct virtualfs_text *)f;
	kfree(file, sizeof(struct virtualfs_text) + file->textlen);
	return 0;
}

static size_t virtualfs_text_read(struct file *f, void *buf, size_t count)
{
	struct virtualfs_text *file = (struct virtualfs_text *)f;
	int read_count = (int)min(count, (size_t)(file->textlen - file->position));
	memcpy(buf, file->text + file->position, read_count);
	file->position += read_count;
	return read_count;
}

static int virtualfs_text_llseek(struct file *f, loff_t offset, loff_t *newoffset, int whence)
{
	struct virtualfs_text *file = (struct virtualfs_text *)f;
	loff_t target;
	switch (whence)
	{
	case SEEK_SET: target = offset; break;
	case SEEK_CUR: target = file->position + offset; break;
	case SEEK_END: target = file->textlen - offset; break;
	default: return -EINVAL;
	}
	if (target >= 0 && target < file->textlen)
	{
		file->position = (int)target;
		*newoffset = target;
		return 0;
	}
	else
		return -EINVAL;
}

static int virtualfs_text_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFREG + 0644;
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

static const struct file_ops virtualfs_text_ops =
{
	.close = virtualfs_text_close,
	.read = virtualfs_text_read,
	.llseek = virtualfs_text_llseek,
	.stat = virtualfs_text_stat,
};

static struct file *virtualfs_text_alloc(struct virtualfs_text_desc *desc)
{
	int len = desc->getbuflen();
	struct virtualfs_text *file = (struct virtualfs_text *)kmalloc(sizeof(struct virtualfs_text) + len);
	file->base_file.op_vtable = &virtualfs_text_ops;
	file->base_file.flags = O_RDONLY;
	file->base_file.ref = 1;
	desc->gettext(file->text);
	file->textlen = strlen(file->text);
	file->position = 0;
	return (struct file *)file;
}

struct virtualfs_directory
{
	struct file base_file;
	const struct virtualfs_directory_desc *desc;
	int position; /* Current position for getdents() */
	int pathlen;
	char path[];
};

static int virtualfs_directory_close(struct file *f)
{
	struct virtualfs_directory *file = (struct virtualfs_directory *)f;
	kfree(file, sizeof(struct virtualfs_directory) + file->pathlen);
	return 0;
}

static int virtualfs_directory_getpath(struct file *f, char *buf)
{
	struct virtualfs_directory *file = (struct virtualfs_directory *)f;
	/* Copy mountpoint */
	int len_mountpoint = strlen(file->desc->mountpoint);
	memcpy(buf, file->desc->mountpoint, len_mountpoint);
	buf[len_mountpoint] = '/';
	/* Copy subpath */
	memcpy(buf + len_mountpoint + 1, file->path, file->pathlen);
	buf[len_mountpoint + 1 + file->pathlen] = 0;
	return len_mountpoint + 1 + file->pathlen;
}

static int virtualfs_directory_llseek(struct file *f, loff_t offset, loff_t *newoffset, int whence)
{
	struct virtualfs_directory *file = (struct virtualfs_directory *)f;
	if (whence == SEEK_SET && offset == 0)
	{
		file->position = 0;
		*newoffset = 0;
		return 0;
	}
	else
		return -EINVAL;
}

static int virtualfs_directory_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFDIR + 0644;
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

static int virtualfs_directory_getdents(struct file *f, void *dirent, size_t count, getdents_callback *fill_callback)
{
	struct virtualfs_directory *file = (struct virtualfs_directory *)f;
	size_t size = 0;
	char *buf = (char *)dirent;
	for (;; file->position++)
	{
		const char *name;
		int type;
		if (file->position == 0)
		{
			name = ".";
			type = DT_DIR;
		}
		else if (file->position == 1)
		{
			name = "..";
			type = DT_DIR;
		}
		else
		{
			int i = file->position - 2;
			if (file->desc->entries[i].desc == NULL)
				return size;
			name = file->desc->entries[i].name;
			switch (file->desc->entries[i].desc->type)
			{
			case VIRTUALFS_TYPE_CUSTOM: type = DT_CHR; break;
			case VIRTUALFS_TYPE_CHAR: type = DT_CHR; break;
			case VIRTUALFS_TYPE_TEXT: type = DT_REG; break;
			default:
				log_error("Invalid virtual fs file type. Corrupted internal data structure.\n");
				__debugbreak();
				return -EIO;
			}
		}
		/* FIXME: Proper inode support (sync with stat()) */
		intptr_t r = (*fill_callback)(buf, file->position, name, strlen(name), type, count, GETDENTS_UTF8);
		if (r == GETDENTS_ERR_BUFFER_OVERFLOW)
			return size;
		if (r < 0)
			return r;
		count -= r;
		size += r;
		buf += r;
	}
}

static const struct file_ops virtualfs_directory_ops =
{
	.close = virtualfs_directory_close,
	.getpath = virtualfs_directory_getpath,
	.llseek = virtualfs_directory_llseek,
	.stat = virtualfs_directory_stat,
	.getdents = virtualfs_directory_getdents,
};

static struct file *virtualfs_directory_alloc(const struct virtualfs_directory_desc *desc, const char *path)
{
	int pathlen = strlen(path);
	struct virtualfs_directory *file = (struct virtualfs_directory *)kmalloc(sizeof(struct virtualfs_directory) + pathlen);
	file->base_file.op_vtable = &virtualfs_directory_ops;
	file->base_file.flags = O_RDWR;
	file->base_file.ref = 1;
	file->desc = desc;
	file->position = 0;
	file->pathlen = strlen(path);
	memcpy(file->path, path, file->pathlen);
	return (struct file *)file;
}

struct virtualfs
{
	struct file_system base_fs;
	const struct virtualfs_directory_desc *dir;
};

static int virtualfs_open(struct file_system *fs, const char *path, int flags, int mode, struct file **p, char *target, int buflen)
{
	const struct virtualfs_directory_desc *dir = ((struct virtualfs *)fs)->dir;
	if (*path == 0 || !strcmp(path, "."))
	{
		if (p)
			*p = virtualfs_directory_alloc(dir, path);
		return 0;
	}
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
			case VIRTUALFS_TYPE_CUSTOM:
			{
				struct virtualfs_custom_desc *desc = (struct virtualfs_custom_desc *)dir->entries[i].desc;
				*p = desc->alloc();
				return 0;
			}
				
			case VIRTUALFS_TYPE_CHAR:
			{
				struct virtualfs_char_desc *desc = (struct virtualfs_char_desc *)dir->entries[i].desc;
				*p = virtualfs_char_alloc(desc);
				return 0;
			}

			case VIRTUALFS_TYPE_TEXT:
			{
				struct virtualfs_text_desc *desc = (struct virtualfs_text_desc *)dir->entries[i].desc;
				*p = virtualfs_text_alloc(desc);
				return 0;
			}

			default:
				log_error("Invalid virtual fs file type. Corrupted internal data structure.\n");
				__debugbreak();
				return -ENOENT;
			}
		}
	}
	log_warning("File not found in virtual fs.\n");
	return -ENOENT;
}

struct file_system *virtualfs_alloc(const struct virtualfs_directory_desc *dir)
{
	struct virtualfs *fs = (struct virtualfs *)kmalloc(sizeof(struct virtualfs));
	fs->base_fs.mountpoint = dir->mountpoint;
	fs->base_fs.open = virtualfs_open;
	fs->dir = dir;
	return (struct file_system *)fs;
}
