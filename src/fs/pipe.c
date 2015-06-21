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
#include <common/poll.h>
#include <fs/pipe.h>
#include <syscall/mm.h>
#include <heap.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct pipe_file
{
	struct file base_file;
	HANDLE handle;
	int is_read;
};

static HANDLE pipe_get_poll_handle(struct file *f, int *poll_flags)
{
	struct pipe_file *pipe = (struct pipe_file *) f;
	if (pipe->is_read)
		*poll_flags = LINUX_POLLIN;
	else
		*poll_flags = LINUX_POLLOUT;
	return pipe->handle;
}

static int pipe_close(struct file *f)
{
	struct pipe_file *pipe = (struct pipe_file *)f;
	CloseHandle(pipe->handle);
	kfree(pipe, sizeof(struct pipe_file));
	return 0;
}

static size_t pipe_read(struct file *f, void *buf, size_t count)
{
	struct pipe_file *pipe = (struct pipe_file *)f;
	if (!pipe->is_read)
	{
		log_warning("read() on pipe write end.\n");
		return -EBADF;
	}
	size_t num_read;
	if (!ReadFile(pipe->handle, buf, count, &num_read, NULL))
	{
		if (GetLastError() == ERROR_BROKEN_PIPE)
		{
			log_info("Pipe closed. Read returns 0.\n");
			return 0;
		}
		return -EIO;
	}
	return num_read;
}

static size_t pipe_write(struct file *f, const void *buf, size_t count)
{
	struct pipe_file *pipe = (struct pipe_file *)f;
	if (pipe->is_read)
	{
		log_warning("write() on pipe read end.\n");
		return -EBADF;
	}
	size_t num_written;
	if (!WriteFile(pipe->handle, buf, count, &num_written, NULL))
	{
		if (GetLastError() == ERROR_BROKEN_PIPE)
		{
			log_info("Write failed: broken pipe.\n");
			/* TODO: Send SIGPIPE signal */
			return -EPIPE;
		}
		return -EIO;
	}
	return num_written;
}

static int pipe_llseek(struct file *f, loff_t offset, loff_t *newoffset, int whence)
{
	return -ESPIPE;
}

static int pipe_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 8);
	buf->st_ino = 0;
	buf->st_mode = S_IFIFO + 0600;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = mkdev(0, 0);
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

static const struct file_ops pipe_ops = {
	.get_poll_handle = pipe_get_poll_handle,
	.close = pipe_close,
	.read = pipe_read,
	.write = pipe_write,
	.llseek = pipe_llseek,
	.stat = pipe_stat,
};

static struct file *pipe_create_file(HANDLE handle, int is_read, int flags)
{
	struct pipe_file *pipe = (struct pipe_file *)kmalloc(sizeof(struct pipe_file));
	file_init(&pipe->base_file, &pipe_ops, is_read ? O_RDONLY: O_WRONLY);
	pipe->handle = handle;
	pipe->is_read = is_read;
	return (struct file *)pipe;
}

int pipe_alloc(struct file **fread, struct file **fwrite, int flags)
{
	HANDLE read_handle, write_handle;
	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.lpSecurityDescriptor = NULL;
	attr.bInheritHandle = TRUE;
	if (!CreatePipe(&read_handle, &write_handle, &attr, 0))
	{
		log_warning("CreatePipe() failed, error code: %d\n");
		return -EMFILE; /* TODO: Find an appropriate flag */
	}
	*fread = pipe_create_file(read_handle, 1, flags);
	*fwrite = pipe_create_file(write_handle, 0, flags);
	return 0;
}
