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
#include <ntdll.h>

/* POSIX.1 says that write(2)s of less than PIPE_BUF bytes must be atomic */
#define PIPE_BUF	4096

struct pipe_file
{
	struct file base_file;
	HANDLE handle;
	HANDLE read_event; /* Signaled when there is read data available */
	HANDLE write_event; /* Signaled when there is write data available */
	bool is_read;
};

static int pipe_get_poll_status(struct file *f)
{
	struct pipe_file *pipe = (struct pipe_file *) f;
	/* Query current pipe quota */
	FILE_PIPE_LOCAL_INFORMATION info;
	IO_STATUS_BLOCK status_block;
	NTSTATUS status;
	status = NtQueryInformationFile(pipe->handle, &status_block, &info, sizeof(info), FilePipeLocalInformation);
	if (!NT_SUCCESS(status))
	{
		log_error("NtQueryInformationFile() failed, status: %x", status);
		return LINUX_POLLERR;
	}
	int r = 0;
	if (info.ReadDataAvailable)
	{
		NtSetEvent(pipe->read_event, NULL);
		r |= LINUX_POLLIN;
	}
	else
		NtClearEvent(pipe->read_event);
	if (info.WriteQuotaAvailable)
	{
		NtSetEvent(pipe->write_event, NULL);
		r |= LINUX_POLLOUT;
	}
	else
		NtClearEvent(pipe->write_event);
	if (r == 0 && info.NamedPipeState != FILE_PIPE_CONNECTED_STATE)
	{
		log_info("Broken pipe.");
		return LINUX_POLLHUP;
	}
	return r;
}

static HANDLE pipe_get_poll_handle(struct file *f, int *poll_flags)
{
	struct pipe_file *pipe = (struct pipe_file *) f;
	if (pipe->is_read)
	{
		*poll_flags = LINUX_POLLIN;
		return pipe->read_event;
	}
	else
	{
		*poll_flags = LINUX_POLLOUT;
		return pipe->write_event;
	}
}

static int pipe_close(struct file *f)
{
	struct pipe_file *pipe = (struct pipe_file *)f;
	NtClose(pipe->read_event);
	NtClose(pipe->write_event);
	CloseHandle(pipe->handle);
	kfree(pipe, sizeof(struct pipe_file));
	return 0;
}

static void pipe_update_events(struct pipe_file *pipe)
{
	FILE_PIPE_LOCAL_INFORMATION info;
	IO_STATUS_BLOCK status_block;
	NTSTATUS status;
	status = NtQueryInformationFile(pipe->handle, &status_block, &info, sizeof(info), FilePipeLocalInformation);
	if (!NT_SUCCESS(status))
	{
		log_error("NtQueryInformationFile() failed, status: %x", status);
		return;
	}
	if (info.ReadDataAvailable > 0)
		NtSetEvent(pipe->read_event, NULL);
	else
		NtClearEvent(pipe->read_event);
	if (info.WriteQuotaAvailable > 0)
		NtSetEvent(pipe->write_event, NULL);
	else
		NtClearEvent(pipe->write_event);
}

static size_t pipe_read(struct file *f, void *buf, size_t count)
{
	AcquireSRWLockShared(&f->rw_lock);
	struct pipe_file *pipe = (struct pipe_file *)f;
	ssize_t r;
	if (!pipe->is_read)
	{
		log_warning("read() on pipe write end.");
		r = -L_EBADF;
		goto out;
	}
	if (f->flags & O_NONBLOCK)
	{
		if (WaitForSingleObject(pipe->read_event, 0) == WAIT_TIMEOUT)
		{
			r = -L_EAGAIN;
			goto out;
		}
	}
	size_t num_read;
	if (!ReadFile(pipe->handle, buf, count, &num_read, NULL))
	{
		if (GetLastError() == ERROR_BROKEN_PIPE)
		{
			log_info("Pipe closed. Read returns 0.");
			r = 0;
			goto out;
		}
		r = -L_EIO;
		goto out;
	}
	r = num_read;
out:
	pipe_update_events(pipe);
	ReleaseSRWLockShared(&f->rw_lock);
	return r;
}

static size_t pipe_write(struct file *f, const void *buf, size_t count)
{
	AcquireSRWLockShared(&f->rw_lock);
	struct pipe_file *pipe = (struct pipe_file *)f;
	ssize_t r;
	if (pipe->is_read)
	{
		log_warning("write() on pipe read end.");
		r = -L_EBADF;
	}
	if (f->flags & O_NONBLOCK)
	{
		if (WaitForSingleObject(pipe->write_event, 0) == WAIT_TIMEOUT)
		{
			r = -L_EAGAIN;
			goto out;
		}
		/* Make sure we have enough write quota available */
		FILE_PIPE_LOCAL_INFORMATION info;
		IO_STATUS_BLOCK status_block;
		NTSTATUS status;
		status = NtQueryInformationFile(pipe->handle, &status_block, &info, sizeof(info), FilePipeLocalInformation);
		if (!NT_SUCCESS(status))
		{
			log_error("NtQueryInformationFile() failed, status: %x", status);
			r = -L_EIO;
			goto out;
		}
		if (info.WriteQuotaAvailable == 0 && info.NamedPipeState != FILE_PIPE_CONNECTED_STATE)
		{
			log_info("Write failed: broken pipe.");
			/* TODO: Send SIGPIPE signal */
			r = -L_EPIPE;
			goto out;
		}
		/* Data length less than PIPE_BUF must be atomic */
		if (info.WriteQuotaAvailable < min(PIPE_BUF, count))
		{
			r = -L_EAGAIN;
			goto out;
		}
	}
	size_t num_written;
	if (!WriteFile(pipe->handle, buf, count, &num_written, NULL))
	{
		if (GetLastError() == ERROR_BROKEN_PIPE)
		{
			log_info("Write failed: broken pipe.");
			/* TODO: Send SIGPIPE signal */
			r = -L_EPIPE;
			goto out;
		}
		r = -L_EIO;
		goto out;
	}
	r = num_written;
out:
	pipe_update_events(pipe);
	ReleaseSRWLockShared(&f->rw_lock);
	return r;
}

static int pipe_llseek(struct file *f, loff_t offset, loff_t *newoffset, int whence)
{
	return -L_ESPIPE;
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
	.get_poll_status = pipe_get_poll_status,
	.get_poll_handle = pipe_get_poll_handle,
	.close = pipe_close,
	.read = pipe_read,
	.write = pipe_write,
	.llseek = pipe_llseek,
	.stat = pipe_stat,
};

static struct file *pipe_create_file(HANDLE handle, HANDLE read_event, HANDLE write_event, bool is_read, int flags)
{
	struct pipe_file *pipe = (struct pipe_file *)kmalloc(sizeof(struct pipe_file));
	file_init(&pipe->base_file, &pipe_ops, is_read ? O_RDONLY: O_WRONLY);
	pipe->handle = handle;
	pipe->read_event = read_event;
	pipe->write_event = write_event;
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
		log_warning("CreatePipe() failed, error code: %d");
		return -L_EMFILE; /* TODO: Find an appropriate flag */
	}
	OBJECT_ATTRIBUTES oa;
	HANDLE read_event, write_event;
	NTSTATUS status;
	InitializeObjectAttributes(&oa, NULL, OBJ_INHERIT, NULL, NULL);
	status = NtCreateEvent(&read_event, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);
	if (!NT_SUCCESS(status))
	{
		log_error("NtCreateEvent() failed, status: %x", status);
		return -L_ENOMEM;
	}
	status = NtCreateEvent(&write_event, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);
	if (!NT_SUCCESS(status))
	{
		log_error("NtCreateEvent() failed, status: %x", status);
		return -L_ENOMEM;
	}
	HANDLE read_event2, write_event2;
	status = NtDuplicateObject(NtCurrentProcess(), read_event, NtCurrentProcess(), &read_event2, 0, OBJ_INHERIT, DUPLICATE_SAME_ACCESS);
	if (!NT_SUCCESS(status))
	{
		log_error("NtDuplicateObject() failed, status: %x", status);
		return -L_ENOMEM;
	}
	status = NtDuplicateObject(NtCurrentProcess(), write_event, NtCurrentProcess(), &write_event2, 0, OBJ_INHERIT, DUPLICATE_SAME_ACCESS);
	if (!NT_SUCCESS(status))
	{
		log_error("NtDuplicateObject() failed, status: %x", status);
		return -L_ENOMEM;
	}
	*fread = pipe_create_file(read_handle, read_event, write_event, true, flags);
	*fwrite = pipe_create_file(write_handle, read_event2, write_event2, false, flags);
	return 0;
}
