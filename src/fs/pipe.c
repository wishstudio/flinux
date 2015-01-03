#include <common/errno.h>
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

static HANDLE pipe_get_poll_handle(struct file *f, int **poll_flags)
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

static size_t pipe_read(struct file *f, char *buf, size_t count)
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

static size_t pipe_write(struct file *f, const char *buf, size_t count)
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

static const struct file_ops pipe_ops = {
	.get_poll_handle = pipe_get_poll_handle,
	.close = pipe_close,
	.read = pipe_read,
	.write = pipe_write,
	.llseek = pipe_llseek,
};

static struct file *pipe_create_file(HANDLE handle, int is_read, int flags)
{
	struct pipe_file *pipe = (struct pipe_file *)kmalloc(sizeof(struct pipe_file));
	pipe->base_file.op_vtable = &pipe_ops;
	pipe->base_file.ref = 1;
	pipe->handle = handle;
	pipe->is_read = is_read;
	return pipe;
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
