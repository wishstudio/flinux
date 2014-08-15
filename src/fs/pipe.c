#include <common/errno.h>
#include <fs/pipe.h>
#include <syscall/mm.h>
#include <log.h>

struct pipe_file
{
	struct file base_file;
	HANDLE handle;
	int is_read;
};

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
		log_debug("read() on pipe write end.\n");
		return -EBADF;
	}
	size_t num_read;
	if (!ReadFile(pipe->handle, buf, count, &num_read, NULL))
		return -EIO;
	return num_read;
}

static size_t pipe_write(struct file *f, const char *buf, size_t count)
{
	struct pipe_file *pipe = (struct pipe_file *)f;
	if (pipe->is_read)
	{
		log_debug("write() on pipe read end.\n");
		return -EBADF;
	}
	size_t num_written;
	if (!WriteFile(pipe->handle, buf, count, &num_written, NULL))
		return -EIO;
	return num_written;
}

static const struct file_ops pipe_ops = {
	.fn_close = pipe_close,
	.fn_read = pipe_read,
	.fn_write = pipe_write,
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
		log_debug("CreatePipe() failed, error code: %d\n");
		return -EMFILE; /* TODO: Find an appropriate flag */
	}
	*fread = pipe_create_file(read_handle, 1, flags);
	*fwrite = pipe_create_file(write_handle, 0, flags);
	return 0;
}
