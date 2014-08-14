#include <common/errno.h>
#include <fs/pipe.h>
#include <syscall/mm.h>

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

struct file *pipe_alloc(HANDLE handle, int is_read, int flags)
{
	struct pipe_file *pipe = (struct pipe_file *)kmalloc(sizeof(struct pipe_file *));
	pipe->base_file.op_vtable = &pipe_ops;
	pipe->base_file.ref = 1;
	pipe->base_file.openflags = 0;
	pipe->handle = handle;
	pipe->is_read = is_read;
	return pipe;
}
