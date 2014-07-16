#include "tty.h"

#include <stdlib.h>

static size_t tty_read(struct fp *f, char *buf, size_t count)
{
	struct tty_fp *tty = (struct tty_fp *) f;
	size_t num_read;
	if (!ReadFile(tty->file_handle, buf, count, &num_read, NULL))
		return -1;
	return num_read;
}

static size_t tty_write(struct fp *f, const char *buf, size_t count)
{
	struct tty_fp *tty = (struct tty_fp *) f;
	size_t num_written;
	if (!WriteFile(tty->file_handle, buf, count, &num_written, NULL))
		return -1;
	return num_written;
}

static int tty_stat(struct fp *f, struct stat64 *buf)
{
	struct tty_fp *tty = (struct tty_fp *) f;
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0644;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = mkdev(5, 0);
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

static int tty_ioctl(struct fp *f, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static const struct file_ops tty_ops = {
	.fn_read = tty_read,
	.fn_write = tty_write,
	.fn_stat = tty_stat,
	.fn_ioctl = tty_ioctl,
};

struct fp *tty_alloc(HANDLE file_handle)
{
	struct tty_fp *tty = (struct tty_fp *) malloc(sizeof(struct tty_fp));
	tty->base_fp.op_vtable = &tty_ops;
	tty->base_fp.offset = 0;
	tty->file_handle = file_handle;

	return (struct fp *) tty;
}
