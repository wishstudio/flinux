#include <fs/tty.h>
#include <heap.h>

static int tty_close(struct file *f)
{
	struct tty_file *tty = (struct tty_file *) f;
	CloseHandle(tty->file_handle);
	kfree(tty, sizeof(struct tty_file));
	return 0;
}

static size_t tty_read(struct file *f, char *buf, size_t count)
{
	struct tty_file *tty = (struct tty_file *) f;
	size_t num_read;
	if (!ReadFile(tty->file_handle, buf, count, &num_read, NULL))
		return -1;
	return num_read;
}

static size_t tty_write(struct file *f, const char *buf, size_t count)
{
	struct tty_file *tty = (struct tty_file *) f;
	size_t num_written;
	if (!WriteFile(tty->file_handle, buf, count, &num_written, NULL))
		return -1;
	return num_written;
}

static int tty_stat(struct file *f, struct stat64 *buf)
{
	struct tty_file *tty = (struct tty_file *) f;
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

static int tty_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static const struct file_ops tty_ops = {
	.fn_close = tty_close,
	.fn_read = tty_read,
	.fn_write = tty_write,
	.fn_stat = tty_stat,
	.fn_ioctl = tty_ioctl,
};

struct file *tty_alloc(HANDLE file_handle)
{
	struct tty_file *tty = (struct tty_file *) kmalloc(sizeof(struct tty_file));
	tty->base_file.op_vtable = &tty_ops;
	tty->base_file.ref = 1;
	tty->base_file.openflags = 0;
	tty->file_handle = file_handle;

	return (struct file *) tty;
}
