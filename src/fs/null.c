#include <common/fcntl.h>
#include <fs/null.h>
#include <heap.h>
#include <log.h>

static int null_dev_close(struct file *f)
{
	kfree(f, sizeof(struct file));
	return 0;
}

static size_t null_dev_read(struct file *f, char *buf, size_t count)
{
	return 0;
}

static size_t null_dev_write(struct file *f, const char *buf, size_t count)
{
	return count;
}

static int null_dev_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0666;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = mkdev(1, 3);
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

static const struct file_ops null_dev_ops =
{
	.close = null_dev_close,
	.read = null_dev_read,
	.write = null_dev_write,
	.stat = null_dev_stat,
};

struct file *null_dev_alloc()
{
	struct file *f = kmalloc(sizeof(struct file));
	f->op_vtable = &null_dev_ops;
	f->ref = 1;
	f->flags = O_RDWR;
	return f;
}
