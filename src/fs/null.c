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

static const struct file_ops null_dev_ops =
{
	.close = null_dev_close,
	.read = null_dev_read,
	.write = null_dev_write,
};

struct file *null_dev_alloc()
{
	struct file *f = kmalloc(sizeof(struct file));
	f->op_vtable = &null_dev_ops;
	f->ref = 1;
	return f;
}
