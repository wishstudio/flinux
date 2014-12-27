#include <fs/null.h>
#include <heap.h>
#include <log.h>

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
	.read = null_dev_read,
	.write = null_dev_write,
};

static struct file null_dev;

struct file *get_null_dev()
{
	null_dev.ref++;
	return &null_dev;
}

void init_null_dev()
{
	null_dev.op_vtable = &null_dev_ops;
	null_dev.ref = 1;
}
