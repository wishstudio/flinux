#include <common/fcntl.h>
#include <fs/file.h>
#include <heap.h>
#include <log.h>

#define SystemFunction036 NTAPI SystemFunction036
#include <NTSecAPI.h>
#undef SystemFunction036

static int random_dev_close(struct file *f)
{
	kfree(f, sizeof(struct file));
	return 0;
}

static size_t random_dev_read(struct file *f, char *buf, size_t count)
{
	if (!RtlGenRandom(buf, count))
		return 0;
	return count;
}

static size_t random_dev_write(struct file *f, const char *buf, size_t count)
{
	return count;
}

static const struct file_ops random_dev_ops =
{
	.close = random_dev_close,
	.read = random_dev_read,
	.write = random_dev_write,
};

static const struct file_ops urandom_dev_ops =
{
	.close = random_dev_close,
	.read = random_dev_read,
	.write = random_dev_write,
};

struct file *random_dev_alloc()
{
	struct file *f = kmalloc(sizeof(struct file));
	f->op_vtable = &random_dev_ops;
	f->ref = 1;
	f->flags = O_RDONLY;
	return f;
}

struct file *urandom_dev_alloc()
{
	struct file *f = kmalloc(sizeof(struct file));
	f->op_vtable = &urandom_dev_ops;
	f->ref = 1;
	f->flags = O_RDONLY;
	return f;
}
