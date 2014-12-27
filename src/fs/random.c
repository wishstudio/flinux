#include <fs/file.h>
#include <log.h>

#define SystemFunction036 NTAPI SystemFunction036
#include <NTSecAPI.h>
#undef SystemFunction036

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
	.read = random_dev_read,
	.write = random_dev_write,
};

static const struct file_ops urandom_dev_ops =
{
	.read = random_dev_read,
	.write = random_dev_write,
};

static struct file random_dev;
static struct file urandom_dev;

struct file *get_random_dev()
{
	random_dev.ref++;
	return &random_dev;
}

struct file *get_urandom_dev()
{
	urandom_dev.ref++;
	return &urandom_dev;
}

void init_random_dev()
{
	random_dev.op_vtable = &random_dev_ops;
	random_dev.ref = 1;
	urandom_dev.op_vtable = &urandom_dev_ops;
	urandom_dev.ref = 1;
}
