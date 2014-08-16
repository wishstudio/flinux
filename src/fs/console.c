#include <fs/console.h>

struct console_file
{
	struct file base_file;
	HANDLE in, out;
};

static const struct file_ops console_ops = {
};

struct file *console_alloc()
{
}
