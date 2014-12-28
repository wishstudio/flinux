#include <common/errno.h>
#include <fs/devfs.h>
#include <fs/null.h>
#include <fs/random.h>
#include <heap.h>
#include <log.h>

struct devfs
{
	struct file_system base_fs;
};

static int devfs_open(const char *path, int flags, int mode, struct file **fp, char *target, int buflen)
{
	if (*path == 0 || !strcmp(path, "."))
	{
		log_error("Opening /dev not handled.\n");
		return -ENOENT;
	}
	else if (!strcmp(path, "null"))
	{
		*fp = null_dev_alloc();
		return 0;
	}
	else if (!strcmp(path, "random"))
	{
		*fp = random_dev_alloc();
		return 0;
	}
	else if (!strcmp(path, "urandom"))
	{
		*fp = urandom_dev_alloc();
		return 0;
	}
	else
	{
		log_warning("devfs: '%s' not found.\n", path);
		return -ENOENT;
	}
}

struct file_system *devfs_alloc()
{
	struct devfs *fs = (struct devfs *)kmalloc(sizeof(struct devfs));
	fs->base_fs.mountpoint = "/dev";
	fs->base_fs.open = devfs_open;
	return fs;
}
