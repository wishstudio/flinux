#include <fs/devfs.h>
#include <heap.h>

struct devfs
{
	struct file_system base_fs;
};

struct file_system *devfs_alloc()
{
	struct devfs *fs = (struct devfs *)kmalloc(sizeof(struct devfs));
	fs->base_fs.mountpoint = "/dev/";
	return fs;
}
