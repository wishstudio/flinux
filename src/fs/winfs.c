#include "winfs.h"
#include <common/fcntl.h>

#include <stdlib.h>
#include <Windows.h>

struct winfs_file
{
	struct file base_file;
	HANDLE handle;
};

static int winfs_stat(struct file *f, struct stat64 *buf)
{
}

static struct file_ops winfs_ops = 
{
	.fn_stat = winfs_stat,
};

struct file *winfs_open(const char *pathname, int flags, int mode)
{
	/* TODO: errno */
	/* TODO: mode */
	DWORD desiredAccess, shareMode, creationDisposition;
	HANDLE handle;
	struct winfs_file *file;

	if (flags & O_RDWR)
		desiredAccess = GENERIC_READ | GENERIC_WRITE;
	else if (flags & O_RDONLY)
		desiredAccess = GENERIC_READ;
	else if (flags & O_WRONLY)
		desiredAccess = GENERIC_WRITE;
	shareMode = FILE_SHARE_READ;
	creationDisposition;
	if (flags & O_EXCL)
		creationDisposition = CREATE_NEW;
	else if (flags & O_CREAT)
	{
		if (flags & O_TRUNC)
			creationDisposition = CREATE_ALWAYS;
		else
			creationDisposition = OPEN_ALWAYS;
	}
	else if (flags & O_TRUNC)
		creationDisposition = TRUNCATE_EXISTING;
	else
		creationDisposition = OPEN_EXISTING;
	handle = CreateFileA(pathname, desiredAccess, shareMode, NULL, creationDisposition, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE)
		return NULL;
	file = (struct winfs_file *)malloc(sizeof(struct winfs_file));
	file->base_file.op_vtable = &winfs_ops;
	file->base_file.offset = 0;
	file->base_file.ref = 1;
}

struct winfs
{
	struct file_system base_fs;
};

struct file_system *win32_fs_alloc()
{
	struct winfs *fs = (struct winfs *)malloc(sizeof(struct winfs));
	fs->base_fs.mountpoint = "/";
	fs->base_fs.open = winfs_open;
	return fs;
}
