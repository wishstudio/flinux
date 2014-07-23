#include "winfs.h"
#include <syscall/mm.h> /* For PAGE_SIZE */
#include <common/fcntl.h>

#include <stdlib.h>
#include <Windows.h>

struct winfs_file
{
	struct file base_file;
	HANDLE handle;
};

#define NANOSECONDS_PER_TICK	100ULL
#define NANOSECONDS_PER_SECOND	1000000000ULL
#define TICKS_PER_SECOND		10000000ULL
#define SEC_TO_UNIX_EPOCH		11644473600ULL

static uint64_t filetime_to_unix_nsec(FILETIME *filetime)
{
	uint64_t ticks = ((uint64_t)filetime->dwHighDateTime << 32ULL) + filetime->dwLowDateTime;
	if (ticks < SEC_TO_UNIX_EPOCH * TICKS_PER_SECOND) /* Out of range */
		return -1;
	ticks -= SEC_TO_UNIX_EPOCH * TICKS_PER_SECOND;
	return ticks * NANOSECONDS_PER_TICK;
}

static uint64_t filetime_to_unix_sec(FILETIME *filetime)
{
	uint64_t nsec = filetime_to_unix_nsec(filetime);
	if (nsec == -1)
		return -1;
	return nsec / NANOSECONDS_PER_SECOND;
}

static int winfs_stat(struct file *f, struct stat64 *buf)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(winfile->handle, &info))
	{
		log_debug("GetFileInformationByHandle() failed.");
		return -1;
	}
	buf->st_dev = mkdev(8, 0); // (8, 0): /dev/sda
	buf->st_ino = ((uint64_t) info.nFileIndexHigh << 32ULL) + info.nFileIndexLow;
	if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
		buf->st_mode = 0555;
	else
		buf->st_mode = 0755;
	if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		buf->st_mode |= S_IFDIR;
	else
		buf->st_mode |= S_IFREG;
	buf->st_nlink = info.nNumberOfLinks;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = 0;
	buf->st_size = ((uint64_t) info.nFileSizeLow << 32ULL) + info.nFileSizeHigh;
	buf->st_blksize = PAGE_SIZE;
	buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;
	buf->st_atime = filetime_to_unix_sec(&info.ftLastAccessTime);
	buf->st_atime_nsec = filetime_to_unix_nsec(&info.ftLastAccessTime);
	buf->st_mtime = filetime_to_unix_sec(&info.ftLastWriteTime);
	buf->st_mtime_nsec = filetime_to_unix_nsec(&info.ftLastWriteTime);
	buf->st_ctime = filetime_to_unix_sec(&info.ftCreationTime);
	buf->st_ctime_nsec = filetime_to_unix_nsec(&info.ftCreationTime);
	return 0;
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
	{
		log_debug("CreateFileA() failed.");
		return NULL;
	}
	file = (struct winfs_file *)malloc(sizeof(struct winfs_file));
	file->base_file.op_vtable = &winfs_ops;
	file->base_file.offset = 0;
	file->base_file.ref = 1;
	return file;
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
