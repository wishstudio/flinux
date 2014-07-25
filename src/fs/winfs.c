#include "winfs.h"
#include <syscall/mm.h> /* For PAGE_SIZE */
#include <common/fcntl.h>
#include <log.h>

#include <stdlib.h>
#include <Windows.h>
#include <ntdll.h>

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

int winfs_close(struct file *f)
{
	struct winfs_file *file = (struct winfs_file *)f;
	if (CloseHandle(file->handle))
		return 0;
	else
		return -1;
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

static int winfs_getdents(struct file *f, struct linux_dirent64 *dirent, int count)
{
	NTSTATUS status;
	struct winfs_file *winfile = (struct winfs_file *) f;
	IO_STATUS_BLOCK status_block;
	#define BUFFER_SIZE	32768
	char buffer[BUFFER_SIZE];
	int size = 0;

	for (;;)
	{
		int buffer_size = count / 3 * 2; /* In worst case, a UTF-16 character (2 bytes) requires 3 bytes to store */
		if (buffer_size >= BUFFER_SIZE)
			buffer_size = BUFFER_SIZE;
		status = NtQueryDirectoryFile(winfile->handle, NULL, NULL, NULL, &status_block, buffer, buffer_size, FileIdFullDirectoryInformation, FALSE, NULL, FALSE);
		if (status != STATUS_SUCCESS)
			break;
		if (status_block.Information == 0)
			break;
		int offset = 0;
		FILE_ID_FULL_DIR_INFORMATION *info;
		do
		{
			 info = (FILE_ID_FULL_DIR_INFORMATION *) &buffer[offset];
			 info->FileId.QuadPart;
			 offset += info->NextEntryOffset;
			 struct linux_dirent64 *p = (struct linux_dirent64 *)((char *) dirent + size);
			 p->d_ino = info->FileId.QuadPart;
			 p->d_off = 0; /* TODO */
			 p->d_type = (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? DT_DIR : DT_REG;
			 ULONG len = info->FileNameLength / 2;
			 p->d_reclen = (sizeof(struct linux_dirent64) + len + 1 + 3) & ~3;
			 for (ULONG i = 0; i < len; i++)
				 if ((p->d_name[i] = info->FileName[i]) == 0)
				 {
					 len = i;
					 break;
				 }
			 size += p->d_reclen;
		} while (info->NextEntryOffset);
	}
	return size;
	#undef BUFFER_SIZE
}

static struct file_ops winfs_ops = 
{
	.fn_close = winfs_close,
	.fn_stat = winfs_stat,
	.fn_getdents = winfs_getdents,
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
	else if (flags & O_WRONLY)
		desiredAccess = GENERIC_WRITE;
	else
		desiredAccess = GENERIC_READ;
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
	handle = CreateFileA(pathname, desiredAccess, shareMode, NULL, creationDisposition, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		log_debug("CreateFileA() failed.");
		return NULL;
	}
	file = (struct winfs_file *)malloc(sizeof(struct winfs_file));
	file->base_file.op_vtable = &winfs_ops;
	file->base_file.offset = 0;
	file->base_file.ref = 1;
	file->handle = handle;
	return file;
}

struct winfs
{
	struct file_system base_fs;
};

struct file_system *winfs_alloc()
{
	struct winfs *fs = (struct winfs *)malloc(sizeof(struct winfs));
	fs->base_fs.mountpoint = "/";
	fs->base_fs.open = winfs_open;
	return fs;
}
