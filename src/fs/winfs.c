#include <common/errno.h>
#include <common/fcntl.h>
#include <fs/winfs.h>
#include <syscall/mm.h>
#include <syscall/vfs.h>
#include <log.h>
#include <heap.h>
#include <str.h>

#include <Windows.h>
#include <ntdll.h>

#define WINFS_SYMLINK_HEADER		"!<symlink>\377\376"
#define WINFS_SYMLINK_HEADER_LEN	(sizeof(WINFS_SYMLINK_HEADER) - 1)

struct winfs_file
{
	struct file base_file;
	HANDLE handle;
};

#define NANOSECONDS_PER_TICK	100ULL
#define NANOSECONDS_PER_SECOND	1000000000ULL
#define TICKS_PER_SECOND		10000000ULL
#define SEC_TO_UNIX_EPOCH		11644473600ULL

static uint64_t filetime_to_unix(FILETIME *filetime)
{
	uint64_t ticks = ((uint64_t)filetime->dwHighDateTime << 32ULL) + filetime->dwLowDateTime;
	if (ticks < SEC_TO_UNIX_EPOCH * TICKS_PER_SECOND) /* Out of range */
		return -1;
	ticks -= SEC_TO_UNIX_EPOCH * TICKS_PER_SECOND;
	return ticks * NANOSECONDS_PER_TICK;
}

static uint64_t filetime_to_unix_sec(FILETIME *filetime)
{
	uint64_t nsec = filetime_to_unix(filetime);
	if (nsec == -1)
		return -1;
	return nsec / NANOSECONDS_PER_SECOND;
}

static uint64_t filetime_to_unix_nsec(FILETIME *filetime)
{
	uint64_t nsec = filetime_to_unix(filetime);
	if (nsec == -1)
		return -1;
	return nsec % NANOSECONDS_PER_SECOND;
}

static void unix_to_filetime(uint64_t nsec, FILETIME *filetime)
{
	uint64_t ticks = nsec / NANOSECONDS_PER_TICK;
	filetime->dwLowDateTime = (DWORD)(ticks % 32ULL);
	filetime->dwHighDateTime = (DWORD)(ticks / 32ULL);
}

static void unix_timeval_to_filetime(const struct timeval *time, FILETIME *filetime)
{
	unix_to_filetime((uint64_t)time->tv_sec * 1000000 + (uint64_t)time->tv_usec, filetime);
}

/*
Test if a handle is a symlink, also return its target if requested.
For optimal performance, caller should ensure the handle is a regular file with system attribute.
When the function is called the file pointer must be at the beginning of the file,
and the caller is reponsible for restoring the file pointer.
*/
static int winfs_read_symlink(HANDLE hFile, char *target, int buflen)
{
	char header[WINFS_SYMLINK_HEADER_LEN];
	size_t num_read;
	if (!ReadFile(hFile, header, WINFS_SYMLINK_HEADER_LEN, &num_read, NULL) || num_read < WINFS_SYMLINK_HEADER_LEN)
		return 0;
	if (memcmp(header, WINFS_SYMLINK_HEADER, WINFS_SYMLINK_HEADER_LEN))
		return 0;
	if (target == NULL || buflen == 0)
	{
		LARGE_INTEGER size;
		if (!GetFileSizeEx(hFile, &size) || size.QuadPart - WINFS_SYMLINK_HEADER_LEN >= PATH_MAX)
			return 0;
		return (int)size.QuadPart - WINFS_SYMLINK_HEADER_LEN;
	}
	else
	{
		if (!ReadFile(hFile, target, buflen, &num_read, NULL))
			return 0;
		target[num_read] = 0;
		return num_read;
	}
}

static int winfs_close(struct file *f)
{
	struct winfs_file *file = (struct winfs_file *)f;
	if (CloseHandle(file->handle))
	{
		kfree(file, sizeof(struct winfs_file));
		return 0;
	}
	else
		return -1;
}

static size_t winfs_get_handle(struct file *f)
{
	return ((struct winfs_file *)f)->handle;
}

static size_t winfs_read(struct file *f, char *buf, size_t count)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	size_t num_read;
	if (!ReadFile(winfile->handle, buf, count, &num_read, NULL))
		return -1;
	return num_read;
}

static size_t winfs_write(struct file *f, const char *buf, size_t count)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	size_t num_written;
	if (!WriteFile(winfile->handle, buf, count, &num_written, NULL))
		return -1;
	return num_written;
}

static int winfs_llseek(struct file *f, loff_t offset, loff_t *newoffset, int whence)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	DWORD dwMoveMethod;
	if (whence == SEEK_SET)
		dwMoveMethod = FILE_BEGIN;
	else if (whence == SEEK_CUR)
		dwMoveMethod = FILE_CURRENT;
	else if (whence == SEEK_END)
		dwMoveMethod = FILE_END;
	else
		return -EINVAL;
	LARGE_INTEGER liDistanceToMove, liNewFilePointer;
	liDistanceToMove.QuadPart = offset;
	SetFilePointerEx(winfile->handle, liDistanceToMove, &liNewFilePointer, dwMoveMethod);
	*newoffset = liNewFilePointer.QuadPart;
	return 0;
}

static int winfs_stat(struct file *f, struct stat64 *buf)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(winfile->handle, &info))
	{
		log_debug("GetFileInformationByHandle() failed.\n");
		return -1;
	}
	buf->st_dev = mkdev(8, 0); // (8, 0): /dev/sda
	buf->st_ino = ((uint64_t) info.nFileIndexHigh << 32ULL) + info.nFileIndexLow;
	if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
		buf->st_mode = 0555;
	else
		buf->st_mode = 0755;
	if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		buf->st_mode |= S_IFDIR;
		buf->st_size = 0;
	}
	else
	{
		int r;
		if ((info.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
			&& (r = winfs_read_symlink(winfile->handle, NULL, 0)) > 0)
		{
			buf->st_mode |= S_IFLNK;
			buf->st_size = r;
		}
		else
		{
			buf->st_mode |= S_IFREG;
			buf->st_size = ((uint64_t)info.nFileSizeHigh << 32ULL) + info.nFileSizeLow;
		}
	}
	buf->st_nlink = info.nNumberOfLinks;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = 0;
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

static int winfs_utimes(struct file *f, const struct timeval times[2])
{
	struct winfs_file *winfs = (struct winfs_file *)f;
	if (times)
	{
		SYSTEMTIME time;
		GetSystemTime(&time);
		FILETIME filetime;
		SystemTimeToFileTime(&time, &filetime);
		SetFileTime(winfs->handle, NULL, &filetime, &filetime);
	}
	else
	{
		FILETIME actime, modtime;
		unix_timeval_to_filetime(&times[0], &actime);
		unix_timeval_to_filetime(&times[1], &modtime);
		SetFileTime(winfs->handle, NULL, &actime, &modtime);
	}
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
		int buffer_size = (count - size) / 2; /* In worst case, a UTF-16 character (2 bytes) requires 4 bytes to store */
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
			 int len = utf16_to_utf8(info->FileName, info->FileNameLength / 2, p->d_name, count - size);
			 p->d_name[len] = 0;
			 p->d_reclen = (sizeof(struct linux_dirent64) + len + 1 + 3) & ~3;
			 size += p->d_reclen;
		} while (info->NextEntryOffset);
	}
	return size;
	#undef BUFFER_SIZE
}

static struct file_ops winfs_ops = 
{
	.get_handle = winfs_get_handle,
	.close = winfs_close,
	.read = winfs_read,
	.write = winfs_write,
	.llseek = winfs_llseek,
	.stat = winfs_stat,
	.utimes = winfs_utimes,
	.getdents = winfs_getdents,
};

static int winfs_symlink(const char *target, const char *linkpath)
{
	HANDLE handle;
	WCHAR wlinkpath[PATH_MAX];

	if (utf8_to_utf16(linkpath, strlen(linkpath) + 1, wlinkpath, PATH_MAX) <= 0)
		return -ENOENT;

	log_debug("CreateFileW(): %s\n", linkpath);
	handle = CreateFileW(wlinkpath, GENERIC_WRITE, FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_SYSTEM, NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		DWORD err = GetLastError();
		if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS)
		{
			log_debug("File already exists.\n");
			return -EEXIST;
		}
		log_debug("CreateFileW() failed, error code: %d.\n", GetLastError());
		return -ENOENT;
	}
	size_t num_written;
	if (!WriteFile(handle, WINFS_SYMLINK_HEADER, WINFS_SYMLINK_HEADER_LEN, &num_written, NULL) || num_written < WINFS_SYMLINK_HEADER_LEN)
	{
		log_debug("WriteFile() failed, error code: %d.\n", GetLastError());
		CloseHandle(handle);
		return -EIO;
	}
	size_t targetlen = strlen(target);
	if (!WriteFile(handle, target, targetlen, &num_written, NULL) || num_written < targetlen)
	{
		log_debug("WriteFile() failed, error code: %d.\n", GetLastError());
		CloseHandle(handle);
		return -EIO;
	}
	CloseHandle(handle);
	return 0;
}

static size_t winfs_readlink(const char *pathname, char *target, size_t buflen)
{
	WCHAR wpathname[PATH_MAX];
	DWORD attr;
	HANDLE hFile;

	if (utf8_to_utf16(pathname, strlen(pathname) + 1, wpathname, PATH_MAX) <= 0)
		return -EIO;
	attr = GetFileAttributesW(wpathname);
	if (attr == INVALID_FILE_ATTRIBUTES)
		return -ENOENT;
	if ((attr & FILE_ATTRIBUTE_DIRECTORY) || !(attr & FILE_ATTRIBUTE_SYSTEM))
		return -EINVAL;
	hFile = CreateFileW(wpathname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return -EIO;
	int ret = winfs_read_symlink(hFile, target, buflen);
	CloseHandle(hFile);
	return ret;
}

static int winfs_unlink(const char *pathname)
{
	if (!DeleteFileA(pathname))
	{
		log_debug("DeleteFile() failed.\n");
		return -ENOENT;
	}
	return 0;
}

static int winfs_open(const char *pathname, int flags, int mode, struct file **fp, char *target, int buflen)
{
	/* TODO: mode */
	DWORD desiredAccess, shareMode, creationDisposition;
	HANDLE handle;
	FILE_ATTRIBUTE_TAG_INFO attributeInfo;
	WCHAR wpathname[PATH_MAX];
	struct winfs_file *file;

	if (utf8_to_utf16(pathname, strlen(pathname) + 1, wpathname, PATH_MAX) <= 0)
		return -ENOENT;

	if (flags & O_PATH)
		desiredAccess = 0;
	else if (flags & O_RDWR)
		desiredAccess = GENERIC_READ | GENERIC_WRITE;
	else if (flags & O_WRONLY)
		desiredAccess = GENERIC_WRITE;
	else
		desiredAccess = GENERIC_READ;
	shareMode = FILE_SHARE_READ | FILE_SHARE_DELETE;
	creationDisposition;
	if (flags & O_EXCL)
		creationDisposition = CREATE_NEW;
	else if (flags & O_CREAT)
	{
		if (flags & O_TRUNC)
			creationDisposition = CREATE_ALWAYS; /* FIXME: This is wrong! */
		else
			creationDisposition = OPEN_ALWAYS;
	}
	else if (flags & O_TRUNC)
		creationDisposition = TRUNCATE_EXISTING;
	else
		creationDisposition = OPEN_EXISTING;
	log_debug("CreateFileW(): %s\n", pathname);
	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.lpSecurityDescriptor = NULL;
	attr.bInheritHandle = TRUE;
	handle = CreateFileW(wpathname, desiredAccess, shareMode, &attr, creationDisposition, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		DWORD err = GetLastError();
		if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS)
		{
			log_debug("File already exists.\n");
			return -EEXIST;
		}
		else
		{
			log_debug("Unhandled CreateFileW() failure, error code: %d, returning ENOENT.\n", GetLastError());
			return -ENOENT;
		}
	}
	if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributeInfo, sizeof(attributeInfo)))
	{
		CloseHandle(handle);
		return -EIO;
	}
	/* Test if the file is a symlink */
	if (attributeInfo.FileAttributes != INVALID_FILE_ATTRIBUTES && (attributeInfo.FileAttributes & FILE_ATTRIBUTE_SYSTEM))
	{
		log_debug("The file has system flag set.\n");
		if (!(desiredAccess & GENERIC_READ))
		{
			/* We need to get a readable handle */
			log_debug("But the handle does not have READ access, try reopening file...\n");
			HANDLE read_handle = ReOpenFile(handle, desiredAccess | GENERIC_READ, shareMode, FILE_FLAG_BACKUP_SEMANTICS);
			if (read_handle == INVALID_HANDLE_VALUE)
			{
				log_debug("Reopen file failed, error code %d. Assume not symlink.\n", GetLastError());
				goto after_symlink_test;
			}
			CloseHandle(handle);
			log_debug("Reopen succeeded.\n");
			handle = read_handle;
		}
		if (winfs_read_symlink(handle, target, buflen) > 0)
		{
			if (!(flags & O_NOFOLLOW))
			{
				CloseHandle(handle);
				return 1;
			}
			if (!(flags & O_PATH))
			{
				CloseHandle(handle);
				log_debug("Specified O_NOFOLLOW but not O_PATH, returning ELOOP.\n");
				return -ELOOP;
			}
		}
		log_debug("Opening file directly.\n");
		LARGE_INTEGER p;
		p.QuadPart = 0;
		if (!SetFilePointerEx(handle, p, NULL, FILE_BEGIN))
		{
			log_debug("SetFilePointerEx() failed, error code: %d.\n", GetLastError());
			CloseHandle(handle);
			return -EIO;
		}
	}
	else if (attributeInfo.FileAttributes != INVALID_FILE_ATTRIBUTES && !(attributeInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (flags & O_DIRECTORY))
	{
		log_debug("Not a directory.\n");
		return -ENOTDIR;
	}

after_symlink_test:
	file = (struct winfs_file *)kmalloc(sizeof(struct winfs_file));
	file->base_file.op_vtable = &winfs_ops;
	file->base_file.ref = 1;
	file->handle = handle;
	*fp = file;
	return 0;
}

struct winfs
{
	struct file_system base_fs;
};

struct file_system *winfs_alloc()
{
	struct winfs *fs = (struct winfs *)kmalloc(sizeof(struct winfs));
	fs->base_fs.mountpoint = "/";
	fs->base_fs.open = winfs_open;
	fs->base_fs.symlink = winfs_symlink;
	fs->base_fs.readlink = winfs_readlink;
	fs->base_fs.unlink = winfs_unlink;
	return fs;
}
