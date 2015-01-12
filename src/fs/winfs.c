#include <common/errno.h>
#include <common/fcntl.h>
#include <common/fs.h>
#include <fs/winfs.h>
#include <syscall/mm.h>
#include <syscall/vfs.h>
#include <datetime.h>
#include <heap.h>
#include <log.h>
#include <str.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <limits.h>
#include <ntdll.h>

#define WINFS_SYMLINK_HEADER		"!<SYMLINK>\379\378"
#define WINFS_SYMLINK_HEADER_LEN	(sizeof(WINFS_SYMLINK_HEADER) - 1)

struct winfs_file
{
	struct file base_file;
	HANDLE handle;
};

/* Convert a relative file name to NT file name, return name lengths, no NULL terminator is appended */
static int filename_to_nt_pathname(const char *filename, WCHAR *buf, int buf_size)
{
	if (buf_size < 4)
		return 0;
	buf[0] = L'\\';
	buf[1] = L'?';
	buf[2] = L'?';
	buf[3] = L'\\';
	buf += 4;
	buf_size -= 4;
	int out_size = 4;
	int len = (DWORD)GetCurrentDirectoryW(buf_size, buf);
	buf += len;
	out_size += len;
	buf_size -= len;
	if (filename[0] == 0)
		return out_size;
	*buf++ = L'\\';
	out_size++;
	buf_size--;
	int fl = utf8_to_utf16_filename(filename, strlen(filename), buf, buf_size);
	if (fl == 0)
		return 0;
	return out_size + fl;
}

/*
Test if a handle is a symlink, also return its target if requested.
For optimal performance, caller should ensure the handle is a regular file with system attribute.
*/
static int winfs_read_symlink(HANDLE hFile, char *target, int buflen)
{
	char header[WINFS_SYMLINK_HEADER_LEN];
	DWORD num_read;
	/* Use overlapped structure to avoid changing file pointer */
	OVERLAPPED overlapped;
	overlapped.Internal = 0;
	overlapped.InternalHigh = 0;
	overlapped.Offset = 0;
	overlapped.OffsetHigh = 0;
	overlapped.hEvent = 0;
	if (!ReadFile(hFile, header, WINFS_SYMLINK_HEADER_LEN, &num_read, &overlapped) || num_read < WINFS_SYMLINK_HEADER_LEN)
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
		overlapped.Offset = WINFS_SYMLINK_HEADER_LEN;
		if (!ReadFile(hFile, target, buflen, &num_read, &overlapped))
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

static size_t winfs_read(struct file *f, char *buf, size_t count)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	size_t num_read = 0;
	while (count > 0)
	{
		DWORD count_dword = (DWORD)min(count, (size_t)UINT_MAX);
		DWORD num_read_dword;
		if (!ReadFile(winfile->handle, buf, count_dword, &num_read_dword, NULL))
		{
			if (GetLastError() == ERROR_HANDLE_EOF)
				return num_read;
			log_warning("ReadFile() failed, error code: %d\n", GetLastError());
			return -EIO;
		}
		if (num_read_dword == 0)
			return num_read;
		num_read += num_read_dword;
		count -= num_read_dword;
	}
	return num_read;
}

static size_t winfs_write(struct file *f, const char *buf, size_t count)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	size_t num_written = 0;
	while (count > 0)
	{
		DWORD count_dword = (DWORD)min(count, (size_t)UINT_MAX);
		DWORD num_written_dword;
		if (!WriteFile(winfile->handle, buf, count_dword, &num_written_dword, NULL))
		{
			log_warning("WriteFile() failed, error code: %d\n", GetLastError());
			return -EIO;
		}
		num_written += num_written_dword;
		count -= num_written_dword;
	}
	return num_written;
}

static size_t winfs_pread(struct file *f, char *buf, size_t count, loff_t offset)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	size_t num_read = 0;
	while (count > 0)
	{
		OVERLAPPED overlapped;
		overlapped.Internal = 0;
		overlapped.InternalHigh = 0;
		overlapped.Offset = offset & 0xFFFFFFFF;
		overlapped.OffsetHigh = offset >> 32ULL;
		overlapped.hEvent = 0;
		DWORD count_dword = (DWORD)min(count, (size_t)UINT_MAX);
		DWORD num_read_dword;
		if (!ReadFile(winfile->handle, buf, count_dword, &num_read_dword, &overlapped))
		{
			if (GetLastError() == ERROR_HANDLE_EOF)
				return num_read;
			log_warning("ReadFile() failed, error code: %d\n", GetLastError());
			return -EIO;
		}
		if (num_read_dword == 0)
			return num_read;
		num_read += num_read_dword;
		offset += num_read_dword;
		count -= num_read_dword;
	}
	return num_read;
}

static size_t winfs_pwrite(struct file *f, const char *buf, size_t count, loff_t offset)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	size_t num_written = 0;
	while (count > 0)
	{
		OVERLAPPED overlapped;
		overlapped.Internal = 0;
		overlapped.InternalHigh = 0;
		overlapped.Offset = offset & 0xFFFFFFFF;
		overlapped.OffsetHigh = offset >> 32ULL;
		overlapped.hEvent = 0;
		DWORD count_dword = (DWORD)min(count, (size_t)UINT_MAX);
		DWORD num_written_dword;
		if (!WriteFile(winfile->handle, buf, count_dword, &num_written_dword, &overlapped))
		{
			log_warning("WriteFile() failed, error code: %d\n", GetLastError());
			return -EIO;
		}
		num_written += num_written_dword;
		offset += num_written_dword;
		count -= num_written_dword;
	}
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

static int winfs_stat(struct file *f, struct newstat *buf)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(winfile->handle, &info))
	{
		log_warning("GetFileInformationByHandle() failed.\n");
		return -1; /* TODO */
	}
	/* Programs (ld.so) may use st_dev and st_ino to identity files so these must be unique for each file. */
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(8, 0); // (8, 0): /dev/sda
	//buf->st_ino = ((uint64_t)info.nFileIndexHigh << 32ULL) + info.nFileIndexLow;
	/* Hash 64 bit inode to 32 bit to fix legacy applications
	 * We may later add an option for changing this behaviour
	 */
	buf->st_ino = info.nFileIndexHigh ^ info.nFileIndexLow;
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

static int winfs_utimens(struct file *f, const struct timespec *times)
{
	struct winfs_file *winfs = (struct winfs_file *)f;
	if (!times)
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
		unix_timespec_to_filetime(&times[0], &actime);
		unix_timespec_to_filetime(&times[1], &modtime);
		SetFileTime(winfs->handle, NULL, &actime, &modtime);
	}
	return 0;
}

static int winfs_getdents(struct file *f, void *dirent, size_t count, getdents_callback *fill_callback)
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
			void *p = (char *)dirent + size;
			uint64_t inode = info->FileId.QuadPart;
			char type = (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? DT_DIR : DT_REG;
			intptr_t reclen = fill_callback(p, inode, info->FileName, info->FileNameLength / 2, type, count - size);
			if (reclen < 0)
				return reclen;
			size += reclen;
		} while (info->NextEntryOffset);
	}
	return size;
	#undef BUFFER_SIZE
}

static int winfs_statfs(struct file *f, struct statfs64 *buf)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	FILE_FS_FULL_SIZE_INFORMATION info;
	IO_STATUS_BLOCK status_block;
	NTSTATUS status = NtQueryVolumeInformationFile(winfile->handle, &status_block, &info, sizeof(info), FileFsFullSizeInformation);
	if (status != STATUS_SUCCESS)
	{
		log_warning("NtQueryVolumeInformationFile() failed, status: %x\n", status);
		return -EIO;
	}
	buf->f_type = 0x5346544e; /* NTFS_SB_MAGIC */
	buf->f_bsize = info.SectorsPerAllocationUnit * info.BytesPerSector;
	buf->f_blocks = info.TotalAllocationUnits.QuadPart;
	buf->f_bfree = info.ActualAvailableAllocationUnits.QuadPart;
	buf->f_bavail = info.CallerAvailableAllocationUnits.QuadPart;
	buf->f_files = 0;
	buf->f_ffree = 0;
	buf->f_fsid.val[0] = 0;
	buf->f_fsid.val[1] = 0;
	buf->f_namelen = PATH_MAX;
	buf->f_frsize = 0;
	buf->f_flags = 0;
	buf->f_spare[0] = 0;
	buf->f_spare[1] = 0;
	buf->f_spare[2] = 0;
	buf->f_spare[3] = 0;
	return 0;
}

static struct file_ops winfs_ops = 
{
	.close = winfs_close,
	.read = winfs_read,
	.write = winfs_write,
	.pread = winfs_pread,
	.pwrite = winfs_pwrite,
	.llseek = winfs_llseek,
	.stat = winfs_stat,
	.utimens = winfs_utimens,
	.getdents = winfs_getdents,
	.statfs = winfs_statfs,
};

static int winfs_symlink(const char *target, const char *linkpath)
{
	HANDLE handle;
	WCHAR wlinkpath[PATH_MAX];

	if (utf8_to_utf16_filename(linkpath, strlen(linkpath) + 1, wlinkpath, PATH_MAX) <= 0)
		return -ENOENT;

	log_info("CreateFileW(): %s\n", linkpath);
	handle = CreateFileW(wlinkpath, GENERIC_WRITE, FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_SYSTEM, NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		DWORD err = GetLastError();
		if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS)
		{
			log_warning("File already exists.\n");
			return -EEXIST;
		}
		log_warning("CreateFileW() failed, error code: %d.\n", GetLastError());
		return -ENOENT;
	}
	DWORD num_written;
	if (!WriteFile(handle, WINFS_SYMLINK_HEADER, WINFS_SYMLINK_HEADER_LEN, &num_written, NULL) || num_written < WINFS_SYMLINK_HEADER_LEN)
	{
		log_warning("WriteFile() failed, error code: %d.\n", GetLastError());
		CloseHandle(handle);
		return -EIO;
	}
	DWORD targetlen = strlen(target);
	if (!WriteFile(handle, target, targetlen, &num_written, NULL) || num_written < targetlen)
	{
		log_warning("WriteFile() failed, error code: %d.\n", GetLastError());
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

	if (utf8_to_utf16_filename(pathname, strlen(pathname) + 1, wpathname, PATH_MAX) <= 0)
		return -ENOENT;
	/* TODO: This is not concurrency safe */
	attr = GetFileAttributesW(wpathname);
	if (attr == INVALID_FILE_ATTRIBUTES)
		return -ENOENT;
	if ((attr & FILE_ATTRIBUTE_DIRECTORY) || !(attr & FILE_ATTRIBUTE_SYSTEM))
		return -EINVAL;
	hFile = CreateFileW(wpathname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return -EIO;
	int ret = winfs_read_symlink(hFile, target, (int)buflen);
	CloseHandle(hFile);
	return ret;
}

static int winfs_link(struct file *f, const char *newpath)
{
	struct winfs_file *winfile = (struct winfs_file *) f;
	NTSTATUS status;
	char buf[sizeof(FILE_LINK_INFORMATION) + PATH_MAX * 2];
	FILE_LINK_INFORMATION *info = (FILE_LINK_INFORMATION *)buf;
	info->ReplaceIfExists = FALSE;
	info->RootDirectory = NULL;
	info->FileNameLength = 2 * filename_to_nt_pathname(newpath, info->FileName, PATH_MAX);
	if (info->FileNameLength == 0)
		return -ENOENT;
	IO_STATUS_BLOCK status_block;
	status = NtSetInformationFile(winfile->handle, &status_block, info, info->FileNameLength + sizeof(FILE_LINK_INFORMATION), FileLinkInformation);
	if (status != STATUS_SUCCESS)
	{
		log_warning("NtSetInformationFile() failed, status: %x.\n", status);
		return -ENOENT;
	}
	return 0;
}

static int winfs_unlink(const char *pathname)
{
	WCHAR wpathname[PATH_MAX];
	
	if (utf8_to_utf16_filename(pathname, strlen(pathname) + 1, wpathname, PATH_MAX) <= 0)
		return -ENOENT;
	if (!DeleteFileW(wpathname))
	{
		log_warning("DeleteFile() failed.\n");
		return -ENOENT;
	}
	return 0;
}

static int winfs_rename(struct file *f, const char *newpath)
{
	struct winfs_file *winfile = (struct winfs_file *)f;
	char buf[sizeof(FILE_RENAME_INFORMATION) + PATH_MAX * 2];
	NTSTATUS status;
	FILE_RENAME_INFORMATION *info = (FILE_RENAME_INFORMATION *)buf;
	info->ReplaceIfExists = TRUE;
	info->RootDirectory = NULL;
	info->FileNameLength = 2 * filename_to_nt_pathname(newpath, info->FileName, PATH_MAX);
	if (info->FileNameLength == 0)
		return -ENOENT;
	IO_STATUS_BLOCK status_block;
	status = NtSetInformationFile(winfile->handle, &status_block, info, info->FileNameLength + sizeof(FILE_RENAME_INFORMATION), FileRenameInformation);
	if (status != STATUS_SUCCESS)
	{
		log_warning("NtSetInformationFile() failed, status: %x\n", status);
		return -ENOENT;
	}
	return 0;
}

static int winfs_mkdir(const char *pathname, int mode)
{
	WCHAR wpathname[PATH_MAX];

	if (utf8_to_utf16_filename(pathname, strlen(pathname) + 1, wpathname, PATH_MAX) <= 0)
		return -ENOENT;
	if (!CreateDirectoryW(wpathname, NULL))
	{
		DWORD err = GetLastError();
		if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS)
		{
			log_warning("File already exists.\n");
			return -EEXIST;
		}
		log_warning("CreateDirectoryW() failed, error code: %d\n", GetLastError());
		return -ENOENT;
	}
	return 0;
}

static int winfs_rmdir(const char *pathname)
{
	WCHAR wpathname[PATH_MAX];
	if (utf8_to_utf16_filename(pathname, strlen(pathname) + 1, wpathname, PATH_MAX) <= 0)
		return -ENOENT;
	if (!RemoveDirectoryW(wpathname))
	{
		log_warning("RemoveDirectoryW() failed, error code: %d\n", GetLastError());
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

	if (utf8_to_utf16_filename(pathname, strlen(pathname) + 1, wpathname, PATH_MAX) <= 0)
		return -ENOENT;

	if (flags & O_PATH)
		desiredAccess = 0;
	else if (flags & O_RDWR)
		desiredAccess = GENERIC_READ | GENERIC_WRITE;
	else if (flags & O_WRONLY)
		desiredAccess = GENERIC_WRITE;
	else
		desiredAccess = GENERIC_READ;
	if (flags & __O_DELETE)
		desiredAccess |= DELETE;
	shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
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
	log_info("CreateFileW(): %s\n", pathname);
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
			log_warning("File already exists.\n");
			return -EEXIST;
		}
		else
		{
			log_warning("Unhandled CreateFileW() failure, error code: %d, returning ENOENT.\n", GetLastError());
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
		log_info("The file has system flag set.\n");
		if (!(desiredAccess & GENERIC_READ))
		{
			/* We need to get a readable handle */
			log_info("But the handle does not have READ access, try reopening file...\n");
			HANDLE read_handle = ReOpenFile(handle, desiredAccess | GENERIC_READ, shareMode, FILE_FLAG_BACKUP_SEMANTICS);
			if (read_handle == INVALID_HANDLE_VALUE)
			{
				log_warning("Reopen file failed, error code %d. Assume not symlink.\n", GetLastError());
				goto after_symlink_test;
			}
			CloseHandle(handle);
			log_info("Reopen succeeded.\n");
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
				log_info("Specified O_NOFOLLOW but not O_PATH, returning ELOOP.\n");
				return -ELOOP;
			}
		}
		log_info("Opening file directly.\n");
	}
	else if (attributeInfo.FileAttributes != INVALID_FILE_ATTRIBUTES && !(attributeInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (flags & O_DIRECTORY))
	{
		log_warning("Not a directory.\n");
		return -ENOTDIR;
	}

after_symlink_test:
	file = (struct winfs_file *)kmalloc(sizeof(struct winfs_file));
	file->base_file.op_vtable = &winfs_ops;
	file->base_file.ref = 1;
	file->base_file.flags = flags;
	file->handle = handle;
	*fp = (struct file *)file;
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
	fs->base_fs.link = winfs_link;
	fs->base_fs.unlink = winfs_unlink;
	fs->base_fs.rename = winfs_rename;
	fs->base_fs.mkdir = winfs_mkdir;
	fs->base_fs.rmdir = winfs_rmdir;
	return (struct file_system *)fs;
}

int winfs_is_winfile(struct file *f)
{
	return f->op_vtable == &winfs_ops;
}
