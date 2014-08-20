#include <common/errno.h>
#include <common/fcntl.h>
#include <fs/console.h>
#include <fs/pipe.h>
#include <fs/winfs.h>
#include <syscall/mm.h>
#include <syscall/vfs.h>
#include <log.h>
#include <Windows.h>
#include <limits.h>

/* Notes on symlink solving:

   Sometimes we need to perform file operation and symlink checking at
   one place.

   For example, if we test symlink first and try opening file later,
   another process may replace the file with a symlink after the symlink
   check. This will result in opening a symlink file as a regular file.

   But for path components this is fine as if a symlink check fails for
   a component, the whole operation immediately fails.
*/

#define MAX_FD_COUNT		1024
#define MAX_SYMLINK_LEVEL	8

struct vfs_data
{
	struct file *fds[MAX_FD_COUNT];
	int fds_cloexec[MAX_FD_COUNT];
	struct file_system *fs_first;
	char cwd[PATH_MAX];
	int umask;
};

static struct vfs_data * const vfs = VFS_DATA_BASE;

static void vfs_add(struct file_system *fs)
{
	fs->next = vfs->fs_first;
	vfs->fs_first = fs;
}

/* Close a file, only used on raw file not created by sys_open() */
static void vfs_close_raw(struct file *f)
{
	if (--f->ref == 0)
		f->op_vtable->close(f);
}

/* Close a file descriptor fd */
static void vfs_close(int fd)
{
	struct file *f = vfs->fds[fd];
	if (--f->ref == 0)
		f->op_vtable->close(f);
	vfs->fds[fd] = NULL;
	vfs->fds_cloexec[fd] = 0;
}

void vfs_init()
{
	mm_mmap(VFS_DATA_BASE, sizeof(struct vfs_data), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	struct file *console = console_alloc();
	console->ref = 3;
	vfs->fds[0] = console;
	vfs->fds[1] = console;
	vfs->fds[2] = console;
	vfs_add(winfs_alloc());
	/* Initialize CWD */
	//static wchar_t wcwd[PATH_MAX];
	//int len = GetCurrentDirectoryW(PATH_MAX, wcwd);
	vfs->cwd[0] = '/';
	vfs->cwd[1] = 0;
	vfs->umask = S_IWGRP | S_IWOTH;
}

void vfs_reset()
{
	/* Handle O_CLOEXEC */
	for (int i = 0; i < MAX_FD_COUNT; i++)
	{
		struct file *f = vfs->fds[i];
		if (f && vfs->fds_cloexec[i])
			vfs_close(i);
	}
	vfs->umask = S_IWGRP | S_IWOTH;
}

void vfs_shutdown()
{
	for (int i = 0; i < MAX_FD_COUNT; i++)
	{
		struct file *f = vfs->fds[i];
		if (f)
			vfs_close(i);
	}
	mm_munmap(VFS_DATA_BASE, sizeof(struct vfs_data));
}

static int alloc_fd_slot()
{
	for (int i = 0; i < MAX_FD_COUNT; i++)
		if (vfs->fds[i] == NULL)
			return i;
	return -1;
}

size_t sys_read(int fd, char *buf, size_t count)
{
	log_debug("read(%d, %x, %d)\n", fd, buf, count);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->read)
		return f->op_vtable->read(f, buf, count);
	else
		return -EBADF;
}

size_t sys_write(int fd, const char *buf, size_t count)
{
	log_debug("write(%d, %x, %d)\n", fd, buf, count);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->write)
		return f->op_vtable->write(f, buf, count);
	else
		return -EBADF;
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
	log_debug("lseek(%d, %d, %d)\n", fd, offset, whence);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->llseek)
	{
		loff_t n;
		int r = f->op_vtable->llseek(f, offset, &n, whence);
		if (r < 0)
			return r;
		if (n >= INT_MAX)
			return -EOVERFLOW; /* TODO: Do we need to rollback? */
		return (off_t) n;
	}
	else
		return -EBADF;
}

int sys_llseek(int fd, unsigned long offset_high, unsigned long offset_low, loff_t *result, int whence)
{
	loff_t offset = ((uint64_t) offset_high << 32ULL) + offset_low;
	log_debug("llseek(%d, %lld, %x, %d)\n", fd, offset, result, whence);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->llseek)
		return f->op_vtable->llseek(f, offset, result, whence);
	else
		return -EBADF;
}

static int find_filesystem(const char *path, struct file_system **out_fs, char **out_subpath)
{
	struct file_system *fs;
	for (fs = vfs->fs_first; fs; fs = fs->next)
	{
		char *p = fs->mountpoint;
		char *subpath = path;
		while (*p && *p == *subpath)
		{
			p++;
			subpath++;
		}
		if (*p == 0)
		{
			*out_fs = fs;
			*out_subpath = subpath;
			return 1;
		}
	}
	return 0;
}

/* Normalize a unix path: remove redundant "/", "." and ".."
   We allow aliasing `current` and `out` */
static int normalize_path(const char *current, const char *pathname, char *out)
{
	/* TODO: Avoid overflow */
	char *p = out;
	if (*pathname == '/')
	{
		*p++ = '/';
		pathname++;
	}
	else
	{
		if (current == out)
			p += strlen(current);
		else
		{
			while (*current)
				*p++ = *current++;
		}
		if (p[-1] != '/')
			*p++ = '/';
	}
	while (pathname[0])
	{
		if (pathname[0] == '/')
			pathname++;
		else if (pathname[0] == '.' && pathname[1] == '/')
			pathname += 2;
		else if (pathname[0] == '.' && pathname[1] == 0)
			pathname += 1;
		else if (pathname[0] == '.' && pathname[1] == '.' && (pathname[2] == '/' || pathname[2] == 0))
		{
			if (pathname[2] == 0)
				pathname += 2;
			else
				pathname += 3;
			while (p > out && p[-1] != '/')
				p--;
		}
		else
		{
			while (*pathname && *pathname != '/')
				*p++ = *pathname++;
			if (*pathname == '/')
				*p++ = *pathname++;
		}
	}
	/* Remove redundant "/" mark at tail, unless the whole path is just "/" */
	if (p - 1 > out && p[-1] == '/')
		p[-1] = 0;
	else
		*p = 0;
	return 1;
}

/*
Test if a component of the given path is a symlink
Return 0 for success, errno for error
*/
static int resolve_symlink(struct file_system *fs, char *path, char *subpath, char *target)
{
	/* Test from right to left */
	/* Note: Currently we assume the symlink only appears in subpath */
	int found = 0;
	log_debug("PATH: %s\n", path);
	for (char *p = subpath + strlen(subpath) - 1; p > subpath; p--)
	{
		if (*p == '/')
		{
			*p = 0;
			log_debug("Testing %s\n", path);
			int r = fs->readlink(subpath, target, MAX_PATH);
			if (r >= 0)
			{
				log_debug("It is a symlink, target: %s\n", target);
				found = 1;
				/* Combine symlink target with remaining path */
				char *q = p + 1;
				char *t = target + r;
				if (*t != '/')
					*t++ = '/';
				while (*q)
					*t++ = *q++;
				*t++ = 0;
				/* Remove symlink basename from path */
				while (p[-1] != '/')
					p--;
				p[0] = 0;
				/* Combine heading file path with remaining path */
				if (!normalize_path(path, target, path))
					return -ENOENT;
				break;
			}
			else if (r != -ENOENT)
				/* A component exists, or i/o failed, returning failure */
				return r;
			*p = '/';
		}
	}
	if (!found)
	{
		log_debug("No component is a symlink.\n");
		return -ENOENT;
	}
	return 0;
}

int vfs_open(const char *pathname, int flags, int mode, struct file **f)
{
	/*
	Supported flags:
	o O_APPEND
	o O_ASYNC
	* O_CLOEXEC
	o O_DIRECT
	* O_DIRECTORY
	o O_DSYNC
	* O_EXCL
	o O_LARGEFILE
	o O_NOATIME
	o O_NOCTTY
	* O_NOFOLLOW
	o O_NONBLOCK
	* O_PATH
	* O_RDONLY
	* O_RDWR
	o O_SYNC
	o O_TMPFILE
	* O_TRUNC
	* O_WRONLY
	All filesystem not supporting these flags should explicitly check "flags" parameter
	*/
	if ((flags & O_APPEND) || (flags & O_DIRECT)
		|| (flags & O_DSYNC)
		|| (flags & O_LARGEFILE) || (flags & O_NOATIME) || (flags & O_NOCTTY)
		|| (flags & O_NONBLOCK) || (flags & O_SYNC) || (flags & O_TMPFILE))
	{
		log_debug("Unsupported flag combination.\n");
		//return -EINVAL;
	}
	if (mode != 0)
	{
		log_debug("mode != 0\n");
		//return -EINVAL;
	}
	/* Resolve path */
	char path[MAX_PATH], target[MAX_PATH];
	if (!normalize_path(vfs->cwd, pathname, path))
		return -ENOENT;
	for (int symlink_level = 0;; symlink_level++)
	{
		if (symlink_level == MAX_SYMLINK_LEVEL)
		{
			return -ELOOP;
		}
		/* Find filesystem */
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(path, &fs, &subpath))
			return -ENOENT;
		/* Try opening the file directly */
		log_debug("Try opening %s\n", path);
		int ret = fs->open(*subpath ? subpath : ".", flags, mode, f, target, MAX_PATH);
		if (ret == 0)
		{
			/* We're done opening the file */
			log_debug("Open file succeeded.\n");
			return 0;
		}
		else if (ret == 1)
		{
			/* The file is a symlink, continue symlink resolving */
			log_debug("It is a symlink, target: %s\n", target);
			/* Remove basename */
			char *p = path + strlen(path) - 1;
			while (*p != '/')
				p--;
			p[1] = 0;
			/* Combine file path with symlink target */
			if (!normalize_path(path, target, path))
				return -ENOENT;
		}
		else if (ret == -ENOENT)
		{
			log_debug("Open file failed, testing whether a component is a symlink...\n");
			if (resolve_symlink(fs, path, subpath, target) < 0)
				return ret;
		}
		else
		{
			log_debug("Open file error.\n");
			return ret;
		}
	}
}

int sys_open(const char *pathname, int flags, int mode)
{
	log_debug("open(%x: \"%s\", %x, %x)\n", pathname, pathname, flags, mode);
	struct file *f;
	int r = vfs_open(pathname, flags, mode, &f);
	if (r < 0)
		return r;
	int fd = alloc_fd_slot();
	if (fd == -1)
	{
		vfs_close_raw(f);
		return -EMFILE;
	}
	vfs->fds[fd] = f;
	vfs->fds_cloexec[fd] = (flags & O_CLOEXEC) > 0;
	return fd;
}

int sys_close(int fd)
{
	log_debug("close(%d)\n", fd);
	struct file *f = vfs->fds[fd];
	if (!f)
		return -EBADF;
	if (--f->ref == 0)
	{
		f->op_vtable->close(f);
		vfs->fds[fd] = NULL;
		vfs->fds_cloexec[fd] = 0;
	}
	return 0;
}

int sys_mknod(const char *pathname, int mode, unsigned int dev)
{
	log_debug("mknod(\"%s\", %x, (%d:%d))", pathname, mode, major(dev), minor(dev));
	/* TODO: Touch that file */
	return 0;
}

int sys_link(const char *oldpath, const char *newpath)
{
	log_debug("link(\"%s\", \"%s\")\n", oldpath, newpath);
	struct file *f;
	char path[MAX_PATH], target[MAX_PATH];
	if (!normalize_path(vfs->cwd, newpath, path))
		return -ENOENT;
	int r = vfs_open(oldpath, O_PATH | O_NOFOLLOW, 0, &f);
	if (r < 0)
		return r;
	if (!winfs_is_winfile(f))
		return -EPERM;
	for (int symlink_level = 0;; symlink_level++)
	{
		if (symlink_level == MAX_SYMLINK_LEVEL)
		{
			return -ELOOP;
		}
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(path, &fs, &subpath))
		{
			vfs_close_raw(f);
			return -ENOENT;
		}
		log_debug("Try linking file...\n");
		int ret;
		if (!fs->link)
			ret = -ENOENT;
		else
			ret = fs->link(f, subpath);
		if (ret == 0)
		{
			log_debug("Link succeeded.\n");
			vfs_close_raw(f);
			return 0;
		}
		else if (ret == -ENOENT)
		{
			log_debug("Link failed, testing whether a component is a symlink...\n");
			if (resolve_symlink(fs, path, subpath, target) < 0)
			{
				vfs_close_raw(f);
				return -ENOENT;
			}
		}
		else
		{
			vfs_close_raw(f);
			return ret;
		}
	}
}

int sys_unlink(const char *pathname)
{
	log_debug("unlink(\"%s\")\n", pathname);
	char path[MAX_PATH], target[MAX_PATH];
	if (!normalize_path(vfs->cwd, pathname, path))
		return -ENOENT;
	for (int symlink_level = 0;; symlink_level++)
	{
		if (symlink_level == MAX_SYMLINK_LEVEL)
		{
			return -ELOOP;
		}
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(path, &fs, &subpath))
			return -ENOENT;
		log_debug("Try unlinking file...\n");
		int ret = fs->unlink(subpath);
		if (ret == 0)
		{
			log_debug("Unlink succeeded.\n");
			return 0;
		}
		else if (ret == -ENOENT)
		{
			log_debug("Unlink failed, testing whether a component is a symlink...\n");
			if (resolve_symlink(fs, path, subpath, target) < 0)
				return -ENOENT;
		}
		else
			return ret;
	}
}

int sys_symlink(const char *symlink_target, const char *linkpath)
{
	log_debug("symlink(\"%s\", \"%s\")\n", symlink_target, linkpath);
	char path[MAX_PATH], target[MAX_PATH];
	if (!normalize_path(vfs->cwd, linkpath, path))
		return -ENOENT;
	for (int symlink_level = 0;; symlink_level++)
	{
		if (symlink_level == MAX_SYMLINK_LEVEL)
		{
			return -ELOOP;
		}
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(path, &fs, &subpath))
			return -ENOENT;
		log_debug("Try creating symlink...\n");
		int ret = fs->symlink(symlink_target, subpath);
		if (ret == 0)
		{
			log_debug("Symlink succeeded.\n");
			return 0;
		}
		else if (ret == -ENOENT)
		{
			log_debug("Create symlink failed, testing whether a component is a symlink...\n");
			if (resolve_symlink(fs, path, subpath, target) < 0)
				return -ENOENT;
		}
		else
			return ret;
	}
}

size_t sys_readlink(const char *pathname, char *buf, int bufsize)
{
	log_debug("readlink(\"%s\", %x, %d)\n", pathname, buf, bufsize);
	char path[MAX_PATH], target[MAX_PATH];
	if (!normalize_path(vfs->cwd, pathname, path))
		return -ENOENT;
	for (int symlink_level = 0;; symlink_level++)
	{
		if (symlink_level == MAX_SYMLINK_LEVEL)
		{
			return -ELOOP;
		}
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(path, &fs, &subpath))
			return -ENOENT;
		log_debug("Try reading symlink...\n");
		int ret = fs->readlink(subpath, buf, bufsize);
		if (ret == -ENOENT)
		{
			log_debug("Symlink not found, testing whether a component is a symlink...\n");
			if (resolve_symlink(fs, path, subpath, target) < 0)
				return -ENOENT;
		}
		else
			return ret;
	}
}

int sys_pipe(int pipefd[2])
{
	return sys_pipe2(pipefd, 0);
}

int sys_pipe2(int pipefd[2], int flags)
{
	/*
	Supported flags:
	* O_CLOEXEC
	o O_DIRECT
	o O_NONBLOCK
	*/
	log_debug("pipe2(%x, %d)\n", pipefd, flags);
	if ((flags & O_DIRECT) || (flags & O_NONBLOCK))
	{
		log_debug("Unsupported flags combination: %x\n", flags);
		return -EINVAL;
	}
	struct file *fread, *fwrite;
	int r = pipe_alloc(&fread, &fwrite, flags);
	if (r < 0)
		return r;
	/* TODO: Deal with EMFILE error */
	int rfd = alloc_fd_slot();
	vfs->fds[rfd] = fread;
	vfs->fds_cloexec[rfd] = (flags & O_CLOEXEC) > 0;
	int wfd = alloc_fd_slot();
	vfs->fds[wfd] = fwrite;
	vfs->fds_cloexec[wfd] = (flags & O_CLOEXEC) > 0;
	pipefd[0] = rfd;
	pipefd[1] = wfd;
	return 0;
}

int sys_dup2(int fd, int newfd)
{
	log_debug("dup2(%d, %d)\n", fd, newfd);
	struct file *f = vfs->fds[fd];
	if (!f)
		return -EBADF;
	if (fd == newfd)
		return newfd;
	if (vfs->fds[newfd])
		vfs_close(newfd);
	vfs->fds[newfd] = f;
	vfs->fds_cloexec[newfd] = 0;
	f->ref++;
	return newfd;
}

int sys_mkdir(const char *pathname, int mode)
{
	log_debug("mkdir(\"%s\", %x)\n", pathname, mode);
	if (mode != 0)
		log_debug("mode != 0\n");
	char path[MAX_PATH], target[MAX_PATH];
	if (!normalize_path(vfs->cwd, pathname, path))
		return -ENOENT;
	for (int symlink_level = 0;; symlink_level++)
	{
		if (symlink_level == MAX_SYMLINK_LEVEL)
		{
			return -ELOOP;
		}
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(path, &fs, &subpath))
			return -ENOENT;
		log_debug("Try creating directory...\n");
		int ret = fs->mkdir(subpath, mode);
		if (ret == -ENOENT)
		{
			log_debug("Creating directory failed, testing whether a component is a symlink...\n");
			if (resolve_symlink(fs, path, subpath, target) < 0)
				return -ENOENT;
		}
		else
			return ret;
	}
}

int sys_getdents64(int fd, struct linux_dirent64 *dirent, unsigned int count)
{
	log_debug("getdents64(%d, %x, %d)\n", fd, dirent, count);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->getdents)
		return f->op_vtable->getdents(f, dirent, count);
	else
		return -EBADF;
}

void stat_from_stat64(struct stat *stat, struct stat64 *stat64)
{
	stat->st_dev = stat64->st_dev;
	stat->st_ino = stat64->st_ino;
	stat->st_mode = stat64->st_mode;
	stat->st_nlink = stat64->st_nlink;
	stat->st_uid = stat64->st_uid;
	stat->st_gid = stat64->st_gid;
	stat->st_rdev = stat64->st_rdev;
	stat->st_size = stat64->st_size;
	stat->st_blksize = stat64->st_blksize;
	stat->st_blocks = stat64->st_blocks;
	stat->st_atime = stat64->st_atime;
	stat->st_atime_nsec = stat64->st_atime_nsec;
	stat->st_mtime = stat64->st_mtime;
	stat->st_mtime_nsec = stat64->st_mtime_nsec;
	stat->st_ctime = stat64->st_ctime;
	stat->st_ctime_nsec = stat64->st_ctime_nsec;
	stat->__unused1 = 0;
	stat->__unused2 = 0;
}

int sys_stat(const char *pathname, struct stat *buf)
{
	struct stat64 buf64;
	int r = sys_stat64(pathname, &buf64);
	if (r == 0)
		stat_from_stat64(buf, &buf64);
	return r;
}

int sys_lstat(const char *pathname, struct stat *buf)
{
	struct stat64 buf64;
	int r = sys_lstat64(pathname, &buf64);
	if (r == 0)
		stat_from_stat64(buf, &buf64);
	return r;
}

int sys_fstat(int fd, struct stat *buf)
{
	struct stat64 buf64;
	int r = sys_fstat64(fd, &buf64);
	if (r == 0)
		stat_from_stat64(buf, &buf64);
	return r;
}

int sys_stat64(const char *pathname, struct stat64 *buf)
{
	log_debug("stat64(\"%s\", %x)\n", pathname, buf);
	int fd = sys_open(pathname, O_PATH, 0);
	if (fd < 0)
		return fd;
	int ret = sys_fstat64(fd, buf);
	sys_close(fd);
	return ret;
}

int sys_lstat64(const char *pathname, struct stat64 *buf)
{
	log_debug("lstat64(\"%s\", %x)\n", pathname, buf);
	int fd = sys_open(pathname, O_PATH | O_NOFOLLOW, 0);
	if (fd < 0)
		return fd;
	int ret = sys_fstat64(fd, buf);
	sys_close(fd);
	return ret;
}

int sys_fstat64(int fd, struct stat64 *buf)
{
	log_debug("fstat64(%d, %x)\n", fd, buf);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->stat)
		return f->op_vtable->stat(f, buf);
	else
		return -EBADF;
}

int sys_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
	log_debug("ioctl(%d, %x, %x)\n", fd, cmd, arg);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->ioctl)
		return f->op_vtable->ioctl(f, cmd, arg);
	else
		return -EBADF;
}

int sys_utime(const char *filename, const struct utimbuf *times)
{
	log_debug("sys_utime(\"%s\", %x)\n", filename, times);
	struct file *f;
	int r = vfs_open(filename, O_WRONLY, 0, &f);
	if (r < 0)
		return r;
	struct timeval t[2];
	t[0].tv_sec = times->actime;
	t[0].tv_usec = 0;
	t[1].tv_sec = times->modtime;
	t[1].tv_usec = 0;
	r = f->op_vtable->utimes(f, t);
	if (r < 0)
		return r;
	vfs_close_raw(f);
	return 0;
}

int sys_utimes(const char *filename, const struct timeval times[2])
{
	log_debug("sys_utimes(\"%s\", %x)\n", filename, times);
	struct file *f;
	int r = vfs_open(filename, O_WRONLY, 0, &f);
	if (r < 0)
		return r;
	r = f->op_vtable->utimes(f, times);
	if (r < 0)
		return r;
	vfs_close_raw(f);
	return 0;
}

int sys_chdir(const char *pathname)
{
	log_debug("chdir(%s)\n", pathname);
	/* TODO: Check whether pathname is a directory */
	int fd = sys_open(pathname, O_PATH, 0);
	if (fd < 0)
		return fd;
	sys_close(fd);
	normalize_path(vfs->cwd, pathname, vfs->cwd);
	return 0;
}

char *sys_getcwd(char *buf, size_t size)
{
	log_debug("getcwd(%x, %d): %s\n", buf, size, vfs->cwd);
	if (size < strlen(vfs->cwd) + 1)
		return -ERANGE;
	strcpy(buf, vfs->cwd);
	return buf;
}

int sys_fcntl64(int fd, int cmd, ...)
{
	log_debug("fcntl64(%d, %d)\n", fd, cmd);
	return 0;
}

int sys_access(const char *pathname, int mode)
{
	log_debug("access(\"%s\", %d)\n", pathname, mode);
	return 0;
}

int sys_chmod(const char *pathname, int mode)
{
	log_debug("chmod(\"%s\", %d)\n", pathname, mode);
	return 0;
}

int sys_umask(int mask)
{
	int old = vfs->umask;
	vfs->umask = mask;
	return old;
}

int sys_chown(const char *pathname, uid_t owner, gid_t group)
{
	log_debug("chown(\"%s\", %d, %d)\n", pathname, owner, group);
	return 0;
}
