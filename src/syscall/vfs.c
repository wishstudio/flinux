#include <common/errno.h>
#include <common/fcntl.h>
#include <fs/tty.h>
#include <fs/winfs.h>
#include <syscall/mm.h>
#include <syscall/vfs.h>
#include <log.h>
#include <Windows.h>

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
	struct file_system *fs_first;
	char cwd[PATH_MAX];
};

static struct vfs_data * const vfs = VFS_DATA_BASE;

static void vfs_add(struct file_system *fs)
{
	fs->next = vfs->fs_first;
	vfs->fs_first = fs;
}

void vfs_init()
{
	mm_mmap(VFS_DATA_BASE, sizeof(struct vfs_data), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	vfs->fds[0] = tty_alloc(GetStdHandle(STD_INPUT_HANDLE));
	vfs->fds[1] = tty_alloc(GetStdHandle(STD_OUTPUT_HANDLE));
	vfs->fds[2] = tty_alloc(GetStdHandle(STD_ERROR_HANDLE));
	vfs_add(winfs_alloc());
	/* Initialize CWD */
	//static wchar_t wcwd[PATH_MAX];
	//int len = GetCurrentDirectoryW(PATH_MAX, wcwd);
	vfs->cwd[0] = '/';
	vfs->cwd[1] = 0;
}

void vfs_reset()
{
	/* TODO: Handle CLOEXEC */
}

void vfs_shutdown()
{
	for (int i = 0; i < MAX_FD_COUNT; i++)
	{
		struct file *f = vfs->fds[i];
		if (f)
			f->op_vtable->fn_close(f);
	}
	mm_munmap(VFS_DATA_BASE, sizeof(struct vfs_data));
}

size_t sys_read(int fd, char *buf, size_t count)
{
	log_debug("read(%d, %x, %d)\n", fd, buf, count);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->fn_read)
		return f->op_vtable->fn_read(f, buf, count);
	else
		return -EBADF;
}

size_t sys_write(int fd, const char *buf, size_t count)
{
	log_debug("write(%d, %x, %d)\n", fd, buf, count);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->fn_write)
		return f->op_vtable->fn_write(f, buf, count);
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
	}
	while (*pathname)
	{
		if (*pathname == '/')
			pathname++;
		else if (*pathname == '.' && *(pathname + 1) == '/')
			pathname += 2;
		else if (*pathname == '.' && *(pathname + 1) == '.' && *(pathname + 2) == '/')
		{
			while (p > out && *(p - 1) != '/')
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

/* Test if a component of the given path is a symlink */
static int resolve_symlink(struct file_system *fs, char *path, char *subpath, char *target)
{
	/* Test from right to left */
	/* Note: Currently we assume the symlink only appears in subpath */
	int found = 0;
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
				char *t = target + strlen(target);
				if (*t != '/')
					*t++ = '/';
				while (*q)
					*t++ = *q++;
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
		log_debug("No component is a symlink.\n");
	return found;
}

int sys_open(const char *pathname, int flags, int mode)
{
	log_debug("open(%x: \"%s\", %x, %x)\n", pathname, pathname, flags, mode);
	/* Supported flags:
	   o O_APPEND
	   o O_ASYNC
	   o O_CLOEXEC
	   o O_DIRECT
	   o O_DIRECTORY
	   o O_DSYNC
	   o O_EXCL
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
	if ((flags & O_APPEND) || (flags & O_CLOEXEC) || (flags & O_DIRECT)
		|| (flags & O_DIRECTORY) || (flags & O_DSYNC) || (flags & O_EXCL)
		|| (flags & O_LARGEFILE) || (flags & O_NOATIME) || (flags & O_NOCTTY)
		|| (flags & O_NONBLOCK) || (flags & O_SYNC) || (flags & O_TMPFILE))
	{
		log_debug("Unsupported flag combination.\n");
		//return -EINVAL;
	}
	if (mode != 0)
	{
		log_debug("mode != 0\n");
		return -EINVAL;
	}
	/* Resolve path */
	char path[MAX_PATH], target[MAX_PATH];
	struct file *f = NULL;
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
		int ret = fs->open(*subpath? subpath: ".", flags, mode, &f, target, MAX_PATH);
		if (ret == 0)
		{
			/* We're done opening the file */
			log_debug("Open file succeeded.\n");
			break;
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
			if (!resolve_symlink(fs, path, subpath, target))
				return ret;
		}
		else
		{
			log_debug("Open file error.\n");
			return ret;
		}
	}
	int fd = -1;
	for (int i = 0; i < MAX_FD_COUNT; i++)
		if (vfs->fds[i] == NULL)
		{
			fd = i;
			break;
		}
	if (fd == -1)
	{
		f->op_vtable->fn_close(f);
		return -EMFILE;
	}
	vfs->fds[fd] = f;
	return fd;
}

int sys_close(int fd)
{
	log_debug("close(%d)\n", fd);
	struct file *f = vfs->fds[fd];
	if (!f)
		return -EBADF;
	f->op_vtable->fn_close(f);
	return 0;
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
			if (!resolve_symlink(fs, path, subpath, target))
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
			if (!resolve_symlink(fs, path, subpath, target))
				return -ENOENT;
		}
		else
			return ret;
	}
}

int sys_dup2(int fd, int newfd)
{
	log_debug("dup2(%d, %d)\n", fd, newfd);
	struct file *f = vfs->fds[fd];
	if (!f)
		return -EBADF;
	if (fd == newfd)
		return newfd;
	/* TODO: Close newfd before duplicate */
	/* TODO: Do things atomically */
	vfs->fds[newfd] = f;
	f->ref++;
	return newfd;
}

int sys_getdents64(int fd, struct linux_dirent64 *dirent, unsigned int count)
{
	log_debug("getdents64(%d, %x, %d)\n", fd, dirent, count);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->fn_getdents)
		return f->op_vtable->fn_getdents(f, dirent, count);
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
	/* TODO: Call sys_close() */
	return ret;
}

int sys_lstat64(const char *pathname, struct stat64 *buf)
{
	log_debug("lstat64(\"%s\", %x)\n", pathname, buf);
	int fd = sys_open(pathname, O_PATH | O_NOFOLLOW, 0);
	if (fd < 0)
		return fd;
	int ret = sys_fstat64(fd, buf);
	/* TODO: Call sys_close() */
	return ret;
}

int sys_fstat64(int fd, struct stat64 *buf)
{
	log_debug("fstat64(%d, %x)\n", fd, buf);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->fn_stat)
		return f->op_vtable->fn_stat(f, buf);
	else
		return -EBADF;
}

int sys_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
	log_debug("ioctl(%d, %d, %x)\n", fd, cmd, arg);
	struct file *f = vfs->fds[fd];
	if (f && f->op_vtable->fn_ioctl)
		return f->op_vtable->fn_ioctl(f, cmd, arg);
	else
		return -EBADF;
}

int sys_chdir(const char *pathname)
{
	log_debug("chdir(%s)\n", pathname);
	int fd = sys_open(pathname, O_PATH, 0);
	if (fd < 0)
		return fd;
	sys_close(fd);
	strcpy(vfs->cwd, pathname);
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
