#include <common/errno.h>
#include <common/fcntl.h>
#include <fs/tty.h>
#include <fs/winfs.h>
#include <syscall/mm.h>
#include <syscall/vfs.h>
#include <log.h>
#include <Windows.h>

#define MAX_FD_COUNT	1024
#define PATH_MAX		4096

struct vfs_data
{
	struct file *fds[MAX_FD_COUNT];
	struct file_system *fs_first;
	char cwd[PATH_MAX];
	size_t cwdlen;
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
	vfs->cwdlen = 2;
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
		while (*current)
			*p++ = *current++;
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
	*p = 0;
	return 0;
}

int sys_open(const char *pathname, int flags, int mode)
{
	/* TODO: Check flags */
	log_debug("open(%x: \"%s\", %x, %x)\n", pathname, pathname, flags, mode);
	char path[MAX_PATH];
	int r = normalize_path("/", pathname, path);
	if (r < 0)
	{
		return r;
	}
	struct file_system *fs;
	char *subpath;
	for (fs = vfs->fs_first; fs; fs = fs->next)
	{
		char *p = fs->mountpoint;
		subpath = path;
		while (*p && *p == *subpath)
		{
			p++;
			subpath++;
		}
		if (*p == 0)
			break;
	}
	struct file *f = fs->open(subpath, flags, mode);
	if (!f)
		return -1; /* TODO: errno */
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
	int fd = sys_open(pathname, __O_STATONLY, 0);
	if (fd < 0)
		return fd;
	int ret = sys_fstat64(fd, buf);
	/* TODO: Call sys_close() */
	return ret;
}

int sys_lstat64(const char *pathname, struct stat64 *buf)
{
	log_debug("lstat64(\"%s\", %x)\n", pathname, buf);
	int fd = sys_open(pathname, __O_STATONLY | O_NOFOLLOW, 0);
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
	return -EIO;
}

char *sys_getcwd(char *buf, size_t size)
{
	log_debug("getcwd(%x, %d): %s\n", buf, size, vfs->cwd);
	if (size < vfs->cwdlen)
		return -ERANGE;
	strcpy(buf, vfs->cwd);
	return buf;
}

int sys_fcntl64(int fd, int cmd, ...)
{
	log_debug("fcntl64(%d, %d)\n", fd, cmd);
	return 0;
}
