/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <common/errno.h>
#include <common/fadvise.h>
#include <common/fcntl.h>
#include <common/ioctls.h>
#include <fs/console.h>
#include <fs/devfs.h>
#include <fs/epollfd.h>
#include <fs/eventfd.h>
#include <fs/pipe.h>
#include <fs/procfs.h>
#include <fs/socket.h>
#include <fs/sysfs.h>
#include <fs/winfs.h>
#include <syscall/mm.h>
#include <syscall/sig.h>
#include <syscall/syscall.h>
#include <syscall/vfs.h>
#include <datetime.h>
#include <log.h>
#include <str.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <limits.h>
#include <malloc.h>

#include <stdlib.h>

/* Notes on symlink solving:

   Sometimes we need to perform file operation and symlink checking at
   one place.

   For example, if we test symlink first and try opening file later,
   another process may replace the file with a symlink after the symlink
   check. This will result in opening a symlink file as a regular file.

   But for path components this is fine as if a symlink check fails for
   a component, the whole operation immediately fails.
*/

struct filed
{
	struct file *fd;
	int cloexec;
};

struct vfs_data
{
	SRWLOCK rw_lock;
	struct filed filed[MAX_FD_COUNT];
	struct file_system *fs_first;
	struct file *cwd;
	int umask;
};

static struct vfs_data *vfs;

static void vfs_add(struct file_system *fs)
{
	fs->next = vfs->fs_first;
	vfs->fs_first = fs;
}

/* Reference a file, only used on raw file handles not created by sys_open() */
void vfs_ref(struct file *f)
{
	InterlockedIncrement(&f->ref);
}

/* Release a file, only used on raw file handles not created by sys_open() */
void vfs_release(struct file *f)
{
	if (InterlockedDecrement(&f->ref) == 0)
		f->op_vtable->close(f);
}

/* Get file handle to a fd (caller locks vfs, either exclusive or shared is okay) */
static struct file *vfs_get_internal(int fd)
{
	if (fd < 0 || fd >= MAX_FD_COUNT)
		return NULL;
	struct file *f = vfs->filed[fd].fd;
	if (f)
		vfs_ref(f);
	return f;
}

/* Get file handle to a fd */
struct file *vfs_get(int fd)
{
	if (fd < 0 || fd >= MAX_FD_COUNT)
		return NULL;
	AcquireSRWLockShared(&vfs->rw_lock);
	struct file *f = vfs->filed[fd].fd;
	if (f)
		vfs_ref(f);
	ReleaseSRWLockShared(&vfs->rw_lock);
	return f;
}

/* Close a file descriptor fd */
static void vfs_close(int fd)
{
	struct file *f = vfs->filed[fd].fd;
	vfs_release(f);
	vfs->filed[fd].fd = NULL;
	vfs->filed[fd].cloexec = 0;
}

void vfs_init()
{
	log_info("vfs subsystem initializing...");
	vfs = mm_static_alloc(sizeof(struct vfs_data));
	InitializeSRWLock(&vfs->rw_lock);
	struct file *console_in, *console_out;
	console_init();
	struct file *console = console_alloc();
	console->ref += 2;
	vfs->filed[0].fd = console;
	vfs->filed[1].fd = console;
	vfs->filed[2].fd = console;
	vfs_add(winfs_alloc());
	vfs_add(devfs_alloc());
	vfs_add(procfs_alloc());
	vfs_add(sysfs_alloc());
	/* Initialize CWD */
	if (vfs_openat(AT_FDCWD, "/", O_DIRECTORY | O_PATH, 0, &vfs->cwd) < 0)
	{
		log_error("Opening initial current directory \"/\" failed.");
		__debugbreak();
	}
	vfs->umask = S_IWGRP | S_IWOTH;
	socket_init();
	log_info("vfs subsystem initialized.");
}

void vfs_reset()
{
	/* Handle O_CLOEXEC */
	for (int i = 0; i < MAX_FD_COUNT; i++)
	{
		struct file *f = vfs->filed[i].fd;
		if (f && vfs->filed[i].cloexec)
			vfs_close(i);
	}
	vfs->umask = S_IWGRP | S_IWOTH;
}

void vfs_shutdown()
{
	for (int i = 0; i < MAX_FD_COUNT; i++)
	{
		struct file *f = vfs->filed[i].fd;
		if (f)
			vfs_close(i);
	}
	socket_shutdown();
}

int vfs_fork(HANDLE process)
{
	if (!console_fork(process))
		return 0;
	AcquireSRWLockShared(&vfs->rw_lock);
	for (int i = 0; i < MAX_FD_COUNT; i++)
		if (vfs->filed[i].fd)
			AcquireSRWLockShared(&vfs->filed[i].fd->rw_lock);
	return 1;
}

static int cmpfiled(const void *a, const void *b)
{
	int fda = *(int *)a;
	int fdb = *(int *)b;

	struct file *filea = vfs->filed[fda].fd;
	struct file *fileb = vfs->filed[fdb].fd;

	if (filea > fileb)
	{
		return 1;
	}
	else if (filea < fileb)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

void vfs_afterfork_child()
{
	vfs = mm_static_alloc(sizeof(struct vfs_data));
	InitializeSRWLock(&vfs->rw_lock);
	console_afterfork();

	int index[MAX_FD_COUNT];
	for (int i = 0; i < MAX_FD_COUNT; i++)
	{
		index[i] = i;
	}

	qsort(index, MAX_FD_COUNT, sizeof(int), cmpfiled);

	struct file *last = NULL;
	for (int i = 0; i < MAX_FD_COUNT; i++)
	{
		struct file *f = vfs->filed[index[i]].fd;
		if (f && f != last)
		{
			InitializeSRWLock(&f->rw_lock);
			if (f->op_vtable->after_fork)
				f->op_vtable->after_fork(f);
		}
		last = f;
	}
}

void vfs_afterfork_parent()
{
	for (int i = 0; i < MAX_FD_COUNT; i++)
		if (vfs->filed[i].fd)
			ReleaseSRWLockShared(&vfs->filed[i].fd->rw_lock);
	ReleaseSRWLockShared(&vfs->rw_lock);
}

static int store_file_internal(struct file *f, int cloexec)
{
	for (int i = 0; i < MAX_FD_COUNT; i++)
		if (vfs->filed[i].fd == NULL)
		{
			vfs->filed[i].fd = f;
			vfs->filed[i].cloexec = cloexec;
			return i;
		}
	return -L_EMFILE;
}

int vfs_store_file(struct file *f, int cloexec)
{
	AcquireSRWLockExclusive(&vfs->rw_lock);
	int r = store_file_internal(f, cloexec);
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(pipe2, int *, pipefd, int, flags)
{
	/*
	Supported flags:
	* O_CLOEXEC
	o O_DIRECT
	o O_NONBLOCK
	*/
	log_info("pipe2(%p, %d)", pipefd, flags);
	if ((flags & O_DIRECT) || (flags & O_NONBLOCK))
	{
		log_error("Unsupported flags combination: %x", flags);
		return -L_EINVAL;
	}
	if (!mm_check_write(pipefd, 2 * sizeof(int)))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *fread, *fwrite;
	int r = pipe_alloc(&fread, &fwrite, flags);
	if (r < 0)
		goto out;
	/* TODO: Deal with EMFILE error */
	int rfd = store_file_internal(fread, (flags & O_CLOEXEC) > 0);
	if (rfd < 0)
	{
		vfs_release(fread);
		vfs_release(fwrite);
		r = rfd;
		goto out;
	}
	int wfd = store_file_internal(fwrite, (flags & O_CLOEXEC) > 0);
	if (wfd < 0)
	{
		vfs_close(rfd);
		vfs_release(fwrite);
		r = wfd;
		goto out;
	}
	pipefd[0] = rfd;
	pipefd[1] = wfd;
	log_info("read fd: %d", rfd);
	log_info("write fd: %d", wfd);

out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(pipe, int *, pipefd)
{
	return sys_pipe2(pipefd, 0);
}

DEFINE_SYSCALL(eventfd2, unsigned int, count, int, flags)
{
	log_info("eventfd2(%u, %d)", count, flags);

	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file* eventfd;
	int r = eventfd_alloc(&eventfd, count, flags);
	if (r)
		goto out;

	r = store_file_internal(eventfd, (flags & O_CLOEXEC) > 0);
	if (r < 0)
		vfs_release(eventfd);

out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

static int vfs_dup(int fd, int newfd, int flags)
{
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f = vfs_get_internal(fd);
	if (!f)
	{
		newfd = -L_EBADF;
		goto out;
	}
	if (newfd == -1)
	{
		for (int i = 0; i < MAX_FD_COUNT; i++)
			if (vfs->filed[i].fd == NULL)
			{
				newfd = i;
				break;
			}
		if (newfd == -1)
		{
			newfd = -L_EMFILE;
			vfs_release(f);
			goto out;
		}
	}
	else
	{
		if (newfd == fd || newfd < 0 || newfd >= MAX_FD_COUNT)
		{
			newfd = -L_EINVAL;
			vfs_release(f);
			goto out;
		}
		if (vfs->filed[newfd].fd)
			vfs_close(newfd);
	}
	vfs->filed[newfd].fd = f;
	vfs->filed[newfd].cloexec = !!(flags & O_CLOEXEC);

out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return newfd;
}

DEFINE_SYSCALL(dup, int, fd)
{
	log_info("dup(%d)", fd);
	return vfs_dup(fd, -1, 0);
}

DEFINE_SYSCALL(dup2, int, fd, int, newfd)
{
	log_info("dup2(%d, %d)", fd, newfd);
	return vfs_dup(fd, newfd, 0);
}

DEFINE_SYSCALL(dup3, int, fd, int, newfd, int, flags)
{
	log_info("dup3(%d, %d, 0x%x)", fd, newfd, flags);
	return vfs_dup(fd, newfd, flags);
}

DEFINE_SYSCALL(read, int, fd, char *, buf, size_t, count)
{
	log_info("read(%d, %p, %p)", fd, buf, count);
	if (!mm_check_write(buf, count))
		return -L_EFAULT;
	struct file *f = vfs_get(fd);
	ssize_t r;
	if (f && f->op_vtable->read)
		r = f->op_vtable->read(f, buf, count);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(write, int, fd, const char *, buf, size_t, count)
{
	log_info("write(%d, %p, %p)", fd, buf, count);
	if (!mm_check_read(buf, count))
		return -L_EFAULT;
	struct file *f = vfs_get(fd);
	ssize_t r;
	if (f && f->op_vtable->write)
		r = f->op_vtable->write(f, buf, count);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(pread64, int, fd, char *, buf, size_t, count, loff_t, offset)
{
	log_info("pread64(%d, %p, %p, %lld)", fd, buf, count, offset);
	if (!mm_check_write(buf, count))
		return -L_EFAULT;
	struct file *f = vfs_get(fd);
	ssize_t r;
	if (f && f->op_vtable->pread)
		r = f->op_vtable->pread(f, buf, count, offset);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(pwrite64, int, fd, const char *, buf, size_t, count, loff_t, offset)
{
	log_info("pwrite64(%d, %p, %p, %lld)", fd, buf, count, offset);
	if (!mm_check_read(buf, count))
		return -L_EFAULT;
	struct file *f = vfs_get(fd);
	ssize_t r;
	if (f && f->op_vtable->pwrite)
		r = f->op_vtable->pwrite(f, buf, count, offset);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(readv, int, fd, const struct iovec *, iov, int, iovcnt)
{
	log_info("readv(%d, 0x%p, %d)", fd, iov, iovcnt);
	for (int i = 0; i < iovcnt; i++)
		if (!mm_check_write(iov[i].iov_base, iov[i].iov_len))
			return -L_EFAULT;
	struct file *f = vfs_get(fd);
	ssize_t r;
	if (f && f->op_vtable->read)
	{
		r = 0;
		for (int i = 0; i < iovcnt; i++)
		{
			ssize_t cur = f->op_vtable->read(f, iov[i].iov_base, iov[i].iov_len);
			if (cur < 0)
			{
				r = cur;
				break;
			}
			r += cur;
			if (cur < iov[i].iov_len)
				break;
		}
	}
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(writev, int, fd, const struct iovec *, iov, int, iovcnt)
{
	log_info("writev(%d, 0x%p, %d)", fd, iov, iovcnt);
	for (int i = 0; i < iovcnt; i++)
		if (!mm_check_read(iov[i].iov_base, iov[i].iov_len))
			return -L_EFAULT;
	struct file *f = vfs_get(fd);
	ssize_t r;
	if (f && f->op_vtable->write)
	{
		r = 0;
		for (int i = 0; i < iovcnt; i++)
		{
			ssize_t cur = f->op_vtable->write(f, iov[i].iov_base, iov[i].iov_len);
			if (cur < 0)
			{
				r = cur;
				break;
			}
			r += cur;
			if (cur < iov[i].iov_len)
				break;
		}
	}
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(preadv, int, fd, const struct iovec *, iov, int, iovcnt, off_t, offset)
{
	log_info("preadv(%d, 0x%p, %d, 0x%x)", fd, iov, iovcnt, offset);
	for (int i = 0; i < iovcnt; i++)
		if (!mm_check_write(iov[i].iov_base, iov[i].iov_len))
			return -L_EFAULT;
	struct file *f = vfs_get(fd);
	ssize_t r;
	if (f && f->op_vtable->pread)
	{
		r = 0;
		for (int i = 0; i < iovcnt; i++)
		{
			ssize_t cur = f->op_vtable->pread(f, iov[i].iov_base, iov[i].iov_len, offset);
			if (r < 0)
			{
				r = cur;
				break;
			}
			r += cur;
			offset += cur;
			if (cur < iov[i].iov_len)
				break;
		}
	}
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(pwritev, int, fd, const struct iovec *, iov, int, iovcnt, off_t, offset)
{
	log_info("pwritev(%d, 0x%p, %d, 0x%x)", fd, iov, iovcnt, offset);
	for (int i = 0; i < iovcnt; i++)
		if (!mm_check_read(iov[i].iov_base, iov[i].iov_len))
			return -L_EFAULT;
	struct file *f = vfs_get(fd);
	ssize_t r;
	if (f && f->op_vtable->pwrite)
	{
		r = 0;
		for (int i = 0; i < iovcnt; i++)
		{
			ssize_t cur = f->op_vtable->pwrite(f, iov[i].iov_base, iov[i].iov_len, offset);
			if (cur < 0)
			{
				r = cur;
				break;
			}
			r += cur;
			offset += cur;
			if (cur < iov[i].iov_len)
				break;
		}
	}
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(truncate, const char *, path, off_t, length)
{
	log_info("truncate(\"%s\", %p)", path, length);
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(AT_FDCWD, path, O_WRONLY, 0, &f);
	if (r < 0)
		goto out;
	if (!f->op_vtable->truncate)
	{
		r = -L_EPERM;
		goto out;
	}
	r = f->op_vtable->truncate(f, length);
	vfs_release(f);

out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(ftruncate, int, fd, off_t, length)
{
	log_info("ftruncate(%d, %p)", fd, length);
	struct file *f = vfs_get(fd);
	int r;
	if (f && f->op_vtable->truncate)
		r = f->op_vtable->truncate(f, length);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(truncate64, const char *, path, loff_t, length)
{
	log_info("truncate64(\"%s\", %lld)", path, length);
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(AT_FDCWD, path, O_WRONLY, 0, &f);
	if (r < 0)
		goto out;
	if (!f->op_vtable->truncate)
	{
		r = -L_EPERM;
		goto out;
	}
	r = f->op_vtable->truncate(f, length);
	vfs_release(f);

out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(ftruncate64, int, fd, loff_t, length)
{
	log_info("ftruncate(%d, %lld)", fd, length);
	struct file *f = vfs_get(fd);
	int r;
	if (f && f->op_vtable->truncate)
		r = f->op_vtable->truncate(f, length);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(fsync, int, fd)
{
	log_info("fsync(%d)", fd);
	struct file *f = vfs_get(fd);
	int r;
	if (!f)
		r = -L_EBADF;
	else if (!f->op_vtable->fsync)
		r = -L_EINVAL;
	else
		r = f->op_vtable->fsync(f);
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(fdatasync, int, fd)
{
	log_info("fdatasync(%d)", fd);
	struct file *f = vfs_get(fd);
	int r;
	if (!f)
		r = -L_EBADF;
	else if (!f->op_vtable->fsync)
		r = -L_EINVAL;
	else
		r = f->op_vtable->fsync(f);
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(lseek, int, fd, off_t, offset, int, whence)
{
	log_info("lseek(%d, %d, %d)", fd, offset, whence);
	struct file *f = vfs_get(fd);
	intptr_t r;
	if (f && f->op_vtable->llseek)
	{
		loff_t n;
		r = f->op_vtable->llseek(f, offset, &n, whence);
		if (r < 0)
			/* Nope */;
		else if (n >= INT_MAX)
			r = -L_EOVERFLOW; /* TODO: Do we need to rollback? */
		else
			r = (off_t) n;
	}
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(llseek, int, fd, unsigned long, offset_high, unsigned long, offset_low, loff_t *, result, int, whence)
{
	loff_t offset = ((uint64_t) offset_high << 32ULL) + offset_low;
	log_info("llseek(%d, %lld, %p, %d)", fd, offset, result, whence);
	if (!mm_check_write(result, sizeof(loff_t)))
		return -L_EFAULT;
	struct file *f = vfs_get(fd);
	int r = 0;
	if (f && f->op_vtable->llseek)
		r = f->op_vtable->llseek(f, offset, result, whence);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

static int find_filesystem(const char *path, struct file_system **out_fs, const char **out_subpath)
{
	struct file_system *fs;
	for (fs = vfs->fs_first; fs; fs = fs->next)
	{
		const char *p = fs->mountpoint;
		const char *subpath = path;
		while (*p && *p == *subpath)
		{
			p++;
			subpath++;
		}
		if (*p == 0)
		{
			*out_fs = fs;
			*out_subpath = subpath;
			if (**out_subpath == '/')
				(*out_subpath)++;
			return 1;
		}
	}
	return 0;
}

/* Resolve a given path (except the last component), output the real path
 * dirpath must be an absolute path without a tailing slash
 * Returns the length of realpath, or errno
 */
static int resolve_path(const char *dirpath, const char *pathname, char *realpath, int *symlink_remain)
{
	char target[PATH_MAX];
	char *realpath_start = realpath;
	/* ENOENT when pathname is empty (according to Linux) */
	if (*pathname == 0)
		return -L_ENOENT;
	/* CAUTION: dirpath can be aliased with realpath */
	if (*pathname == '/')
	{
		/* Absolute */
		pathname++;
	}
	else
	{
		/* Relative: Copy dirpath */
		if (realpath == dirpath)
		{
			/* Whoa, not even need to copy anything */
			realpath += strlen(dirpath);
		}
		else
		{
			while (*dirpath)
				*realpath++ = *dirpath++;
		}
		if (realpath > realpath_start && realpath[-1] == '/')
			realpath--;
	}
	while (*pathname)
	{
		if (pathname[0] == '/')
			pathname++;
		else if (pathname[0] == '.' && pathname[1] == '/')
			pathname += 2;
		else if (pathname[0] == '.' && pathname[1] == '.' && pathname[2] == '/')
		{
			pathname += 3;
			/* Remove last component if exists */
			if (realpath > realpath_start)
				for (realpath--; *realpath != '/'; realpath--);
		}
		else
		{
			*realpath++ = '/';
			/* Append current component */
			while (*pathname && *pathname != '/')
				*realpath++ = *pathname++;
			if (*pathname == '/')
			{
				pathname++;
				/* Resolve component */
				for (;;)
				{
					struct file_system *fs;
					char *subpath;
					*realpath = 0;
					if (!find_filesystem(realpath_start, &fs, &subpath))
						return -L_ENOTDIR;
					if (!fs->open)
						return -L_ENOTDIR;
					int r = fs->open(fs, subpath, O_PATH | O_DIRECTORY, 0, NULL, target, PATH_MAX);
					if (r < 0)
						return r;
					else if (r == 0) /* It is a regular file, go forward */
						break;
					else if (r == 1)
					{
						/* It is a symlink */
						if ((*symlink_remain)-- == 0)
							return -L_ELOOP;
						/* We resolve the symlink target using a recursive call */
						/* Remove basename */
						for (realpath--; *realpath != '/'; realpath--);
						*realpath = 0;
						r = resolve_path(realpath_start, target, realpath_start, symlink_remain);
						if (r < 0)
							return r;
						realpath = realpath_start + r;
						if (realpath > realpath_start && realpath[-1] == '/')
							realpath--;
						/* The last component is not resolved by the recursive call, solve it now */
					}
				}
			}
			else
			{
				/* Done */
				/* Normalize last component if it is "." or ".." */
				if (realpath[-1] == '.' && realpath[-2] == '/')
				{
					realpath -= 2;
					break;
				}
				else if (realpath[-1] == '.' && realpath[-2] == '.' && realpath[-3] == '/')
				{
					/* Remove last component if exists */
					realpath -= 3;
					if (realpath - 1 > realpath_start)
						for (realpath--; *realpath != '/'; realpath--);
					break;
				}
				else
					break;
			}
		}
	}
	if (realpath == realpath_start)
		*realpath++ = '/'; /* Return "/" instead of empty string */
	*realpath = 0;
	return realpath - realpath_start;
}

/* resolve_path(), *at() version */
int resolve_pathat(int dirfd, const char *pathname, char *realpath, int *symlink_remain)
{
	char dirpath[PATH_MAX];
	if (pathname[0] != '/')
	{
		struct file *f = dirfd == AT_FDCWD? vfs->cwd: vfs_get_internal(dirfd);
		if (!f)
			return -L_EBADF;
		f->op_vtable->getpath(f, dirpath);
		if (dirfd != AT_FDCWD)
			vfs_release(f);
	}
	return resolve_path(dirpath, pathname, realpath, symlink_remain);
}

int vfs_openat(int dirfd, const char *pathname, int flags, int mode, struct file **f)
{
	/*
	Supported flags:
	* O_APPEND
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
	if ((flags & O_DIRECT)
		|| (flags & O_DSYNC)
		|| (flags & O_LARGEFILE) || (flags & O_NOATIME) || (flags & O_NOCTTY)
		|| (flags & O_NONBLOCK) || (flags & __O_SYNC) || (flags & __O_TMPFILE))
	{
		log_error("Unsupported flag combination found.");
		//return -L_EINVAL;
	}
	if (mode != 0)
	{
		log_error("mode != 0");
		//return -L_EINVAL;
	}
	char realpath[PATH_MAX], target[PATH_MAX];
	int symlink_remain = MAX_SYMLINK_LEVEL;
	int r = resolve_pathat(dirfd, pathname, realpath, &symlink_remain);
	for (;;)
	{
		if (r < 0)
			return r;
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(realpath, &fs, &subpath))
			return -L_ENOENT;
		int ret = fs->open(fs, subpath, flags, mode, f, target, PATH_MAX);
		if (ret <= 0)
			return ret;
		else if (ret == 1)
		{
			/* Note: O_NOFOLLOW is handled in fs.open() */
			/* It is a symlink, continue resolving */
			if (symlink_remain-- == 0)
				return -L_ELOOP;
			/* Remove basename */
			char *p = realpath + r;
			for (p--; *p != '/'; p--);
			*p = 0;
			r = resolve_path(realpath, target, realpath, &symlink_remain);
		}
		else
			return r;
	}
}

DEFINE_SYSCALL(openat, int, dirfd, const char *, pathname, int, flags, int, mode)
{
	log_info("openat(%d, \"%s\", %x, %x)", dirfd, pathname, flags, mode);
	if (!mm_check_read_string(pathname))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(dirfd, pathname, flags, mode, &f);
	if (r >= 0)
	{
		r = store_file_internal(f, (flags & O_CLOEXEC) > 0);
		if (r < 0)
			vfs_release(f);
		else
			log_info("openat() file descriptor id: %d", r);
	}
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(open, const char *, pathname, int, flags, int, mode)
{
	log_info("open(%p: \"%s\", %x, %x)", pathname, pathname, flags, mode);
	return sys_openat(AT_FDCWD, pathname, flags, mode);
}

DEFINE_SYSCALL(creat, const char *, pathname, int, mode)
{
	log_info("creat(\"%s\", %x)", pathname, mode);
	return sys_openat(AT_FDCWD, pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

DEFINE_SYSCALL(close, int, fd)
{
	log_info("close(%d)", fd);
	int r = 0;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	if (!vfs->filed[fd].fd)
		r = -L_EBADF;
	else
		vfs_close(fd);
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(mknodat, int, dirfd, const char *, pathname, int, mode, unsigned int, dev)
{
	log_info("mknodat(%d, \"%s\", %x, (%d:%d))", dirfd, pathname, mode, major(dev), minor(dev));
	if (!mm_check_read_string(pathname))
		return -L_EFAULT;
	/* TODO: Touch that file */
	return 0;
}

DEFINE_SYSCALL(mknod, const char *, pathname, int, mode, unsigned int, dev)
{
	log_info("mknod(\"%s\", %x, (%d:%d))", pathname, mode, major(dev), minor(dev));
	return sys_mknodat(AT_FDCWD, pathname, mode, dev);
}

DEFINE_SYSCALL(linkat, int, olddirfd, const char *, oldpath, int, newdirfd, const char *, newpath, int, flags)
{
	log_info("linkat(%d, \"%s\", %d, \"%x\", %x)", olddirfd, oldpath, newdirfd, newpath, flags);
	if (!mm_check_read_string(oldpath) || !mm_check_read_string(newpath))
		return -L_EFAULT;
	if (flags & AT_EMPTY_PATH)
	{
		log_error("AT_EMPTY_PATH not supported.");
		return -L_EINVAL;
	}
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int openflags = O_PATH;
	if (!(openflags & AT_SYMLINK_FOLLOW))
		openflags |= O_NOFOLLOW;
	int r = vfs_openat(olddirfd, oldpath, openflags, 0, &f);
	if (r < 0)
		goto out;
	if (!winfs_is_winfile(f))
	{
		r = -L_EPERM;
		goto out;
	}
	char realpath[PATH_MAX];
	int symlink_remain = MAX_SYMLINK_LEVEL;
	r = resolve_pathat(newdirfd, newpath, realpath, &symlink_remain);
	if (r < 0)
		goto out;
	struct file_system *fs;
	char *subpath;
	if (!find_filesystem(realpath, &fs, &subpath))
		r = -L_ENOENT;
	else if (!fs->link)
		r = -L_EXDEV;
	else
		r = fs->link(fs, f, subpath);
	vfs_release(f);
out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(link, const char *, oldpath, const char *, newpath)
{
	log_info("link(\"%s\", \"%s\")", oldpath, newpath);
	return sys_linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

DEFINE_SYSCALL(unlinkat, int, dirfd, const char *, pathname, int, flags)
{
	log_info("unlinkat(%d, \"%s\", %x)", dirfd, pathname, flags);
	if (!mm_check_read_string(pathname))
		return -L_EFAULT;

	AcquireSRWLockExclusive(&vfs->rw_lock);
	char realpath[PATH_MAX];
	int symlink_remain = MAX_SYMLINK_LEVEL;
	int r = resolve_pathat(dirfd, pathname, realpath, &symlink_remain);
	if (r >= 0)
	{
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(realpath, &fs, &subpath))
			r = -L_ENOENT;
		else if (flags & AT_REMOVEDIR)
		{
			if (!fs->rmdir)
				r = -L_EPERM;
			else
				r = fs->rmdir(fs, subpath);
		}
		else
		{
			if (!fs->unlink)
				r = -L_EPERM;
			else
				r = fs->unlink(fs, subpath);
		}
	}
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(unlink, const char *, pathname)
{
	log_info("unlink(\"%s\")", pathname);
	return sys_unlinkat(AT_FDCWD, pathname, 0);
}

DEFINE_SYSCALL(symlinkat, const char *, target, int, newdirfd, const char *, linkpath)
{
	log_info("symlinkat(\"%s\", %d, \"%s\")", target, newdirfd, linkpath);
	if (!mm_check_read_string(target) || !mm_check_read_string(linkpath))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	char realpath[PATH_MAX];
	int symlink_remain = MAX_SYMLINK_LEVEL;
	int r = resolve_pathat(newdirfd, linkpath, realpath, &symlink_remain);
	if (r >= 0)
	{
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(realpath, &fs, &subpath))
			r = -L_ENOTDIR;
		else if (!fs->symlink)
			r = -L_EPERM;
		else
			r = fs->symlink(fs, target, subpath);
	}
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(symlink, const char *, target, const char *, linkpath)
{
	log_info("symlink(\"%s\", \"%s\")", target, linkpath);
	return sys_symlinkat(target, AT_FDCWD, linkpath);
}

DEFINE_SYSCALL(readlinkat, int, dirfd, const char *, pathname, char *, buf, int, bufsize)
{
	log_info("readlinkat(%d, \"%s\", %p, %d)", dirfd, pathname, buf, bufsize);
	if (!mm_check_read_string(pathname) || !mm_check_write(buf, bufsize))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(dirfd, pathname, O_PATH | O_NOFOLLOW, 0, &f);
	if (r >= 0)
	{
		if (!f->op_vtable->readlink)
			r = -L_EINVAL;
		else
			r = f->op_vtable->readlink(f, buf, bufsize);
		vfs_release(f);
	}
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(readlink, const char *, pathname, char *, buf, int, bufsize)
{
	log_info("readlink(\"%s\", %p, %d)", pathname, buf, bufsize);
	return sys_readlinkat(AT_FDCWD, pathname, buf, bufsize);
}

DEFINE_SYSCALL(renameat2, int, olddirfd, const char *, oldpath, int, newdirfd, const char *, newpath, unsigned int, flags)
{
	log_info("renameat2(%d, \"%s\", %d, \"%s\", %x)", olddirfd, oldpath, newdirfd, newpath, flags);
	if (flags)
	{
		log_error("flags not supported.");
		return -L_EINVAL;
	}
	if (!mm_check_read_string(oldpath) || !mm_check_read_string(newpath))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(olddirfd, oldpath, O_PATH | O_NOFOLLOW | __O_DELETE, 0, &f);
	if (r < 0)
		goto out;
	if (!winfs_is_winfile(f))
	{
		r = -L_EPERM;
		goto out;
	}
	char realpath[PATH_MAX];
	int symlink_remain = MAX_SYMLINK_LEVEL;
	r = resolve_pathat(newdirfd, newpath, realpath, &symlink_remain);
	if (r < 0)
		goto out;
	struct file_system *fs;
	char *subpath;
	if (!find_filesystem(realpath, &fs, &subpath))
		r = -L_EXDEV;
	else if (!fs->rename)
		r = -L_EXDEV;
	else
		r = fs->rename(fs, f, subpath);
	vfs_release(f);
out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(renameat, int, olddirfd, const char *, oldpath, int, newdirfd, const char *, newpath)
{
	log_info("renameat(%d, \"%s\", %d, \"%s\")", olddirfd, oldpath, newdirfd, newpath);
	return sys_renameat2(olddirfd, oldpath, newdirfd, newpath, 0);
}

DEFINE_SYSCALL(rename, const char *, oldpath, const char *, newpath)
{
	log_info("rename(\"%s\", \"%s\")", oldpath, newpath);
	return sys_renameat2(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

DEFINE_SYSCALL(mkdirat, int, dirfd, const char *, pathname, int, mode)
{
	log_info("mkdirat(%d, \"%s\", %d)", dirfd, pathname, mode);
	if (mode != 0)
		log_error("mode != 0");
	if (!mm_check_read_string(pathname))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	char realpath[PATH_MAX];
	int symlink_remain = MAX_SYMLINK_LEVEL;
	/* Very special case: mkdir with a tailing slash is equivalent to no tailing slash */
	int l = strlen(pathname);
	int r;
	if (pathname[l - 1] == '/')
	{
		char path[PATH_MAX];
		strcpy(path, pathname);
		path[l - 1] = 0;
		r = resolve_pathat(dirfd, path, realpath, &symlink_remain);
	}
	else
		r = resolve_pathat(dirfd, pathname, realpath, &symlink_remain);
	if (r >= 0)
	{
		struct file_system *fs;
		char *subpath;
		if (!find_filesystem(realpath, &fs, &subpath))
			r = -L_ENOTDIR;
		else if (!fs->mkdir)
			r = -L_EPERM;
		else
			r = fs->mkdir(fs, subpath, mode);
	}
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(mkdir, const char *, pathname, int, mode)
{
	log_info("mkdir(\"%s\", %x)", pathname, mode);
	return sys_mkdirat(AT_FDCWD, pathname, mode);
}

DEFINE_SYSCALL(rmdir, const char *, pathname)
{
	log_info("rmdir(\"%s\")", pathname);
	return sys_unlinkat(AT_FDCWD, pathname, AT_REMOVEDIR);
}

static intptr_t getdents_fill(void *buffer, uint64_t inode, const void *name, int namelen, char type, size_t size, int flags)
{
	/* For UTF-16, there is guaranteed to be enough room */
	if (flags & GETDENTS_UTF8)
	{
		/* For UTF-8, check whether we have enough room */
		int reclen = (sizeof(struct linux_dirent) + namelen + 1 + 8) & ~(uintptr_t)8;
		if (size < reclen)
			return GETDENTS_ERR_BUFFER_OVERFLOW;
	}
	struct linux_dirent *dirent = (struct linux_dirent *)buffer;
	dirent->d_ino = inode;
	if (dirent->d_ino != inode)
		return -L_EOVERFLOW;
	dirent->d_off = 0; /* TODO */
	intptr_t len;
	if (flags & GETDENTS_UTF16)
		len = utf16_to_utf8_filename(name, namelen, dirent->d_name, size);
	else
	{
		len = namelen;
		memcpy(dirent->d_name, name, namelen + 1);
	}
	/* Don't care much about the size, there is guaranteed to be enough room */
	dirent->d_name[len] = 0;
	dirent->d_name[len + 1] = type;
	log_info("Added %s, inode = %llx, type = %d", dirent->d_name, inode, type);
	dirent->d_reclen = (sizeof(struct linux_dirent) + len + 1 + 8) & ~(uintptr_t)8;
	return dirent->d_reclen;
}

static intptr_t getdents64_fill(void *buffer, uint64_t inode, const void *name, int namelen, char type, size_t size, int flags)
{
	if (flags & GETDENTS_UTF8)
	{
		/* For UTF-8, check whether we have enough room */
		int reclen = (sizeof(struct linux_dirent) + namelen + 1 + 8) & ~(uintptr_t)8;
		if (size < reclen)
			return GETDENTS_ERR_BUFFER_OVERFLOW;
	}
	struct linux_dirent64 *dirent = (struct linux_dirent64 *)buffer;
	dirent->d_ino = inode;
	dirent->d_off = 0; /* TODO */
	dirent->d_type = type;
	intptr_t len;
	if (flags & GETDENTS_UTF16)
		len = utf16_to_utf8_filename(name, namelen, dirent->d_name, size);
	else
	{
		len = namelen;
		memcpy(dirent->d_name, name, namelen + 1);
	}
	/* Don't care much about the size, there is guaranteed to be enough room */
	dirent->d_name[len] = 0;
	log_info("Added %s, inode = %llx, type = %d", dirent->d_name, inode, type);
	dirent->d_reclen = (sizeof(struct linux_dirent64) + len + 1 + 8) & ~(uintptr_t)8;
	return dirent->d_reclen;
}

DEFINE_SYSCALL(getdents, int, fd, struct linux_dirent *, dirent, unsigned int, count)
{
	log_info("getdents(%d, %p, %d)", fd, dirent, count);
	if (!mm_check_write(dirent, count))
		return -L_EFAULT;
	struct file *f = vfs_get(fd);
	int r;
	if (f && f->op_vtable->getdents)
		r = f->op_vtable->getdents(f, dirent, count, getdents_fill);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(getdents64, int, fd, struct linux_dirent64 *, dirent, unsigned int, count)
{
	log_info("getdents64(%d, %p, %d)", fd, dirent, count);
	if (!mm_check_write(dirent, count))
		return -L_EFAULT;
	struct file *f = vfs_get(fd);
	int r;
	if (f && f->op_vtable->getdents)
		r = f->op_vtable->getdents(f, dirent, count, getdents64_fill);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

static int stat_from_newstat(struct stat *stat, const struct newstat *newstat)
{
	INIT_STRUCT_STAT_PADDING(stat);
	stat->st_dev = newstat->st_dev;
	stat->st_ino = newstat->st_ino;
	if (stat->st_ino != newstat->st_ino)
		return -L_EOVERFLOW;
	stat->st_mode = newstat->st_mode;
	stat->st_nlink = newstat->st_nlink;
	if (stat->st_nlink != newstat->st_nlink)
		return -L_EOVERFLOW;
	stat->st_uid = newstat->st_uid;
	stat->st_gid = newstat->st_gid;
	stat->st_rdev = newstat->st_rdev;
	stat->st_size = newstat->st_size;
	stat->st_blksize = newstat->st_blksize;
	stat->st_blocks = newstat->st_blocks;
	stat->st_atime = newstat->st_atime;
	stat->st_atime_nsec = newstat->st_atime_nsec;
	stat->st_mtime = newstat->st_mtime;
	stat->st_mtime_nsec = newstat->st_mtime_nsec;
	stat->st_ctime = newstat->st_ctime;
	stat->st_ctime_nsec = newstat->st_ctime_nsec;
	return 0;
}

static int stat64_from_newstat(struct stat64 *stat, const struct newstat *newstat)
{
	INIT_STRUCT_STAT64_PADDING(stat);
	stat->st_dev = newstat->st_dev;
	stat->st_ino = newstat->st_ino;
	stat->st_mode = newstat->st_mode;
	stat->st_nlink = newstat->st_nlink;
	stat->st_uid = newstat->st_uid;
	stat->st_gid = newstat->st_gid;
	stat->st_rdev = newstat->st_rdev;
	stat->st_size = newstat->st_size;
	stat->st_blksize = newstat->st_blksize;
	stat->st_blocks = newstat->st_blocks;
	stat->st_atime = newstat->st_atime;
	stat->st_atime_nsec = newstat->st_atime_nsec;
	stat->st_mtime = newstat->st_mtime;
	stat->st_mtime_nsec = newstat->st_mtime_nsec;
	stat->st_ctime = newstat->st_ctime;
	stat->st_ctime_nsec = newstat->st_ctime_nsec;
	return 0;
}

static int vfs_statat(int dirfd, const char *pathname, struct newstat *stat, int flags)
{
	int r = 0;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	if (flags & AT_NO_AUTOMOUNT)
	{
		log_error("AT_NO_AUTOMOUNT not supported.");
		r = -L_EINVAL;
		goto out;
	}
	struct file *f;
	if (flags & AT_EMPTY_PATH)
	{
		f = vfs_get_internal(dirfd);
		if (!f)
		{
			r = -L_EBADF;
			goto out;
		}
	}
	else
	{
		int openflags = O_PATH;
		if (flags & AT_SYMLINK_NOFOLLOW)
			openflags |= O_NOFOLLOW;
		r = vfs_openat(dirfd, pathname, openflags, 0, &f);
		if (r < 0)
			goto out;
	}
	r = f->op_vtable->stat(f, stat);
	vfs_release(f);

out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(newstatat, int, dirfd, const char *, pathname, struct newstat *, buf, int, flags)
{
	log_info("newstatat(%d, \"%s\", %p, %x)", dirfd, pathname, buf, flags);
	if ((!(flags & AT_EMPTY_PATH) && !mm_check_read_string(pathname)) || !mm_check_write(buf, sizeof(struct newstat)))
		return -L_EFAULT;
	return vfs_statat(dirfd, pathname, buf, flags);
}

DEFINE_SYSCALL(newfstat, int, fd, struct newstat *, buf)
{
	log_info("newfstat(%d, %p)", fd, buf);
	if (!mm_check_write(buf, sizeof(struct newstat)))
		return -L_EFAULT;
	return vfs_statat(fd, NULL, buf, AT_EMPTY_PATH);
}

DEFINE_SYSCALL(newstat, const char *, pathname, struct newstat *, buf)
{
	log_info("newstat(\"%s\", %p)", pathname, buf);
	if (!mm_check_read_string(pathname) || !mm_check_write(buf, sizeof(struct newstat)))
		return -L_EFAULT;
	return vfs_statat(AT_FDCWD, pathname, buf, 0);
}

DEFINE_SYSCALL(newlstat, const char *, pathname, struct newstat *, buf)
{
	log_info("newlstat(\"%s\", %p)", pathname, buf);
	if (!mm_check_read_string(pathname) || !mm_check_write(buf, sizeof(struct newstat)))
		return -L_EFAULT;
	return vfs_statat(AT_FDCWD, pathname, buf, AT_SYMLINK_NOFOLLOW);
}

DEFINE_SYSCALL(fstatat64, int, dirfd, const char *, pathname, struct stat64 *, buf, int, flags)
{
	log_info("fstatat64(%d, \"%s\", %p, %x)", dirfd, pathname, buf, flags);
	if ((!(flags & AT_EMPTY_PATH) && !mm_check_read_string(pathname)) || !mm_check_write(buf, sizeof(struct stat64)))
		return -L_EFAULT;
	struct newstat stat;
	int r = vfs_statat(dirfd, pathname, &stat, flags);
	if (r)
		return r;
	return stat64_from_newstat(buf, &stat);
}

DEFINE_SYSCALL(fstat64, int, fd, struct stat64 *, buf)
{
	log_info("fstat64(%d, %p)", fd, buf);
	if (!mm_check_write(buf, sizeof(struct stat64)))
		return -L_EFAULT;
	struct newstat stat;
	int r = vfs_statat(fd, NULL, &stat, AT_EMPTY_PATH);
	if (r)
		return r;
	return stat64_from_newstat(buf, &stat);
}

DEFINE_SYSCALL(stat64, const char *, pathname, struct stat64 *, buf)
{
	log_info("stat64(\"%s\", %p)", pathname, buf);
	if (!mm_check_write(buf, sizeof(struct stat64)))
		return -L_EFAULT;
	struct newstat stat;
	int r = vfs_statat(AT_FDCWD, pathname, &stat, 0);
	if (r)
		return r;
	return stat64_from_newstat(buf, &stat);
}

DEFINE_SYSCALL(lstat64, const char *, pathname, struct stat64 *, buf)
{
	log_info("lstat64(\"%s\", %p)", pathname, buf);
	if (!mm_check_write(buf, sizeof(struct stat64)))
		return -L_EFAULT;
	struct newstat stat;
	int r = vfs_statat(AT_FDCWD, pathname, &stat, AT_SYMLINK_NOFOLLOW);
	if (r)
		return r;
	return stat64_from_newstat(buf, &stat);
}

DEFINE_SYSCALL(fstat, int, fd, struct stat *, buf)
{
	log_info("fstat(%d, %p)", fd, buf);
	if (!mm_check_write(buf, sizeof(struct stat)))
		return -L_EFAULT;
	struct newstat stat;
	int r = vfs_statat(fd, NULL, &stat, AT_EMPTY_PATH);
	if (r)
		return r;
	return stat_from_newstat(buf, &stat);
}

DEFINE_SYSCALL(stat, const char *, pathname, struct stat *, buf)
{
	log_info("stat(\"%s\", %p)", pathname, buf);
	if (!mm_check_write(buf, sizeof(struct stat)))
		return -L_EFAULT;
	struct newstat stat;
	int r = vfs_statat(AT_FDCWD, pathname, &stat, 0);
	if (r)
		return r;
	return stat_from_newstat(buf, &stat);
}

DEFINE_SYSCALL(lstat, const char *, pathname, struct stat *, buf)
{
	log_info("lstat(\"%d\", %p)", pathname, buf);
	if (!mm_check_write(buf, sizeof(struct stat)))
		return -L_EFAULT;
	struct newstat stat;
	int r = vfs_statat(AT_FDCWD, pathname, &stat, AT_SYMLINK_NOFOLLOW);
	if (r)
		return r;
	return stat_from_newstat(buf, &stat);
}

static int statfs_from_statfs64(struct statfs *statfs, struct statfs64 *statfs64)
{
	statfs->f_type = statfs64->f_type;
	statfs->f_bsize = statfs64->f_bsize;
	statfs->f_blocks = statfs64->f_blocks;
	if (statfs->f_blocks != statfs64->f_blocks)
		return -L_EOVERFLOW;
	statfs->f_bfree = statfs64->f_bfree;
	if (statfs->f_bfree != statfs64->f_bfree)
		return -L_EOVERFLOW;
	statfs->f_bavail = statfs64->f_bavail;
	if (statfs->f_bavail != statfs64->f_bavail)
		return -L_EOVERFLOW;
	statfs->f_files = statfs64->f_files;
	if (statfs->f_files != statfs64->f_files)
		return -L_EOVERFLOW;
	statfs->f_ffree = statfs64->f_ffree;
	if (statfs->f_ffree != statfs64->f_ffree)
		return -L_EOVERFLOW;
	statfs->f_fsid = statfs64->f_fsid;
	statfs->f_namelen = statfs64->f_namelen;
	statfs->f_frsize = statfs64->f_frsize;
	statfs->f_flags = statfs64->f_flags;
	statfs->f_spare[0] = 0;
	statfs->f_spare[1] = 0;
	statfs->f_spare[2] = 0;
	statfs->f_spare[3] = 0;
	return 0;
}

static int vfs_fstatfs(int fd, struct statfs64 *buf)
{
	struct file *f = vfs_get(fd);
	int r;
	if (f && f->op_vtable->statfs)
		r = f->op_vtable->statfs(f, buf);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

static int vfs_statfs(const char *pathname, struct statfs64 *buf)
{
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(AT_FDCWD, pathname, O_PATH, 0, &f);
	if (r == 0)
	{
		if (f->op_vtable->statfs)
			r = f->op_vtable->statfs(f, buf);
		else
			r = -L_EBADF;
		vfs_release(f);
	}
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(fstatfs, int, fd, struct statfs *, buf)
{
	log_info("fstatfs(%d, %p)", fd, buf);
	if (!mm_check_write(buf, sizeof(struct statfs)))
		return -L_EFAULT;
	struct statfs64 statfs64;
	int r = vfs_fstatfs(fd, &statfs64);
	if (r)
		return r;
	return statfs_from_statfs64(buf, &statfs64);
}

DEFINE_SYSCALL(statfs, const char *, pathname, struct statfs *, buf)
{
	log_info("statfs(\"%s\", %p)", pathname, buf);
	if (!mm_check_write(buf, sizeof(struct statfs)))
		return -L_EFAULT;
	struct statfs64 statfs64;
	int r = vfs_statfs(pathname, &statfs64);
	if (r)
		return r;
	return statfs_from_statfs64(buf, &statfs64);
}

DEFINE_SYSCALL(fstatfs64, int, fd, size_t, sz, struct statfs64 *, buf)
{
	log_info("fstatfs64(%d, %d, %p)", fd, sz, buf);
	if (sz != sizeof(struct statfs64))
		return -L_EINVAL;
	if (!mm_check_write(buf, sizeof(struct statfs64)))
		return -L_EFAULT;
	return vfs_fstatfs(fd, buf);
}

DEFINE_SYSCALL(statfs64, const char *, pathname, size_t, sz, struct statfs64 *, buf)
{
	log_info("statfs64(\"%s\", %d, %p)", pathname, sz, buf);
	if (sz != sizeof(struct statfs64))
		return -L_EINVAL;
	if (!mm_check_write(buf, sizeof(struct statfs64)))
		return -L_EFAULT;
	return vfs_statfs(pathname, buf);
}

DEFINE_SYSCALL(fadvise64_64, int, fd, loff_t, offset, loff_t, len, int, advice)
{
	log_info("fadvise64_64(%d, %lld, %lld, %d)", fd, offset, len, advice);
	/* It seems windows does not support any of the fadvise semantics
	 * We simply check the validity of parameters and return
	 */
	int r;
	struct file *f = vfs_get(fd);
	if (!f)
		r = -L_EBADF;
	else
	{
		switch (advice)
		{
		case POSIX_FADV_NORMAL:
		case POSIX_FADV_RANDOM:
		case POSIX_FADV_SEQUENTIAL:
		case POSIX_FADV_WILLNEED:
		case POSIX_FADV_DONTNEED:
		case POSIX_FADV_NOREUSE:
			r = 0;
			break;

		default:
			r = -L_EINVAL;
		}
		vfs_release(f);
	}
	return r;
}

DEFINE_SYSCALL(fadvise64, int, fd, loff_t, offset, size_t, len, int, advice)
{
	return sys_fadvise64_64(fd, offset, len, advice);
}

DEFINE_SYSCALL(ioctl, int, fd, unsigned int, cmd, unsigned long, arg)
{
	log_info("ioctl(%d, %x, %x)", fd, cmd, arg);
	if (cmd == L_FIOCLEX)
		return sys_fcntl(fd, F_SETFD, FD_CLOEXEC);
	else if (cmd == L_FIONCLEX)
		return sys_fcntl(fd, F_SETFD, 0);
	struct file *f = vfs_get(fd);
	int r;
	if (f && f->op_vtable->ioctl)
		r = f->op_vtable->ioctl(f, cmd, arg);
	else
		r = -L_EBADF;
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(utime, const char *, filename, const struct utimbuf *, times)
{
	log_info("utime(\"%s\", %p)", filename, times);
	if (!mm_check_read_string(filename) || (times && !mm_check_read(times, sizeof(struct utimbuf))))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(AT_FDCWD, filename, O_WRONLY, 0, &f);
	if (r < 0)
		goto out;
	if (!times)
		r = f->op_vtable->utimens(f, NULL);
	else
	{
		struct timespec t[2];
		t[0].tv_sec = times->actime;
		t[0].tv_nsec = 0;
		t[1].tv_sec = times->modtime;
		t[1].tv_nsec = 0;
		r = f->op_vtable->utimens(f, t);
	}
	vfs_release(f);

out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(utimes, const char *, filename, const struct timeval *, times)
{
	log_info("utimes(\"%s\", %p)", filename, times);
	if (!mm_check_read_string(filename) || (times && !mm_check_read(times, 2 * sizeof(struct timeval))))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(AT_FDCWD, filename, O_WRONLY, 0, &f);
	if (r < 0)
		goto out;
	if (!times)
		r = f->op_vtable->utimens(f, NULL);
	else
	{
		struct timespec t[2];
		unix_timeval_to_unix_timespec(&times[0], &t[0]);
		unix_timeval_to_unix_timespec(&times[1], &t[1]);
		r = f->op_vtable->utimens(f, t);
	}
	vfs_release(f);
out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(utimensat, int, dirfd, const char *, pathname, const struct timespec *, times, int, flags)
{
	log_info("utimensat(%d, \"%s\", %p, 0x%x)", dirfd, pathname, times, flags);
	if ((pathname && !mm_check_read_string(pathname)) || (times && !mm_check_read(times, 2 * sizeof(struct timespec))))
		return -L_EFAULT;
	if (!pathname)
	{
		/* Special case: use dirfd as file fd */
		struct file *f = vfs_get(dirfd);
		int r;
		if (f && f->op_vtable->utimens)
			r = f->op_vtable->utimens(f, times);
		else
			r = -L_EBADF;
		if (f)
			vfs_release(f);
		return r;
	}
	AcquireSRWLockExclusive(&vfs->rw_lock);
	int openflags = O_WRONLY | O_PATH;
	if (flags & AT_SYMLINK_NOFOLLOW)
		openflags |= O_NOFOLLOW;
	struct file *f;
	int r = vfs_openat(dirfd, pathname, openflags, 0, &f);
	if (r < 0)
		goto out;
	r = f->op_vtable->utimens(f, times);
	vfs_release(f);
out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(chdir, const char *, pathname)
{
	log_info("chdir(%s)", pathname);
	if (!mm_check_read_string(pathname))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f;
	int r = vfs_openat(AT_FDCWD, pathname, O_PATH | O_DIRECTORY, 0, &f);
	if (r < 0)
		goto out;
	vfs_release(vfs->cwd);
	vfs->cwd = f;
out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(fchdir, int, fd)
{
	log_info("fchdir(%d)", fd);
	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *f = vfs_get_internal(fd);
	int r = 0;
	if (!f)
	{
		r = -L_EBADF;
		goto out;
	}
	vfs_release(vfs->cwd);
	vfs->cwd = f;
out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(getcwd, char *, buf, size_t, size)
{
	log_info("getcwd(%p, %p)", buf, size);
	if (!mm_check_write(buf, size))
		return -L_EFAULT;
	AcquireSRWLockShared(&vfs->rw_lock);
	char cwd[PATH_MAX];
	intptr_t r = vfs->cwd->op_vtable->getpath(vfs->cwd, cwd);
	if (size < r + 1)
		r = -L_ERANGE;
	else
	{
		log_info("cwd: \"%s\"", cwd);
		memcpy(buf, cwd, r + 1);
		r = (intptr_t)buf;
	}
	ReleaseSRWLockShared(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(fcntl, int, fd, int, cmd, int, arg)
{
	log_info("fcntl(%d, %d)", fd, cmd);
	if (cmd == F_DUPFD)
		return sys_dup(fd);
	struct file *f = vfs_get(fd);
	int r = 0;
	if (!f)
		r = -L_EBADF;
	else
	{
		/* TODO: Whether we need locking on reading/writing cloexec flag? */
		switch (cmd)
		{
		case F_GETFD:
		{
			int cloexec = vfs->filed[fd].cloexec;
			log_info("F_GETFD: CLOEXEC: %d", cloexec);
			r = cloexec? FD_CLOEXEC: 0;
			break;
		}
		case F_SETFD:
		{
			int cloexec = (arg & FD_CLOEXEC)? 1: 0;
			log_info("F_SETFD: CLOEXEC: %d", cloexec);
			vfs->filed[fd].cloexec = cloexec;
			break;
		}
		case F_GETFL:
		{
			log_info("F_GETFL: %x", f->flags);
			r = f->flags;
			break;
		}
		case F_SETFL:
		{
			log_info("F_SETFL: 0%o", arg);
			if ((arg & O_APPEND) || (arg & FASYNC) || (arg & O_DIRECT) || (arg & O_NOATIME))
				log_error("flags contain unsupported bits.");
			else
				f->flags = (f->flags & ~O_NONBLOCK) | (arg & O_NONBLOCK);
			break;
		}
		default:
			log_error("Unsupported command: %d", cmd);
			r = -L_EINVAL;
			break;
		}
		vfs_release(f);
	}
	return r;
}

DEFINE_SYSCALL(fcntl64, int, fd, int, cmd, int, arg)
{
	return sys_fcntl(fd, cmd, arg);
}

DEFINE_SYSCALL(faccessat, int, dirfd, const char *, pathname, int, mode, int, flags)
{
	log_info("faccessat(%d, \"%s\", %d, %x)", dirfd, pathname, mode, flags);
	if (!mm_check_read_string(pathname))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	int openflags = O_PATH;
	if (flags & AT_SYMLINK_NOFOLLOW)
		openflags |= O_NOFOLLOW;
	/* Currently emulate access behaviour by testing whether the file exists */
	struct file *f;
	int r = vfs_openat(dirfd, pathname, openflags, mode, &f);
	if (r < 0)
		goto out;
	vfs_release(f);
out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(access, const char *, pathname, int, mode)
{
	log_info("access(\"%s\", %d)", pathname, mode);
	return sys_faccessat(AT_FDCWD, pathname, mode, 0);
}

DEFINE_SYSCALL(fchmodat, int, dirfd, const char *, pathname, int, mode, int, flags)
{
	log_info("fchmodat(%d, \"%s\", %d, %x)", dirfd, pathname, mode, flags);
	if (!mm_check_read_string(pathname))
		return -L_EFAULT;
	if (flags)
		log_error("flags not supported.");
	log_error("fchmodat() not implemented.");
	return 0;
}

DEFINE_SYSCALL(fchmod, int, fd, int, mode)
{
	log_info("fchmod(%d, %d)", fd, mode);
	log_error("fchmod() not implemented.");
	return 0;
}

DEFINE_SYSCALL(chmod, const char *, pathname, int, mode)
{
	log_info("chmod(\"%s\", %d)", pathname, mode);
	return sys_fchmodat(AT_FDCWD, pathname, mode, 0);
}

DEFINE_SYSCALL(umask, int, mask)
{
	int old = vfs->umask;
	vfs->umask = mask;
	return old;
}

DEFINE_SYSCALL(chroot, const char *, pathname)
{
	log_info("chroot(\"%s\")", pathname);
	if (!mm_check_read_string(pathname))
		return -L_EFAULT;
	AcquireSRWLockExclusive(&vfs->rw_lock);
	char realpath[PATH_MAX];
	int symlink_remain = MAX_SYMLINK_LEVEL;
	int r = resolve_pathat(AT_FDCWD, pathname, realpath, &symlink_remain);
	if (r < 0)
		goto out;
	log_info("resolved path: \"%s\"", realpath);
	WCHAR wpath[PATH_MAX];
	utf8_to_utf16_filename(realpath, r + 1, wpath, PATH_MAX);
	/* TODO */
	if (!SetCurrentDirectoryW(wpath + 1)) /* ignore the heading slash */
		log_error("SetCurrentDirectoryW() failed, error code: %d", GetLastError());
out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(fchownat, int, dirfd, const char *, pathname, uid_t, owner, gid_t, group, int, flags)
{
	log_info("fchownat(%d, \"%s\", %d, %d, %x)", dirfd, pathname, owner, group, flags);
	if (pathname && !mm_check_read_string(pathname))
		return -L_EFAULT;
	log_error("fchownat() not implemented.");
	return 0;
}

DEFINE_SYSCALL(fchown, int, fd, uid_t, owner, gid_t, group)
{
	log_info("fchown(%d, %d, %d)", fd, owner, group);
	return sys_fchownat(AT_FDCWD, NULL, owner, group, AT_EMPTY_PATH);
}

DEFINE_SYSCALL(chown, const char *, pathname, uid_t, owner, gid_t, group)
{
	log_info("chown(\"%s\", %d, %d)", pathname, owner, group);
	return sys_fchownat(AT_FDCWD, pathname, owner, group, 0);
}

DEFINE_SYSCALL(lchown, const char *, pathname, uid_t, owner, gid_t, group)
{
	log_info("lchown(\"%s\", %d, %d)", pathname, owner, group);
	return sys_fchownat(AT_FDCWD, pathname, owner, group, AT_SYMLINK_NOFOLLOW);
}

static int vfs_ppoll(struct linux_pollfd *fds, int nfds, int timeout, const sigset_t *sigmask)
{
	/* Count of handles to be waited on */
	int cnt = 0;
	/* File structures */
	struct file **files = (struct file **)alloca(nfds * sizeof(struct file *));
	/* Handles to be waited on */
	HANDLE *handles = (HANDLE *)alloca(nfds * sizeof(HANDLE));
	/* Indices of handles in the original fds[] array */
	int *indices = (int *)alloca(nfds * sizeof(int));

	if (timeout < 0)
		timeout = INFINITE;
	for (int i = 0; i < nfds; i++)
		fds[i].revents = 0;
	int num_result = 0;
	int done = 0;
	for (int i = 0; i < nfds; i++)
	{
		if (fds[i].fd < 0)
		{
			files[i] = NULL;
			continue;
		}
		struct file *f = files[i] = vfs_get(fds[i].fd);
		/* TODO: Support for regular files */
		if (!f)
		{
			fds[i].revents = LINUX_POLLNVAL;
			num_result++;
			continue;
		}
		if (!f->op_vtable->get_poll_handle && !f->op_vtable->get_poll_status)
		{
			log_error("polling not implemented for file %d", fds[i].fd);
			continue;
		}
		if (f->op_vtable->get_poll_status)
		{
			int e = f->op_vtable->get_poll_status(f);
			if ((fds[i].events & e) > 0)
			{
				/* It is ready at this moment */
				fds[i].revents = fds[i].events & e;
				num_result++;
				done = 1;
				continue;
			}
		}
		if (f->op_vtable->get_poll_handle)
		{
			int e;
			HANDLE handle = f->op_vtable->get_poll_handle(f, &e);
			if ((fds[i].events & e) > 0)
			{
				handles[cnt] = handle;
				indices[cnt] = i;
				cnt++;
			}
		}
	}
	if (cnt && !done)
	{
		sigset_t oldmask;
		if (sigmask)
			signal_before_pwait(sigmask, &oldmask);
		LARGE_INTEGER frequency, start;
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&start);
		int remain = timeout;
		for (;;)
		{
			DWORD result = signal_wait(cnt, handles, remain);
			if (result == WAIT_TIMEOUT)
			{
				num_result = 0;
				goto out;
			}
			else if (result == WAIT_INTERRUPTED)
			{
				num_result = -L_EINTR;
				goto out;
			}
			else if (result < WAIT_OBJECT_0 || result >= WAIT_OBJECT_0 + cnt)
			{
				num_result = -L_ENOMEM; /* TODO: Find correct errno */
				goto out;
			}
			else
			{
				/* Wait successfully, fill in the revents field of that handle */
				int id = indices[result - WAIT_OBJECT_0];
				struct file *f = files[id];
				/*
				 * Some file descriptors (console, socket) may be not readable even if it is signaled
				 * Query the current state again to make sure
				 */
				int e;
				if (f->op_vtable->get_poll_status)
				{
					/* The file descriptor provides get_poll_status() function, use this to query precise event flags */
					e = f->op_vtable->get_poll_status(f);
				}
				else
				{
					/* Otherwise, the event flags associated with the poll object is used */
					f->op_vtable->get_poll_handle(f, &e);
				}
				if ((e & fds[id].events) == 0)
				{
					LARGE_INTEGER current;
					QueryPerformanceCounter(&current);
					if (timeout != INFINITE)
					{
						remain = timeout - (current.QuadPart - start.QuadPart) / (frequency.QuadPart * 1000LL);
						if (remain < 0)
							break;
					}
					continue;
				}
				fds[id].revents = fds[id].events & e;
				num_result++;
				break;
			}
		}
		if (sigmask)
			signal_after_pwait(&oldmask);
	}
out:
	for (int i = 0; i < nfds; i++)
		if (files[i])
			vfs_release(files[i]);
	return num_result;
}

static int vfs_pselect6(int nfds, struct fdset *readfds, struct fdset *writefds, struct fdset *exceptfds,
	int timeout, const sigset_t *sigmask)
{
	int cnt = 0;
	struct linux_pollfd *fds = (struct linux_pollfd *)alloca(sizeof(struct linux_pollfd) * nfds);
	for (int i = 0; i < nfds; i++)
	{
		int events = 0;
		if (readfds && LINUX_FD_ISSET(i, readfds))
			events |= LINUX_POLLIN;
		if (writefds && LINUX_FD_ISSET(i, writefds))
			events |= LINUX_POLLOUT;
		if (exceptfds && LINUX_FD_ISSET(i, exceptfds))
			events |= LINUX_POLLERR;
		if (events)
		{
			fds[cnt].fd = i;
			fds[cnt].events = events;
			cnt++;
		}
	}
	int r = vfs_ppoll(fds, cnt, timeout, sigmask);
	if (r <= 0)
		return r;
	if (readfds)
		LINUX_FD_ZERO(nfds, readfds);
	if (writefds)
		LINUX_FD_ZERO(nfds, writefds);
	if (exceptfds)
		LINUX_FD_ZERO(nfds, exceptfds);
	for (int i = 0; i < cnt; i++)
	{
		if (readfds && (fds[i].revents & LINUX_POLLIN))
			LINUX_FD_SET(fds[i].fd, readfds);
		if (writefds && (fds[i].revents & LINUX_POLLOUT))
			LINUX_FD_SET(fds[i].fd, writefds);
		if (exceptfds && (fds[i].revents & LINUX_POLLERR))
			LINUX_FD_SET(fds[i].fd, exceptfds);
	}
	return r;
}

DEFINE_SYSCALL(poll, struct linux_pollfd *, fds, int, nfds, int, timeout)
{
	log_info("poll(0x%p, %d, %d)", fds, nfds, timeout);
	if (!mm_check_write(fds, nfds * sizeof(struct linux_pollfd)))
		return -L_EFAULT;
	return vfs_ppoll(fds, nfds, timeout, NULL);
}

DEFINE_SYSCALL(ppoll, struct linux_pollfd *, fds, int, nfds, const struct timespec *, timeout_ts, const sigset_t *, sigmask, size_t, sigsetsize)
{
	log_info("ppoll(%p, %d, %p, %p)", fds, nfds, timeout_ts, sigmask);
	if (sigsetsize != sizeof(sigset_t))
		return -L_EINVAL;
	if (timeout_ts && !mm_check_read(timeout_ts, sizeof(struct timespec)))
		return -L_EFAULT;
	if (sigmask && !mm_check_read(sigmask, sizeof(sigset_t)))
		return -L_EFAULT;
	int timeout = timeout_ts == NULL ? -1 : (timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000);
	return vfs_ppoll(fds, nfds, timeout, sigmask);
}

DEFINE_SYSCALL(select, int, nfds, struct fdset *, readfds, struct fdset *, writefds, struct fdset *, exceptfds, struct timeval *, timeout)
{
	log_info("select(%d, 0x%p, 0x%p, 0x%p, 0x%p)", nfds, readfds, writefds, exceptfds, timeout);
	if ((readfds && !mm_check_write(readfds, sizeof(struct fdset)))
		|| (writefds && !mm_check_write(writefds, sizeof(struct fdset)))
		|| (exceptfds && !mm_check_write(exceptfds, sizeof(struct fdset)))
		|| (timeout && !mm_check_read(timeout, sizeof(struct timeval))))
		return -L_EFAULT;
	int time;
	if (timeout)
		time = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
	else
		time = -1;
	return vfs_pselect6(nfds, readfds, writefds, exceptfds, time, NULL);
}

DEFINE_SYSCALL(pselect6, int, nfds, struct fdset *, readfds, struct fdset *, writefds, struct fdset *, exceptfds,
	const struct timespec *, timeout_ts, void *, sigmask_data)
{
	struct sigmask_data
	{
		const sigset_t *sigmask;
		size_t sigsetlen;
	} *sd;
	if (!mm_check_read(sigmask_data, sizeof(sigmask_data)))
		return -L_EFAULT;
	sd = (struct sigmask_data *)sigmask_data;
	if (sd->sigsetlen != sizeof(sigset_t))
		return -L_EINVAL;
	const sigset_t *sigmask = sd->sigmask;
	log_info("pselect6(%d, %p, %p, %p, %p, %p)", nfds, readfds, writefds, exceptfds, timeout_ts, sigmask);
	if ((readfds && !mm_check_write(readfds, sizeof(struct fdset)))
		|| (writefds && !mm_check_write(writefds, sizeof(struct fdset)))
		|| (exceptfds && !mm_check_write(exceptfds, sizeof(struct fdset)))
		|| (timeout_ts && !mm_check_read(timeout_ts, sizeof(struct timespec)))
		|| (sigmask && !mm_check_read(sigmask, sizeof(sigset_t))))
		return -L_EFAULT;
	int timeout = timeout_ts == NULL ? -1 : (timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000);
	return vfs_pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

DEFINE_SYSCALL(epoll_create1, int, flags)
{
	log_info("epoll_create1(%d)", flags);

	AcquireSRWLockExclusive(&vfs->rw_lock);
	struct file *epollfd;
	int r = epollfd_alloc(&epollfd);
	if (r)
		goto out;
	r = store_file_internal(epollfd, (flags & EPOLL_CLOEXEC) > 0);
	if (r < 0)
		vfs_release(epollfd);

out:
	ReleaseSRWLockExclusive(&vfs->rw_lock);
	return r;
}

DEFINE_SYSCALL(epoll_create, int, size)
{
	log_info("epoll_create(%d)", size);
	if (size <= 0)
		return -L_EINVAL;
	return sys_epoll_create1(0);
}

DEFINE_SYSCALL(epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event)
{
	log_info("epoll_ctl(epfd=%d, op=%d, fd=%d, epoll_event=%p)", epfd, op, fd, event);
	if (!mm_check_read(event, sizeof(struct epoll_event)))
		return -L_EINVAL;
	if ((event->events & EPOLLET))
	{
		log_error("Edge triggered epoll is not supported.");
		return -L_EINVAL;
	}
	int r = 0;
	struct file *f = vfs_get(epfd);
	if (!f || !epollfd_is_epollfd(f))
	{
		r = -L_EBADF;
		goto out;
	}
	struct file *mf = vfs_get(fd);
	if (!mf)
	{
		r = -L_EBADF;
		goto out;
	}
	switch (op)
	{
	case EPOLL_CTL_ADD:
	{
		r = epollfd_ctl_add(f, fd, event);
		break;
	}
	case EPOLL_CTL_DEL:
	{
		r = epollfd_ctl_del(f, fd);
		break;
	}
	case EPOLL_CTL_MOD:
	{
		r = epollfd_ctl_mod(f, fd, event);
		break;
	}
	default:
		r = -L_EINVAL;
	}
out:
	if (mf)
		vfs_release(mf);
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(epoll_pwait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout, const sigset_t *, sigmask)
{
	log_info("epoll_pwait(%d, %p, %d, %d, %p)", epfd, events, maxevents, timeout, sigmask);
	if (!mm_check_write(events, sizeof(struct epoll_event) * maxevents))
		return -L_EFAULT;
	if (sigmask && !mm_check_read(sigmask, sizeof(sigset_t)))
		return -L_EFAULT;
	struct file *f = vfs_get(epfd);
	int r;
	if (!f || !epollfd_is_epollfd(f))
	{
		r = -L_EBADF;
		goto out;
	}
	int nfds = epollfd_get_nfds(f);
	struct linux_pollfd *pollfds = (struct linux_pollfd *)alloca(sizeof(struct linux_pollfd) * nfds);
	epollfd_to_pollfds(f, pollfds);
	r = vfs_ppoll(pollfds, nfds, timeout, sigmask);
	if (r < 0)
		goto out;
	r = epollfd_to_events(f, pollfds, events, maxevents);
out:
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(epoll_wait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout)
{
	return sys_epoll_pwait(epfd, events, maxevents, timeout, NULL);
}

DEFINE_SYSCALL(getxattr, const char *, path, const char *, name, void *, value, size_t, size)
{
	log_info("getxattr(\"%s\", \"%s\", %p, %d)", path, name, value, size);
	log_warning("getxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(lgetxattr, const char *, path, const char *, name, void *, value, size_t, size)
{
	log_info("lgetxattr(\"%s\", \"%s\", %p, %d)", path, name, value, size);
	log_warning("lgetxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(fgetxattr, int, fd, const char *, name, void *, value, size_t, size)
{
	log_info("fgetxattr(%d, \"%s\", %p, %d)", fd, name, value, size);
	log_warning("fgetxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(listxattr, const char *, path, char *, list, size_t, size)
{
	log_info("listxattr(\"%s\", %p, %d)", path, list, size);
	log_warning("listxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(llistxattr, const char *, path, char *, list, size_t, size)
{
	log_info("llistxattr(\"%s\", %p, %d)", path, list, size);
	log_warning("llistxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(flistxattr, int, fd, char *, list, size_t, size)
{
	log_info("flistxattr(%d, %p, %d)", fd, list, size);
	log_warning("flistxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(setxattr, const char *, path, const char *, name, const void *, value, size_t, size, int, flags)
{
	log_info("setxattr(\"%s\", \"%s\", %p, %d, %x)", path, name, value, size, flags);
	log_warning("setxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(lsetxattr, const char *, path, const char *, name, const void *, value, size_t, size, int, flags)
{
	log_info("lsetxattr(\"%s\", \"%s\", %p, %d, %x)", path, name, value, size, flags);
	log_warning("lsetxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(fsetxattr, int, fd, const char *, name, const void *, value, size_t, size, int, flags)
{
	log_info("fsetxattr(%d, \"%s\", %p, %d, %x)", fd, name, value, size, flags);
	log_warning("fsetxattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(removexattr, const char *, path, const char *, name)
{
	log_info("removexattr(\"%s\", \"%s\")", path, name);
	log_warning("removexattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(lremovexattr, const char *, path, const char *, name)
{
	log_info("lremovexattr(\"%s\", \"%s\")", path, name);
	log_warning("lremovexattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(fremovexattr, int, fd, const char *, name)
{
	log_info("fremovexattr(%d, \"%s\")", fd, name);
	log_warning("fremovexattr() not implemented.");
	return -L_EOPNOTSUPP;
}

DEFINE_SYSCALL(fallocate, int, fd, int, mode, loff_t, offset, loff_t, len) 
{
	log_info("fallocate(%d, %d, %d, %d)", fd, mode, offset, len);
	log_warning("fallocate() not implemented.");
	return -L_EOPNOTSUPP;
}
