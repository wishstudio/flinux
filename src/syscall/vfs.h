#ifndef _SYSCALL_VFS_H
#define _SYSCALL_VFS_H

#include "types.h"

struct stat {
	unsigned long st_dev;
	unsigned long st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned long st_rdev;
	unsigned long st_size;
	unsigned long st_blksize;
	unsigned long st_blocks;
	unsigned long st_atime;
	unsigned long st_atime_nsec;
	unsigned long st_mtime;
	unsigned long st_mtime_nsec;
	unsigned long st_ctime;
	unsigned long st_ctime_nsec;
	unsigned long __unused1;
	unsigned long __unused2;
};

int sys_stat(const char *pathname, struct stat *buf);
int sys_lstat(const char *pathname, struct stat *buf);
int sys_fstat(int fd, struct stat *buf);

#endif
