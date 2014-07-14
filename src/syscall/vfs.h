#ifndef _SYSCALL_VFS_H
#define _SYSCALL_VFS_H

#include <common/stat.h>

int sys_stat(const char *pathname, struct stat *buf);
int sys_lstat(const char *pathname, struct stat *buf);
int sys_fstat(int fd, struct stat *buf);

#endif
