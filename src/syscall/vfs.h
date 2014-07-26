#ifndef _SYSCALL_VFS_H
#define _SYSCALL_VFS_H

#include <stdint.h>
#include <common/stat.h>
#include <common/dirent.h>

void vfs_init();
void vfs_shutdown();

size_t sys_read(int fd, char *buf, size_t count);
size_t sys_write(int fd, const char *buf, size_t count);

int sys_open(const char *pathname, int flags, int mode);
int sys_close(int fd);

int sys_dup2(int fd, int newfd);

int sys_getdents64(int fd, struct linux_dirent64 *dirent, unsigned int count);

int sys_stat(const char *pathname, struct stat *buf);
int sys_lstat(const char *pathname, struct stat *buf);
int sys_fstat(int fd, struct stat *buf);

int sys_stat64(const char *pathname, struct stat64 *buf);
int sys_lstat64(const char *pathname, struct stat64 *buf);
int sys_fstat64(int fd, struct stat64 *buf);

int sys_ioctl(int fd, unsigned int cmd, unsigned long arg);
char *sys_getcwd(char *buf, size_t size);

#endif
