#pragma once

#include <common/stat.h>
#include <common/dirent.h>
#include <fs/file.h>

#include <stdint.h>

#define PATH_MAX		4096

void vfs_init();
void vfs_reset();
void vfs_shutdown();

int vfs_open(const char *pathname, int flags, int mode, struct file **f);
void vfs_close(int fd);
struct file *vfs_get(int fd);
void vfs_release(struct file *f);

size_t sys_read(int fd, char *buf, size_t count);
size_t sys_write(int fd, const char *buf, size_t count);
size_t sys_pread64(int fd, char *buf, size_t count, loff_t offset);
size_t sys_pwrite64(int fd, const char *buf, size_t count, loff_t offset);
off_t sys_lseek(int fd, off_t offset, int whence);
int sys_llseek(unsigned long offset_high, unsigned long offset_low, loff_t *result, int whence);

int sys_open(const char *pathname, int flags, int mode);
int sys_close(int fd);

int sys_mknod(const char *pathname, int mode, unsigned int dev);

int sys_link(const char *pathname);
int sys_unlink(const char *pathname);

int sys_symlink(const char *target, const char *linkpath);
size_t sys_readlink(const char *pathname, char *buf, size_t bufsize);

int sys_pipe(int pipefd[2]);
int sys_pipe2(int pipefd[2], int flags);

int sys_dup2(int fd, int newfd);

int sys_mkdir(const char *pathname, int mode);
int sys_getdents64(int fd, struct linux_dirent64 *dirent, unsigned int count);

int sys_stat(const char *pathname, struct stat *buf);
int sys_lstat(const char *pathname, struct stat *buf);
int sys_fstat(int fd, struct stat *buf);

int sys_stat64(const char *pathname, struct stat64 *buf);
int sys_lstat64(const char *pathname, struct stat64 *buf);
int sys_fstat64(int fd, struct stat64 *buf);

int sys_utime(const char *filename, const struct utimbuf *times);
int sys_utimes(const char *filename, const struct timeval times[2]);

int sys_ioctl(int fd, unsigned int cmd, unsigned long arg);
int sys_chdir(const char *pathname);
char *sys_getcwd(char *buf, size_t size);

int sys_fcntl64(int fd, int cmd, ...);

int sys_access(const char *pathname, int mode);
int sys_chmod(const char *pathname, int mode);
int sys_umask(int mask);
int sys_chown(const char *pathname, uid_t owner, gid_t group);
