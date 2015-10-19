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

#pragma once

#include <common/stat.h>
#include <common/dirent.h>
#include <common/poll.h>
#include <common/select.h>
#include <common/uio.h>
#include <fs/file.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>

#define PATH_MAX			4096
#define MAX_FD_COUNT		1024
#define MAX_SYMLINK_LEVEL	8

void vfs_init();
void vfs_reset();
void vfs_shutdown();
int vfs_fork(HANDLE process);
void vfs_afterfork_parent();
void vfs_afterfork_child();
int vfs_store_file(struct file *f, int cloexec);

int vfs_openat(int dirfd, const char *pathname, int flags, int mode, struct file **f);
struct file *vfs_get(int fd);
void vfs_ref(struct file *f);
void vfs_release(struct file *f);
void vfs_get_root_mountpoint(struct mount_point *mp);
bool vfs_get_mountpoint(int key, struct mount_point *mp);
