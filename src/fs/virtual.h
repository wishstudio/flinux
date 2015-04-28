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

#include <fs/file.h>

#define VIRTUALFS_TYPE_INVALID		0	/* Invalid entry */
#define VIRTUALFS_TYPE_CUSTOM		1	/* Fully custom character file */
#define VIRTUALFS_TYPE_CHAR			2	/* Character device */

struct virtualfs_desc
{
	int type;
};

/* VIRTUALFS_TYPE_CUSTOM */
/* To use this desc, implement a custom file allocation function.
 * Call virtualfs_custom_file_init() in it.
 * Set the file_ops.stat vptr to virtualfs_custom_file_stat().
 */
struct virtualfs_custom_desc
{
	int type;
	int device;
	struct file *(*alloc)();
};
#define VIRTUALFS_CUSTOM(_device, _alloc) \
	{ \
		.type = VIRTUALFS_TYPE_CUSTOM, \
		.device = _device, \
		.alloc = _alloc, \
	}

/* VIRTUALFS_TYPE_CHAR */
struct virtualfs_char_desc
{
	int type;
	int device;
	size_t (*read)(void *buf, size_t count);
	size_t (*write)(const void *buf, size_t count);
};
#define VIRTUALFS_CHAR(_device, _read, _write) \
	{ \
		.type = VIRTUALFS_TYPE_CHAR, \
		.device = _device, \
		.read = _read, \
		.write = _write, \
	}

struct virtualfs_entry
{
	char name[32];
	struct virtualfs_desc *desc;
};
#define VIRTUALFS_ENTRY(_name, _desc) \
	{ .name = _name, .desc = (struct virtualfs_desc *)&_desc },
#define VIRTUALFS_ENTRY_END() \
	{ .name = "", .desc = NULL },

struct virtualfs_directory_desc
{
	struct virtualfs_entry entries[];
};

struct virtualfs_custom
{
	struct file base_file;
	struct virtualfs_desc *desc;
};

int virtualfs_get_poll_status_inout(struct file *f); /* get_poll_status: Always POLLIN | POLLOUT */

/* For custom file */
void virtualfs_custom_init(void *file, struct virtualfs_desc *desc);
int virtualfs_custom_stat(struct file *f, struct newstat *buf);

/* File system calls */
struct file_system *virtualfs_alloc(char *mountpoint, const struct virtualfs_directory_desc *dir);
