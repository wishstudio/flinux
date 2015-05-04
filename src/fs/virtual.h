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
#define VIRTUALFS_TYPE_DIRECTORY	1	/* Directory */
#define VIRTUALFS_TYPE_CUSTOM		2	/* Fully custom character file */
#define VIRTUALFS_TYPE_CHAR			3	/* Character device */
#define VIRTUALFS_TYPE_TEXT			4	/* In-memory read only text file */
#define VIRTUALFS_TYPE_PARAM		5	/* Kernel sysfs parameter */

struct virtualfs_desc
{
	int type;
};

#define VIRTUALFS_ENTRY_TYPE_END		0
#define VIRTUALFS_ENTRY_TYPE_STATIC		1
#define VIRTUALFS_ENTRY_TYPE_DYNAMIC	2
#define VIRTUALFS_ITER_END				-1
struct virtualfs_entry
{
	int type;
	union
	{
		/* For static entry */
		struct
		{
			char name[32];
			struct virtualfs_desc *desc;
		};
		/* For dynamic entry */
		struct
		{
			void (*begin_iter)(int dir_tag);
			void (*end_iter)(int dir_tag);
			int (*iter)(int dir_tag, int iter_tag, int *type, char *name, int namelen);
			int (*open)(int dir_tag, const char *name, int namelen, int *file_tag, struct virtualfs_desc **desc);
		};
	};
};
#define VIRTUALFS_ENTRY(_name, _desc) \
	{ .type = VIRTUALFS_ENTRY_TYPE_STATIC, .name = _name, .desc = (struct virtualfs_desc *)&_desc },
#define VIRTUALFS_ENTRY_DYNAMIC(_begin_iter, _end_iter, _iter, _open) \
	{ .type = VIRTUALFS_ENTRY_TYPE_DYNAMIC, .begin_iter = _begin_iter, \
		.end_iter = _end_iter, .iter = _iter, .open = _open },
#define VIRTUALFS_ENTRY_END() \
	{ .type = VIRTUALFS_ENTRY_TYPE_END },

/* VIRTUALFS_TYPE_DIRECTORY */
struct virtualfs_directory_desc
{
	int type;
	struct virtualfs_entry entries[];
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
	size_t (*read)(int tag, void *buf, size_t count);
	size_t (*write)(int tag, const void *buf, size_t count);
};
#define VIRTUALFS_CHAR(_device, _read, _write) \
	{ \
		.type = VIRTUALFS_TYPE_CHAR, \
		.device = _device, \
		.read = _read, \
		.write = _write, \
	}

/* VIRTUALFS_TYPE_TEXT */
struct virtualfs_text_desc
{
	int type;
	int (*getbuflen)(int tag);
	void (*gettext)(int tag, char *buf);
};
#define VIRTUALFS_TEXT(_getbuflen, _gettext) \
	{ \
		.type = VIRTUALFS_TYPE_TEXT, \
		.getbuflen = _getbuflen, \
		.gettext = _gettext, \
	}

/* VIRTUALFS_TYPE_PARAM */
#define VIRTUALFS_PARAM_TYPE_RAW		0
#define VIRTUALFS_PARAM_TYPE_INT		1
#define VIRTUALFS_PARAM_TYPE_UINT		2
struct virtualfs_param_desc
{
	int type;
	int valtype;
	union {
		size_t (*get)(int tag, char *buf, size_t count);
		int (*get_int)(int tag);
		unsigned int (*get_uint)(int tag);
	};
	union {
		void (*set)(int tag, const char *buf, size_t count);
		void (*set_int)(int tag, int value);
		void (*set_uint)(int tag, unsigned int value);
	};
};
#define __VIRTUALFS_PARAM_META(_valtype, _suffix, _getter, _setter) \
	{ \
		.type = VIRTUALFS_TYPE_PARAM, \
		.valtype = _valtype, \
		.get##_suffix = _getter, \
		.set##_suffix = _setter, \
	}
#define VIRTUALFS_PARAM(_getter, _setter) __VIRTUALFS_PARAM_META(VIRTUALFS_PARAM_TYPE_RAW, , _getter, _setter)
#define VIRTUALFS_PARAM_READONLY(_getter) VIRTUALFS_PARAM(_getter, NULL)
#define VIRTUALFS_PARAM_WRITEONLY(_setter) VIRTUALFS_PARAM(NULL, _setter)
#define VIRTUALFS_PARAM_INT(_getter, _setter) __VIRTUALFS_PARAM_META(VIRTUALFS_PARAM_TYPE_INT, _int, _getter, _setter)
#define VIRTUALFS_PARAM_INT_READONLY(_getter) VIRTUALFS_PARAM_INT(_getter, NULL)
#define VIRTUALFS_PARAM_INT_WRITEONLY(_setter) VIRTUALFS_PARAM_INT(NULL, _setter)
#define VIRTUALFS_PARAM_UINT(_getter, _setter) __VIRTUALFS_PARAM_META(VIRTUALFS_PARAM_TYPE_UINT, _uint, _getter, _setter)
#define VIRTUALFS_PARAM_UINT_READONLY(_getter) VIRTUALFS_PARAM_UINT(_getter, NULL)
#define VIRTUALFS_PARAM_UINT_WRITEONLY(_setter) VIRTUALFS_PARAM_UINT(NULL, _setter)

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
struct file_system *virtualfs_alloc(const char *mountpoint, const struct virtualfs_directory_desc *dir);
