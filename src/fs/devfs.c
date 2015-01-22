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
#include <fs/devfs.h>
#include <fs/null.h>
#include <fs/random.h>
#include <heap.h>
#include <log.h>

struct devfs
{
	struct file_system base_fs;
};

static int devfs_open(const char *path, int flags, int mode, struct file **fp, char *target, int buflen)
{
	if (*path == 0 || !strcmp(path, "."))
	{
		if (fp)
		{
			log_error("Opening /dev not handled.\n");
			return -ENOENT;
		}
		else
			return 0;
	}
	else if (!strcmp(path, "null"))
	{
		*fp = null_dev_alloc();
		return 0;
	}
	else if (!strcmp(path, "random"))
	{
		*fp = random_dev_alloc();
		return 0;
	}
	else if (!strcmp(path, "urandom"))
	{
		*fp = urandom_dev_alloc();
		return 0;
	}
	else
	{
		log_warning("devfs: '%s' not found.\n", path);
		return -ENOENT;
	}
}

struct file_system *devfs_alloc()
{
	struct devfs *fs = (struct devfs *)kmalloc(sizeof(struct devfs));
	fs->base_fs.mountpoint = "/dev";
	fs->base_fs.open = devfs_open;
	return fs;
}
