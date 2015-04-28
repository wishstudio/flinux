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
#include <fs/console.h>
#include <fs/devfs.h>
#include <fs/null.h>
#include <fs/random.h>
#include <fs/virtual.h>
#include <heap.h>
#include <log.h>

struct devfs
{
	struct file_system base_fs;
};

static const struct virtualfs_directory_desc devfs =
{
	.entries = {
		VIRTUALFS_ENTRY("null", null_desc)
		VIRTUALFS_ENTRY("random", random_desc)
		VIRTUALFS_ENTRY("urandom", urandom_desc)
		VIRTUALFS_ENTRY("console", console_desc)
		VIRTUALFS_ENTRY("tty", console_desc)
		VIRTUALFS_ENTRY_END()
	}
};

struct file_system *devfs_alloc()
{
	return virtualfs_alloc("/dev", &devfs);
}
