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

#include <fs/sysfs.h>
#include <fs/virtual.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static int vm_min_free_kbytes_get()
{
	return 4096;
}
struct virtualfs_param_desc vm_min_free_kbytes_desc = VIRTUALFS_PARAM_UINT_READONLY(vm_min_free_kbytes_get);

struct virtualfs_directory_desc sys_vm_desc =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("min_free_kbytes", vm_min_free_kbytes_desc)
		VIRTUALFS_ENTRY_END()
	}
};

struct virtualfs_directory_desc sysfs_desc =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("vm", sys_vm_desc)
		VIRTUALFS_ENTRY_END()
	}
};
