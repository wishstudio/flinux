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
#include <fs/procfs.h>
#include <fs/virtual.h>
#include <log.h>
#include <str.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void procfs_pid_begin_iter(int dir_tag);
void procfs_pid_end_iter(int dir_tag);
int procfs_pid_iter(int dir_tag, int iter_tag, int *type, char *name, int namelen);
static int procfs_pid_open(int dir_tag, const char *name, int namelen, int *file_tag, struct virtualfs_desc **desc)
{
	return -ENOENT;
}

static int sys_vm_min_free_kbytes_get(int tag)
{
	return 4096;
}
struct virtualfs_param_desc sys_vm_min_free_kbytes_desc = VIRTUALFS_PARAM_UINT_READONLY(sys_vm_min_free_kbytes_get);

struct virtualfs_directory_desc sys_vm_desc =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("min_free_kbytes", sys_vm_min_free_kbytes_desc)
		VIRTUALFS_ENTRY_END()
	}
};

struct virtualfs_directory_desc sys_desc =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("vm", sys_vm_desc)
		VIRTUALFS_ENTRY_END()
	}
};

static int meminfo_getbuflen(int tag)
{
	return 512;
}

static void meminfo_gettext(int tag, char *buf)
{
	MEMORYSTATUSEX memory;
	memory.dwLength = sizeof(memory);
	GlobalMemoryStatusEx(&memory);
	ksprintf(buf,
		"MemTotal:  %13llu kB\n"
		"MemFree:   %13llu kB\n"
		"HighTotal: %13llu kB\n"
		"HighFree:  %13llu kB\n"
		"LowTotal:  %13llu kB\n"
		"LowFree:   %13llu kB\n"
		"SwapTotal: %13llu kB\n"
		"SwapFree:  %13llu kB\n",
		memory.ullTotalPhys / 1024ULL, memory.ullAvailPhys / 1024ULL,
		0ULL, 0ULL,
		memory.ullTotalPhys / 1024ULL, memory.ullAvailPhys / 1024ULL,
		memory.ullTotalPageFile / 1024ULL, memory.ullAvailPageFile / 1024ULL);
}

static struct virtualfs_text_desc meminfo_desc = VIRTUALFS_TEXT(meminfo_getbuflen, meminfo_gettext);

static const struct virtualfs_directory_desc procfs =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY_DYNAMIC(procfs_pid_begin_iter, procfs_pid_end_iter, procfs_pid_iter, procfs_pid_open)
		VIRTUALFS_ENTRY("sys", sys_desc)
		VIRTUALFS_ENTRY("meminfo", meminfo_desc)
		VIRTUALFS_ENTRY_END()
	}
};

struct file_system *procfs_alloc()
{
	return virtualfs_alloc("/proc", &procfs);
}
