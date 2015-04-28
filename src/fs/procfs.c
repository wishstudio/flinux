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

#include <fs/procfs.h>
#include <fs/virtual.h>
#include <log.h>
#include <str.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static int meminfo_getbuflen()
{
	return 512;
}

static void meminfo_gettext(char *buf)
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
	.mountpoint = "/proc",
	.entries = {
		VIRTUALFS_ENTRY("meminfo", meminfo_desc)
		VIRTUALFS_ENTRY_END()
	}
};

struct file_system *procfs_alloc()
{
	return virtualfs_alloc(&procfs);
}
