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
#include <common/param.h>
#include <dbt/cpuid.h>
#include <fs/procfs.h>
#include <fs/virtual.h>
#include <syscall/process.h>
#include <datetime.h>
#include <log.h>
#include <ntdll.h>
#include <str.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static int mounts_gettext(int tag, char *buf)
{
	return ksprintf(buf, "none / ntfs\n");
}

static struct virtualfs_text_desc proc_mounts_desc = VIRTUALFS_TEXT(mounts_gettext);

static int proc_stat_gettext(int tag, char *buf)
{
	return process_query_pid(tag, PROCESS_QUERY_STAT, buf);
}

static struct virtualfs_text_desc proc_stat_desc = VIRTUALFS_TEXT(proc_stat_gettext);

struct virtualfs_directory_desc proc_pid_desc =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("mounts", proc_mounts_desc)
		VIRTUALFS_ENTRY("stat", proc_stat_desc)
		VIRTUALFS_ENTRY_END()
	}
};

void procfs_pid_begin_iter(int dir_tag);
void procfs_pid_end_iter(int dir_tag);
int procfs_pid_iter(int dir_tag, int iter_tag, int *type, char *name, int namelen);
static int procfs_pid_open(int dir_tag, const char *name, int namelen, int *file_tag, struct virtualfs_desc **desc)
{
	char buf[32];
	if (namelen >= sizeof(buf))
		return -L_ENOENT;
	strncpy(buf, name, namelen);
	buf[namelen] = 0;
	pid_t pid;
	if (!katou(buf, &pid))
		return -L_ENOENT;
	if (!process_pid_exist(pid))
		return -L_ENOENT;
	*file_tag = pid;
	*desc = (struct virtualfs_desc *)&proc_pid_desc;
	return 0;
}

static int sys_vm_min_free_kbytes_get(int tag)
{
	return 4096;
}
static struct virtualfs_param_desc sys_vm_min_free_kbytes_desc = VIRTUALFS_PARAM_UINT_READONLY(sys_vm_min_free_kbytes_get);

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

static int stat_gettext(int tag, char *buf)
{
	char *original_buf = buf;
	/* TODO: Support more than one processors */
	LARGE_INTEGER idle_time, kernel_time, user_time;
	GetSystemTimes((FILETIME *)&idle_time, (FILETIME *)&kernel_time, (FILETIME *)&user_time);
	uint64_t user = user_time.QuadPart / (TICKS_PER_SECOND / USER_HZ);
	uint64_t nice = 0;
	uint64_t system = kernel_time.QuadPart / (TICKS_PER_SECOND / USER_HZ);
	uint64_t idle = idle_time.QuadPart / (TICKS_PER_SECOND / USER_HZ);
	system -= idle; /* KernelTime includes IdleTime */
	uint64_t iowait = 0;
	uint64_t irq = 0;
	uint64_t softirq = 0;
	uint64_t steal = 0, guest = 0, guest_nice = 0;

	buf += ksprintf(buf, "cpu   %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
		user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice);
	buf += ksprintf(buf, "intr  %llu\n", 0);
	buf += ksprintf(buf, "swap  %llu %llu\n", 0);
	uint64_t ctxt = 0;
	buf += ksprintf(buf, "ctxt  %llu\n", ctxt);
	/* Boot time */
	SYSTEM_TIMEOFDAY_INFORMATION tod_info;
	NtQuerySystemInformation(SystemTimeOfDayInformation, &tod_info, sizeof(tod_info), NULL);
	uint64_t btime = filetime_to_unix_sec((FILETIME *)&tod_info.BootTime);
	buf += ksprintf(buf, "btime %llu\n", btime);
	uint64_t processes = 0;
	buf += ksprintf(buf, "processes %llu\n", processes);
	int procs_running = 1;
	buf += ksprintf(buf, "procs_running %d\n", procs_running);
	int procs_blocked = 0;
	buf += ksprintf(buf, "procs_blocked %d\n", procs_blocked);
	return buf - original_buf;
}

static struct virtualfs_text_desc stat_desc = VIRTUALFS_TEXT(stat_gettext);

static int cpuinfo_gettext(int tag, char *buf)
{
	struct cpuid_t cpuid;

	char vendorid[13];
	vendorid[12] = 0;
	dbt_cpuid(0, 0, &cpuid);
	int cpuid_level = cpuid.eax;
	memcpy(vendorid, &cpuid.ebx, sizeof(cpuid.ebx));
	memcpy(vendorid + 4, &cpuid.edx, sizeof(cpuid.edx));
	memcpy(vendorid + 8, &cpuid.ecx, sizeof(cpuid.ecx));
	strip(vendorid);

	dbt_cpuid(1, 0, &cpuid);
	int clflush_size = ((cpuid.ebx & 0xFF00) >> 8) * 8;

	dbt_cpuid(1, 0, &cpuid);
	int stepping = cpuid.eax & 0xF;
	int model = (cpuid.eax & 0xF0) >> 4;
	int family = (cpuid.eax & 0xF00) >> 8;

	int cache_size = 0;
	for (int i = 0;; i++)
	{
		dbt_cpuid(4, i, &cpuid);
		if (cpuid.eax == 0)
			break;
		struct ebx_struct
		{
			int line_size: 12;
			int partitions: 10;
			int ways: 10;
		};
		struct ebx_struct *ebx = (struct ebx_struct *)&cpuid.ebx;
		cache_size = (ebx->ways + 1) * (ebx->partitions + 1) * (ebx->line_size + 1) * (cpuid.ecx + 1);
	}

	char modelname[49];
	modelname[48] = 0;
	dbt_cpuid(0x80000002, 0, &cpuid);
	memcpy(modelname, &cpuid, sizeof(cpuid));
	dbt_cpuid(0x80000003, 0, &cpuid);
	memcpy(modelname + 16, &cpuid, sizeof(cpuid));
	dbt_cpuid(0x80000004, 0, &cpuid);
	memcpy(modelname + 32, &cpuid, sizeof(cpuid));
	strip(modelname);

	dbt_cpuid(0x80000008, 0, &cpuid);
	int physical_address_bits = cpuid.eax & 0xFF;
	int virtual_address_bits = (cpuid.eax & 0xFF00) >> 8;

	char flags[4096];
	dbt_get_cpuinfo(flags);
	return ksprintf(buf,
		"processor\t: 0\n"
		"vendor_id\t: %s\n"
		"cpu family\t: %d\n"
		"model\t\t: %d\n"
		"model name\t: %s\n"
		"stepping\t: %d\n"
		"cache size\t: %d KB\n"
		"cpuid level\t: %d\n"
		"flags\t\t:%s\n"
		"clflush size\t: %d\n"
		"address sizes\t: %d bits physical, %d bits virtual\n",
		vendorid,
		family,
		model,
		modelname,
		stepping,
		cache_size / 1024,
		cpuid_level,
		flags,
		clflush_size,
		physical_address_bits, virtual_address_bits);
}

static struct virtualfs_text_desc cpuinfo_desc = VIRTUALFS_TEXT(cpuinfo_gettext);

static int loadavg_gettext(int tag, char *buf)
{
	return ksprintf(buf,
		"%u.%02u %u.%02u %u.%02u %d/%d %d\n",
		0, 0, 0, 0, 0, 0, 0, 0, 0);
}

static struct virtualfs_text_desc loadavg_desc = VIRTUALFS_TEXT(loadavg_gettext);

static int meminfo_gettext(int tag, char *buf)
{
	MEMORYSTATUSEX memory;
	memory.dwLength = sizeof(memory);
	GlobalMemoryStatusEx(&memory);
	return ksprintf(buf,
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

static struct virtualfs_text_desc meminfo_desc = VIRTUALFS_TEXT(meminfo_gettext);

static int uptime_gettext(int tag, char *buf)
{
	/* The file contains two numbers:
	 * The first is the total number of seconds the system has been up.
	 * The second is the total number of seconds each core has spent idle.
	 * On multi-core systems, the second number may be greater than the first.
	 */
	uint64_t total = GetTickCount64() / 100ULL;
	LARGE_INTEGER idle_time, kernel_time, user_time;
	GetSystemTimes((FILETIME *)&idle_time, (FILETIME *)&kernel_time, (FILETIME *)&user_time);
	uint64_t idle = idle_time.QuadPart / (TICKS_PER_SECOND / 100);
	return ksprintf(buf, "%llu.%02u %llu.%02u\n",
		total / 100ULL, (uint32_t)(total % 100ULL),
		idle / 100ULL, (uint32_t)(idle % 100ULL));
}

static struct virtualfs_text_desc uptime_desc = VIRTUALFS_TEXT(uptime_gettext);

static const struct virtualfs_directory_desc procfs =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY_DYNAMIC(procfs_pid_begin_iter, procfs_pid_end_iter, procfs_pid_iter, procfs_pid_open)
		VIRTUALFS_ENTRY("self", proc_pid_desc)
		VIRTUALFS_ENTRY("stat", stat_desc)
		VIRTUALFS_ENTRY("sys", sys_desc)
		VIRTUALFS_ENTRY("cpuinfo", cpuinfo_desc)
		VIRTUALFS_ENTRY("loadavg", loadavg_desc)
		VIRTUALFS_ENTRY("meminfo", meminfo_desc)
		VIRTUALFS_ENTRY("uptime", uptime_desc)
		VIRTUALFS_ENTRY("mounts", proc_mounts_desc)
		VIRTUALFS_ENTRY_END()
	}
};

struct file_system *procfs_alloc()
{
	return virtualfs_alloc("/proc", &procfs);
}
