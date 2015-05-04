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

#include <fs/file.h>
#include <fs/virtual.h>
#include <syscall/syscall.h>
#include <errno.h>
#include <log.h>

#define SystemFunction036 NTAPI SystemFunction036
#include <NTSecAPI.h>
#undef SystemFunction036

DEFINE_SYSCALL(getrandom, void *, buf, size_t, buflen, unsigned int, flags)
{
	log_info("getrandom(%p, %d, %x)\n", buf, buflen, flags);
	if (!mm_check_write(buf, buflen))
		return -EFAULT;
	if (!RtlGenRandom(buf, buflen))
		return 0;
	return buflen;
}

static size_t random_read(int tag, void *buf, size_t count)
{
	if (!RtlGenRandom(buf, count))
		return 0;
	return count;
}

static size_t random_write(int tag, const void *buf, size_t count)
{
	return count;
}

struct virtualfs_char_desc random_desc = VIRTUALFS_CHAR(mkdev(1, 8), random_read, random_write);
struct virtualfs_char_desc urandom_desc = VIRTUALFS_CHAR(mkdev(1, 9), random_read, random_write);
