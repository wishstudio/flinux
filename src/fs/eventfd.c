/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 * Copyright (C) 2015 Adam Hoka <adam.hoka@gmail.com>
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
#include <common/fcntl.h>
#include <common/poll.h>
#include <fs/eventfd.h>
#include <syscall/mm.h>
#include <heap.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define EVENTFD_VALUE_MAX 0xfffffffffffffffeLLU

#define EFD_SEMAPHORE (1 << 0)
#define EFD_CLOEXEC O_CLOEXEC
#define EFD_NONBLOCK O_NONBLOCK

struct eventfd_file
{
	struct file efd_base_file;
	uint64_t *efd_value;
	HANDLE efd_handle;
	HANDLE efd_mutex;
	HANDLE efd_sem_canread;
	HANDLE efd_sem_canwrite;
	int efd_flags;
};

static const struct file_ops eventfd_ops;

int eventfd_alloc(struct file **eventfdfile, uint64_t count, int flags)
{
	if (flags & (EFD_SEMAPHORE))
	{
		log_error("eventfd: EFD_SEMAPHORE is unsupported!\n");
		return -EINVAL;
	}

	struct eventfd_file *efd = kmalloc(sizeof(struct eventfd_file));
	efd->efd_base_file.op_vtable = &eventfd_ops;
	efd->efd_base_file.ref = 1;
	efd->efd_base_file.flags = O_RDWR;

	SECURITY_ATTRIBUTES attrs;
	attrs.nLength = sizeof(SECURITY_ATTRIBUTES);
	attrs.lpSecurityDescriptor = NULL;
	attrs.bInheritHandle = TRUE;

	efd->efd_handle = CreateFileMapping(NULL, &attrs, PAGE_READWRITE, 0, 8, NULL);
	if (efd->efd_handle == NULL)
	{
		log_error("eventfd: Can't create handle: %u\n", GetLastError());
		return -ENOMEM;
	}

	efd->efd_value = MapViewOfFile(efd->efd_handle, FILE_MAP_ALL_ACCESS, 0, 0, 8);
	if (efd->efd_value == NULL)
	{
		log_error("eventfd: Can't map handle: %u\n", GetLastError());
		return -ENOMEM;
	}

	efd->efd_mutex = CreateMutex(&attrs, FALSE, NULL);
	efd->efd_sem_canread = CreateSemaphore(&attrs, 0, 1, NULL);
	efd->efd_sem_canwrite = CreateSemaphore(&attrs, 1, 1, NULL);

	*efd->efd_value = count;
	efd->efd_flags = flags;

	*eventfdfile = (struct file *)efd;

	return 0;
}

static int eventfd_close(struct file *f)
{
	struct eventfd_file *efd = (struct eventfd_file *)f;

	log_info("eventfd: close(%p)\n", f);

	BOOL rv = UnmapViewOfFile(efd->efd_value);
	if (rv)
	{
		log_error("eventfd: can't unmap handle during close\n");
	}

	rv = CloseHandle(efd->efd_handle);
	if (rv)
	{
		log_error("eventfd: can't close handle during close\n");
	}

	CloseHandle(efd->efd_mutex);
	CloseHandle(efd->efd_sem_canread);
	CloseHandle(efd->efd_sem_canwrite);

	kfree(efd, sizeof(struct eventfd_file));
	return 0;
}

static int eventfd_get_poll_status(struct file *f)
{
	struct eventfd_file *efd = (struct eventfd_file *)f;
	int events = 0;

	if (*efd->efd_value < EVENTFD_VALUE_MAX)
	{
		events |= LINUX_POLLOUT;
	}

	if (*efd->efd_value > 0)
	{
		events |= LINUX_POLLIN;
	}

	return events;
}

static void eventfd_after_fork(struct file *f)
{
	struct eventfd_file *efd = (struct eventfd_file *)f;

	log_info("eventfd: after_fork\n");

	efd->efd_value = MapViewOfFile(efd->efd_handle, FILE_MAP_ALL_ACCESS, 0, 0, 8);
}

static size_t eventfd_read(struct file *f, void *buf, size_t count)
{
	struct eventfd_file *efd = (struct eventfd_file *)f;

	log_info("eventfd: read(%p, %p, %u)\n", f, buf, count);

	if (count < 8)
	{
		return -EINVAL;
	}

	WaitForSingleObject(efd->efd_mutex, INFINITE);

	while (*efd->efd_value == 0)
	{
		ReleaseMutex(efd->efd_mutex);

		if (efd->efd_flags & EFD_NONBLOCK)
		{
			return -EAGAIN;
		}
		else
		{
			WaitForSingleObject(efd->efd_sem_canread, INFINITE);
		}

		WaitForSingleObject(efd->efd_mutex, INFINITE);
	}

	uint64_t* output = (uint64_t *)buf;

	*output = *efd->efd_value;
	*efd->efd_value = 0;

	ReleaseSemaphore(efd->efd_sem_canwrite, 1, NULL);
	ReleaseMutex(efd->efd_mutex);

	return 8;
}

static size_t eventfd_write(struct file *f, const void *buf, size_t count)
{
	struct eventfd_file *efd = (struct eventfd_file *)f;

	log_info("eventfd: write(%p, %p, %u)\n", f, buf, count);

	if (count < 8)
	{
		return -EINVAL;
	}

	WaitForSingleObject(efd->efd_mutex, INFINITE);

	const uint64_t* input = (const uint64_t *)buf;
	while (*efd->efd_value + *input > EVENTFD_VALUE_MAX)
	{
		ReleaseMutex(efd->efd_mutex);

		if (efd->efd_flags & EFD_NONBLOCK)
		{
			return -EAGAIN;
		}
		else
		{
			WaitForSingleObject(efd->efd_sem_canwrite, INFINITE);
		}

		WaitForSingleObject(efd->efd_mutex, INFINITE);
	}

	*efd->efd_value += *input;

	ReleaseSemaphore(efd->efd_sem_canread, 1, NULL);
	ReleaseMutex(efd->efd_mutex);

	return 8;
}

static const struct file_ops eventfd_ops = {
	.get_poll_status = eventfd_get_poll_status,
	.after_fork = eventfd_after_fork,
	.close = eventfd_close,
	.read = eventfd_read,
	.write = eventfd_write,
};
