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
#include <common/poll.h>
#include <fs/epollfd.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <heap.h>
#include <log.h>

#define MAX_EPOLLFD_COUNT	128

struct epoll_fd
{
	int fd;
	struct epoll_event event;
};

struct epollfd_file
{
	struct file base_file;
	int fd_count;
	struct epoll_fd fds[MAX_EPOLLFD_COUNT];
};

static int epollfd_close(struct file *f)
{
	struct epollfd_file *epollfd = (struct epollfd_file *)f;
	kfree(epollfd, sizeof(struct epollfd_file));
	return 0;
}

int epollfd_ctl_add(struct file *f, int fd, struct epoll_event *event)
{
	struct epollfd_file *epollfd = (struct epollfd_file *)f;
	AcquireSRWLockExclusive(&epollfd->base_file.rw_lock);
	int r = 0;
	/* Ensure the monitoring file is not registered before */
	for (int i = 0; i < epollfd->fd_count; i++)
		if (epollfd->fds[i].fd == fd)
		{
			r = -L_EEXIST;
			goto out;
		}
	/* Add the file */
	epollfd->fds[epollfd->fd_count].fd = fd;
	epollfd->fds[epollfd->fd_count].event = *event;
	epollfd->fd_count++;
out:
	ReleaseSRWLockExclusive(&epollfd->base_file.rw_lock);
	return r;
}

int epollfd_ctl_del(struct file *f, int fd)
{
	struct epollfd_file *epollfd = (struct epollfd_file *)f;
	AcquireSRWLockExclusive(&epollfd->base_file.rw_lock);
	int r = 0;
	/* Find and delete the monitoring file */
	for (int i = 0; i < epollfd->fd_count; i++)
		if (epollfd->fds[i].fd == fd)
		{
			for (int j = i; j + 1 < epollfd->fd_count; j++)
				epollfd->fds[j] = epollfd->fds[j + 1];
			epollfd->fd_count--;
			goto out;
		}
	r = -L_ENOENT;
out:
	ReleaseSRWLockExclusive(&epollfd->base_file.rw_lock);
	return r;
}

int epollfd_ctl_mod(struct file *f, int fd, struct epoll_event *event)
{
	struct epollfd_file *epollfd = (struct epollfd_file *)f;
	AcquireSRWLockExclusive(&epollfd->base_file.rw_lock);
	int r = 0;
	/* Find and modify the monitoring file */
	for (int i = 0; i < epollfd->fd_count; i++)
		if (epollfd->fds[i].fd == fd)
		{
			epollfd->fds[i].event = *event;
			goto out;
		}
	r = -L_ENOENT;
out:
	ReleaseSRWLockExclusive(&epollfd->base_file.rw_lock);
	return r;
}

static const struct file_ops epollfd_ops = {
	.close = epollfd_close,
};

int epollfd_alloc(struct file **f)
{
	struct epollfd_file *epollfd = (struct epollfd_file *)kmalloc(sizeof(struct epollfd_file));
	file_init(&epollfd->base_file, &epollfd_ops, 0);
	epollfd->fd_count = 0;
	*f = (struct file *)epollfd;
	return 0;
}

bool epollfd_is_epollfd(struct file *f)
{
	return f->op_vtable == &epollfd_ops;
}

int epollfd_get_nfds(struct file *f)
{
	struct epollfd_file *epollfd = (struct epollfd_file *)f;
	return epollfd->fd_count;
}

void epollfd_to_pollfds(struct file *f, struct linux_pollfd *fds)
{
	struct epollfd_file *epollfd = (struct epollfd_file *)f;
	for (int i = 0; i < epollfd->fd_count; i++)
	{
		fds[i].fd = epollfd->fds[i].fd;
		fds[i].events = epollfd->fds[i].event.events & (POLLIN | POLLOUT | POLLERR);
		fds[i].revents = 0;
	}
}

int epollfd_to_events(struct file *f, const struct linux_pollfd *fds, struct epoll_event *events, int maxevents)
{
	struct epollfd_file *epollfd = (struct epollfd_file *)f;
	int r = 0;
	for (int i = 0; i < epollfd->fd_count; i++)
	{
		if (r >= maxevents)
			return r;
		if (fds[i].revents)
		{
			events[r].events = fds[i].revents;
			events[r].data = epollfd->fds[i].event.data;
			r++;
		}
	}
	return r;
}
