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

#include <common/eventpoll.h>
#include <fs/file.h>

#include <stdbool.h>

int epollfd_alloc(struct file **epollfd);
bool epollfd_is_epollfd(struct file *f);

int epollfd_ctl_add(struct file *f, int fd, struct epoll_event *event);
int epollfd_ctl_del(struct file *f, int fd);
int epollfd_ctl_mod(struct file *f, int fd, struct epoll_event *event);
int epollfd_get_nfds(struct file *f);
void epollfd_to_pollfds(struct file *f, struct linux_pollfd *fds);
int epollfd_to_events(struct file *f, const struct linux_pollfd *fds, struct epoll_event *events, int maxevents);
