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

#include <fs/file.h>
#include <fs/virtual.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void console_init();
int console_fork(HANDLE process);
void console_afterfork();

struct virtualfs_custom_desc console_desc;
size_t console_read(void *buf, size_t count);
size_t console_write(const void *buf, size_t count);
struct file *console_alloc();
