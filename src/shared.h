/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2015 Xiangyan Sun <wishstudio@gmail.com>
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

#include <stdbool.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ntdll.h>

HANDLE shared_get_object_directory();
void shared_init();
bool shared_fork(HANDLE child);
void shared_afterfork_parent();
void shared_afterfork_child();

/* Static allocation for globally shared area
 * Currently the users of this API should make sure to work with zero initialization
 * Because they do not have any chance of manually initialize their shared data area
 */
#define SHARED_ALLOC_SIZE		3 * BLOCK_SIZE
void *shared_alloc(size_t size);
