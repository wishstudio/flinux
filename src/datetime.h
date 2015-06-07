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

#include <common/time.h>

#include <stdint.h>
#include <Windows.h>

#define NANOSECONDS_PER_TICK	100ULL
#define NANOSECONDS_PER_SECOND	1000000000ULL
#define TICKS_PER_SECOND		10000000ULL

uint64_t filetime_to_unix_sec(const FILETIME *filetime);
uint64_t filetime_to_unix_nsec(const FILETIME *filetime);
void filetime_to_unix_timeval(const FILETIME *filetime, struct timeval *tv);
void filetime_to_unix_timespec(const FILETIME *filetime, struct timespec *tv);
void unix_timeval_to_filetime(const struct timeval *time, FILETIME *filetime);
void unix_timespec_to_filetime(const struct timespec *time, FILETIME *filetime);
void unix_timeval_to_unix_timespec(const struct timeval *timeval, struct timespec *timespec);
