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

#ifdef _DEBUG

void log_init();
void log_shutdown();
void log_raw(const char *format, ...);
void log_debug(const char *format, ...);
void log_info(const char *format, ...);
void log_warning(const char *format, ...);
void log_error(const char *format, ...);

#else

#define log_init() ((void*)0)
#define log_shutdown() ((void*)0)
#define log_raw(format, ...) ((void*)0)
#define log_debug(format, ...) ((void*)0)
#define log_info(format, ...) ((void*)0)
#define log_warning(format, ...) ((void*)0)
#define log_error(format, ...) ((void*)0)

#endif
