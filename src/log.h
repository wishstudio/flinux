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

void log_init_thread();
void log_init();
void log_shutdown();
void log_raw_internal(const char *format, ...);
void log_debug_internal(const char *format, ...);
void log_info_internal(const char *format, ...);
void log_warning_internal(const char *format, ...);
void log_error_internal(const char *format, ...);

extern int logger_attached;
#define log_raw(format, ...) do { if (logger_attached) log_raw_internal(format, __VA_ARGS__); } while (0)
#define log_debug(format, ...) do { if (logger_attached) log_debug_internal(format, __VA_ARGS__); } while (0)
#define log_info(format, ...) do { if (logger_attached) log_info_internal(format, __VA_ARGS__); } while (0)
#define log_warning(format, ...) do { if (logger_attached) log_warning_internal(format, __VA_ARGS__); } while (0)
#define log_error(format, ...) do { if (logger_attached) log_error_internal(format, __VA_ARGS__); } while (0)
