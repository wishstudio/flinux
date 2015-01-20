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

#include <log.h>
#include <vsprintf.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdarg.h>

#ifdef _DEBUG

#define BUFFER_SIZE 1024
static HANDLE hFile;
static char buffer[BUFFER_SIZE];

void log_init()
{
	char filename[13] = "flinux-?.log";
	for (char i = '0'; i <= '9'; i++)
	{
		filename[7] = i;
		hFile = CreateFileA(filename, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
			break;
	}
}

void log_shutdown()
{
	CloseHandle(hFile);
}

void log_raw(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int size = kvsprintf(buffer, format, ap);
	DWORD bytes_written;
	WriteFile(hFile, buffer, size, &bytes_written, NULL);
}

static void log_internal(char *type, const char *format, va_list ap)
{
	buffer[0] = '(';
	buffer[1] = type;
	buffer[2] = type;
	buffer[3] = ')';
	buffer[4] = ' ';
	int size = 5 + kvsprintf(buffer + 5, format, ap);
	DWORD bytes_written;
	WriteFile(hFile, buffer, size, &bytes_written, NULL);
}

void log_debug(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal('D', format, ap);
}

void log_info(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal('I', format, ap);
}

void log_warning(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal('W', format, ap);
}

void log_error(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal('E', format, ap);
}

#endif
