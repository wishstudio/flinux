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

#include <common/types.h>
#include <log.h>
#include <vsprintf.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdarg.h>

int logger_attached;
static HANDLE hLoggerPipe;
static char buffer[1024];

#define PROTOCOL_VERSION	1
#define PROTOCOL_MAGIC		'flog'
struct request
{
	uint32_t magic;
	uint32_t version;
	uint32_t pid;
	uint32_t tid;
};

void log_init()
{
	LPCWSTR pipeName = L"\\\\.\\pipe\\flog_server";
	for (;;)
	{
		hLoggerPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hLoggerPipe == INVALID_HANDLE_VALUE)
		{
			/* Non critical error code, just wait and try connecting again */
			if (GetLastError() != ERROR_PIPE_BUSY || !WaitNamedPipeW(pipeName, NMPWAIT_WAIT_FOREVER))
			{
				logger_attached = 0;
				break;
			}
			continue;
		}
		/* Send initial request */
		struct request request;
		request.magic = PROTOCOL_MAGIC;
		request.version = PROTOCOL_VERSION;
		request.pid = GetProcessId(GetCurrentProcess());
		request.tid = GetThreadId(GetCurrentThread());
		DWORD written;
		if (!WriteFile(hLoggerPipe, &request, sizeof(request), &written, NULL))
		{
			CloseHandle(hLoggerPipe);
			logger_attached = 0;
		}
		else
			logger_attached = 1;
		break;
	}
}

void log_shutdown()
{
	if (logger_attached)
		CloseHandle(hLoggerPipe);
}

void log_raw_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int size = kvsprintf(buffer, format, ap);
	DWORD bytes_written;
	if (!WriteFile(hLoggerPipe, buffer, size, &bytes_written, NULL))
	{
		CloseHandle(hLoggerPipe);
		logger_attached = 0;
	}
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
	if (!WriteFile(hLoggerPipe, buffer, size, &bytes_written, NULL))
	{
		CloseHandle(hLoggerPipe);
		logger_attached = 0;
	}
}

void log_debug_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal('D', format, ap);
}

void log_info_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal('I', format, ap);
}

void log_warning_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal('W', format, ap);
}

void log_error_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal('E', format, ap);
}
