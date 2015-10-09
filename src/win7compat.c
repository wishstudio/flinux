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

#include <win7compat.h>
#include <ntdll.h>

typedef ULONGLONG (NTAPI RtlGetSystemTimePrecise_t)();
static RtlGetSystemTimePrecise_t *pfnRtlGetSystemTimePrecise;

void win7compat_GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimePreciseAsFileTime)
{
	if (pfnRtlGetSystemTimePrecise)
	{
		ULONGLONG result = pfnRtlGetSystemTimePrecise();
		lpSystemTimePreciseAsFileTime->dwLowDateTime = result & 0xFFFFFFFFULL;
		lpSystemTimePreciseAsFileTime->dwHighDateTime = result >> 32ULL;
	}
	else
		GetSystemTimeAsFileTime(lpSystemTimePreciseAsFileTime);
}

void win7compat_init()
{
	HANDLE ntdll_handle;
	UNICODE_STRING module_file_name;
	RtlInitUnicodeString(&module_file_name, L"ntdll.dll");
	NTSTATUS status = LdrLoadDll(NULL, 0, &module_file_name, &ntdll_handle);
	if (!NT_SUCCESS(status))
		return;
	ANSI_STRING function_name;
	RtlInitAnsiString(&function_name, "RtlGetSystemTimePrecise");
	LdrGetProcedureAddress(ntdll_handle, &function_name, 0, (PVOID *)&pfnRtlGetSystemTimePrecise);
}
