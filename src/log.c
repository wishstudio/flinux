#include "log.h"

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
		hFile = CreateFileA(filename, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
			break;
	}
}

void log_shutdown()
{
	CloseHandle(hFile);
}

void log_debug(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int size = wvsprintfA(buffer, format, ap);
	WriteFile(hFile, buffer, size, NULL, NULL);
	FlushFileBuffers(hFile);
}
#endif
