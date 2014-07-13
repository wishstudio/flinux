#include "log.h"

#include <Windows.h>
#include <stdarg.h>

#ifdef _DEBUG

#define BUFFER_SIZE 1024
static HANDLE hFile;
static char buffer[BUFFER_SIZE];

void log_init()
{
	hFile = CreateFile("flinux.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void log_shutdown()
{
	CloseHandle(hFile);
}

void log_debug(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int size = vsprintf_s(buffer, BUFFER_SIZE, format, ap);
	WriteFile(hFile, buffer, size, NULL, NULL);
	FlushFileBuffers(hFile);
}
#endif
