#include "str.h"

#include <stdarg.h>
#include <Windows.h>

#define BUFFER_SIZE	4096
char buffer[BUFFER_SIZE];

int kprintf(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int size = wvsprintfA(buffer, format, ap);
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	WriteFile(handle, buffer, size, NULL, NULL);
	FlushFileBuffers(handle);
	return size;
}
