#include "log.h"

#include <Windows.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef _DEBUG

static FILE *debug_file;

void log_init()
{
	fopen_s(&debug_file, "flinux.log", "w");
}

void log_shutdown()
{
	fclose(debug_file);
}

void log_debug(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(debug_file, format, ap);
	fflush(debug_file);
}
#endif
