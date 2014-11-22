#include <log.h>

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
	int size = wvsprintfA(buffer, format, ap);
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
	int size = 5 + wvsprintfA(buffer + 5, format, ap);
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
