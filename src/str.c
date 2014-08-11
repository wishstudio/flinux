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

/* Grab low "bits" bits of x */
#define LOWBITS(x, bits) ((x) & ((1 << ((bits) + 1)) - 1))
int utf8_to_utf16(const char *data, int srclen, uint16_t *outdata, int dstlen)
{
	/* TODO: Handle invalid sequence */
	int outlen = 0;
	for (int i = 0; i < srclen;)
	{
		uint32_t codepoint = 0;
		if ((data[i] & 0xF8) == 0xF0) // 11110xxx
		{
			codepoint += LOWBITS(data[i++], 3) << 18;
			codepoint += LOWBITS(data[i++], 6) << 12;
			codepoint += LOWBITS(data[i++], 6) << 6;
			codepoint += LOWBITS(data[i++], 6);
		}
		else if ((data[i] & 0xF0) == 0xE0) // 1110xxxx
		{
			codepoint += LOWBITS(data[i++], 4) << 12;
			codepoint += LOWBITS(data[i++], 6) << 6;
			codepoint += LOWBITS(data[i++], 6);
		}
		else if ((data[i] & 0xE0) == 0xC0) // 110xxxxx
		{
			codepoint += LOWBITS(data[i++], 5) << 6;
			codepoint += LOWBITS(data[i++], 6);
		}
		else // 0xxxxxxx
			codepoint += data[i++];
		if (outdata)
		{
			if (codepoint <= 0xFFFF && outlen + 1 <= dstlen)
				outdata[outlen++] = codepoint;
			else if (outlen + 2 <= dstlen)
			{
				outdata[outlen++] = 0xD800 + ((codepoint - 0x10000) >> 10);
				outdata[outlen++] = 0xDC00 + ((codepoint - 0x10000) & 0x3FF);
			}
		}
		else if (codepoint <= 0xFFFF)
			outlen += 1;
		else
			outlen += 2;
	}
	return outlen;
}

int utf16_to_utf8(const uint16_t *data, int srclen, char *outdata, int dstlen)
{
	/* TODO: Handle invalid sequence */
	int outlen = 0;
	for (int i = 0; i < srclen;)
	{
		uint32_t codepoint;
		if (data[i] >= 0xD800 && data[i] <= 0xDFFF)
		{
			codepoint = 0x10000;
			codepoint += (data[i++] - 0xD800) << 10;
			codepoint += data[i++] - 0xDC00;
		}
		else
			codepoint = data[i++];
		if (outdata)
		{
			if (codepoint <= 0x7F && outlen + 1 <= dstlen)
				outdata[outlen++] = codepoint;
			else if (codepoint <= 0x07FF && outlen + 2 <= dstlen)
			{
				outdata[outlen++] = 0x80000000 | (codepoint & 0x3F);
				outdata[outlen++] = 0xC0000000 | (codepoint >> 6);
			}
			else if (codepoint <= 0xFFFF && outlen + 3 <= dstlen)
			{
				outdata[outlen++] = 0x80000000 | (codepoint & 0x3F);
				outdata[outlen++] = 0x80000000 | ((codepoint >> 6) & 0x3F);
				outdata[outlen++] = 0xE0000000 | (codepoint >> 12);
			}
			else if (outlen + 4 <= dstlen) /* <= 0x10FFFF */
			{
				outdata[outlen++] = 0x80000000 | (codepoint & 0x3F);
				outdata[outlen++] = 0x80000000 | ((codepoint >> 6) & 0x3F);
				outdata[outlen++] = 0x80000000 | ((codepoint >> 12) & 0x3F);
				outdata[outlen++] = 0xF0000000 | (codepoint >> 18);
			}
		}
		else if (codepoint <= 0x7F)
			outlen += 1;
		else if (codepoint <= 0x07FF)
			outlen += 2;
		else if (codepoint <= 0xFFFF)
			outlen += 3;
		else /* <= 0x10FFFF */
			outlen += 4;
	}
	return outlen;
}
