#include <str.h>
#include <vsprintf.h>

#include <stdarg.h>
#include <Windows.h>

#define BUFFER_SIZE	4096
char buffer[BUFFER_SIZE];

int kprintf(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int size = kvsprintf(buffer, format, ap);
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	WriteFile(handle, buffer, size, NULL, NULL);
	FlushFileBuffers(handle);
	return size;
}

/*
Some characters can not be used on Windows as part of file names, such as
" * : < > ? |. But they are valid in Linux and unfortunately people really
do use them in filenames.
We map these characters to Unicode private use area in the U+00F0xx range.
This is compatible with the Cygwin scheme.
*/
static const uint16_t filename_transform_chars[] =
{
	0, 0xf000 | 1, 0xf000 | 2, 0xf000 | 3,
	0xf000 | 4, 0xf000 | 5, 0xf000 | 6, 0xf000 | 7,
	0xf000 | 8, 0xf000 | 9, 0xf000 | 10, 0xf000 | 11,
	0xf000 | 12, 0xf000 | 13, 0xf000 | 14, 0xf000 | 15,
	0xf000 | 16, 0xf000 | 17, 0xf000 | 18, 0xf000 | 19,
	0xf000 | 20, 0xf000 | 21, 0xf000 | 22, 0xf000 | 23,
	0xf000 | 24, 0xf000 | 25, 0xf000 | 26, 0xf000 | 27,
	0xf000 | 28, 0xf000 | 29, 0xf000 | 30, 0xf000 | 31,
	' ', '!', 0xf000 | '"', '#',
	'$', '%', '&', 39,
	'(', ')', 0xf000 | '*', '+',
	',', '-', '.', '\\',
	'0', '1', '2', '3',
	'4', '5', '6', '7',
	'8', '9', 0xf000 | ':', ';',
	0xf000 | '<', '=', 0xf000 | '>', 0xf000 | '?',
	'@', 'A', 'B', 'C',
	'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K',
	'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S',
	'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', '[',
	'\\', ']', '^', '_',
	'`', 'a', 'b', 'c',
	'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k',
	'l', 'm', 'n', 'o',
	'p', 'q', 'r', 's',
	't', 'u', 'v', 'w',
	'x', 'y', 'z', '{',
	0xf000 | '|', '}', '~', 127
};

/* Grab low "bits" bits of x */
#define LOWBITS(x, bits) ((x) & ((1 << ((bits) + 1)) - 1))

static __forceinline uint32_t utf8_read_increment(const char **data, const char *last)
{
	if ((**data & 0x80) == 0 && *data + 1 <= last) // 0xxxxxxx
		return *(*data)++;
	else if ((**data & 0xE0) == 0xC0 && *data + 2 <= last) // 110xxxxx
	{
		uint32_t codepoint = 0;
		codepoint += LOWBITS(*(*data)++, 5) << 6;
		codepoint += LOWBITS(*(*data)++, 6);
		return codepoint;
	}
	else if ((**data & 0xF0) == 0xE0 && *data + 3 <= last) // 1110xxxx
	{
		uint32_t codepoint = 0;
		codepoint += LOWBITS(*(*data)++, 4) << 12;
		codepoint += LOWBITS(*(*data)++, 6) << 6;
		codepoint += LOWBITS(*(*data)++, 6);
		return codepoint;
	}
	else if ((**data & 0xF8) == 0xF0 && *data + 4 <= last) // 11110xxx
	{
		uint32_t codepoint = 0;
		codepoint += LOWBITS(*(*data)++, 3) << 18;
		codepoint += LOWBITS(*(*data)++, 6) << 12;
		codepoint += LOWBITS(*(*data)++, 6) << 6;
		codepoint += LOWBITS(*(*data)++, 6);
		return 0;
	}
	else
		return -1;
}

static __forceinline int utf8_write_increment(uint32_t codepoint, char **out, const char *outlast)
{
	if (codepoint <= 0x7F && *out + 1 <= outlast)
	{
		*(*out)++ = codepoint;
		return 1;
	}
	else if (codepoint <= 0x07FF && *out + 2 <= outlast)
	{
		*(*out)++ = 0xC0 | (codepoint >> 6);
		*(*out)++ = 0x80 | (codepoint & 0x3F);
		return 2;
	}
	else if (codepoint <= 0xFFFF && *out + 3 <= outlast)
	{
		*(*out)++ = 0xE0 | (codepoint >> 12);
		*(*out)++ = 0x80 | ((codepoint >> 6) & 0x3F);
		*(*out)++ = 0x80 | (codepoint & 0x3F);
		return 3;
	}
	else if (*out + 4 <= outlast) /* <= 0x10FFFF */
	{
		*(*out)++ = 0xF0 | (codepoint >> 18);
		*(*out)++ = 0x80 | ((codepoint >> 12) & 0x3F);
		*(*out)++ = 0x80 | ((codepoint >> 6) & 0x3F);
		*(*out)++ = 0x80 | (codepoint & 0x3F);
		return 4;
	}
	else
		return 0;
}

static __forceinline int utf8_count_len(uint32_t codepoint)
{
	if (codepoint <= 0x7F)
		return 1;
	else if (codepoint <= 0x07FF)
		return 2;
	else if (codepoint <= 0xFFFF)
		return 3;
	else /* <= 0x10FFFF */
		return 4;
}

static __forceinline uint32_t utf16_read_increment(const uint16_t **data, const uint16_t *last)
{
	if (*data + 1 <= last && (**data < 0xD800 || **data >= 0xE000))
		return *(*data)++;
	else if (*data + 2 <= last && 0[*data] >= 0xD800 && 0[*data] <= 0xDBFF && 1[*data] >= 0xDC00 && 1[*data] <= 0xDFFF)
	{
		uint32_t codepoint = 0x10000;
		codepoint += (0[*data] - 0xD800) << 10;
		codepoint += 1[*data] - 0xDC00;
		*data += 2;
		return codepoint;
	}
	else
		return -1;
}

static __forceinline int utf16_write_increment(uint32_t codepoint, uint16_t **out, const uint16_t *outlast)
{
	if (codepoint <= 0xFFFF && *out + 1 <= outlast)
	{
		*(*out)++ = codepoint;
		return 1;
	}
	else if (*out + 2 <= outlast)
	{
		*(*out)++ = 0xD800 + ((codepoint - 0x10000) >> 10);
		*(*out)++ = 0xDC00 + ((codepoint - 0x10000) & 0x3FF);
		return 2;
	}
	else
		return -1;
}

static __forceinline int utf16_count_len(uint32_t codepoint)
{
	if (codepoint <= 0xFFFF)
		return 1;
	else
		return 2;
}

int utf8_to_utf16(const char *data, int srclen, uint16_t *outdata, int dstlen)
{
	const char *last = data + srclen;
	const uint16_t *outlast = outdata + dstlen;
	int outlen = 0;
	if (outdata)
	{
		while (data < last)
		{
			uint32_t codepoint = utf8_read_increment(&data, last);
			if (codepoint == -1)
				return -1;
			int r = utf16_write_increment(codepoint, &outdata, outlast);
			if (r < 0)
				return -1;
			outlen += r;
		}
	}
	else
	{
		while (data < last)
		{
			uint32_t codepoint = utf8_read_increment(&data, last);
			if (codepoint == -1)
				return -1;
			outlen += utf16_count_len(codepoint);
		}
	}
	return outlen;
}

int utf8_to_utf16_filename(const char *data, int srclen, uint16_t *outdata, int dstlen)
{
	const char *last = data + srclen;
	const uint16_t *outlast = outdata + dstlen;
	int outlen = 0;
	if (outdata)
	{
		while (data < last)
		{
			uint32_t codepoint = utf8_read_increment(&data, last);
			if (codepoint == -1)
				return -1;
			if (codepoint <= 0x80)
				codepoint = filename_transform_chars[codepoint];
			int r = utf16_write_increment(codepoint, &outdata, outlast);
			if (r < 0)
				return -1;
			outlen += r;
		}
	}
	else
	{
		while (data < last)
		{
			uint32_t codepoint = utf8_read_increment(&data, last);
			if (codepoint == -1)
				return -1;
			if (codepoint <= 0x80)
				codepoint = filename_transform_chars[codepoint];
			outlen += utf16_count_len(codepoint);
		}
	}
	return outlen;
}

int utf16_to_utf8(const uint16_t *data, int srclen, char *outdata, int dstlen)
{
	const uint16_t *last = data + srclen;
	const char *outlast = outdata + dstlen;
	int outlen = 0;
	if (outdata)
	{
		while (data < last)
		{
			uint32_t codepoint = utf16_read_increment(&data, last);
			if (codepoint == -1)
				return -1;
			int r = utf8_write_increment(codepoint, &outdata, outlast);
			if (r < 0)
				return -1;
			outlen += r;
		}
	}
	else
	{
		while (data < last)
		{
			uint32_t codepoint = utf16_read_increment(&data, last);
			if (codepoint == -1)
				return -1;
			outlen += utf8_count_len(codepoint);
		}
	}
	return outlen;
}

int utf16_to_utf8_filename(const uint16_t *data, int srclen, char *outdata, int dstlen)
{
	const uint16_t *last = data + srclen;
	const char *outlast = outdata + dstlen;
	int outlen = 0;
	if (outdata)
	{
		while (data < last)
		{
			uint32_t codepoint = utf16_read_increment(&data, last);
			if (codepoint == -1)
				return -1;
			if (filename_transform_chars[codepoint & 0x7F] == codepoint)
				codepoint &= 0x7F;
			int r = utf8_write_increment(codepoint, &outdata, outlast);
			if (r < 0)
				return -1;
			outlen += r;
		}
	}
	else
	{
		while (data < last)
		{
			uint32_t codepoint = utf16_read_increment(&data, last);
			if (codepoint == -1)
				return -1;
			if (filename_transform_chars[codepoint & 0x7F] == codepoint)
				codepoint &= 0x7F;
			outlen += utf8_count_len(codepoint);
		}
	}
	return outlen;
}
