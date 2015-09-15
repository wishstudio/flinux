#include "utf8.h"

/* Grab low "bits" bits of x */
#define LOWBITS(x, bits) ((x) & ((1 << ((bits) + 1)) - 1))

int utf8_get_sequence_len(char ch)
{
	if ((ch & 0x80) == 0)
		return 1;
	else if ((ch & 0xE0) == 0xC0)
		return 2;
	else if ((ch & 0xF0) == 0xE0)
		return 3;
	else if ((ch & 0xF8) == 0xF0)
		return 4;
	else
		return -1;
}

uint32_t utf8_decode(const char *data)
{
	if ((data[0] & 0x80) == 0)
		return (uint32_t)data[0];
	else if ((data[0] & 0xE0) == 0xC0)
		return (uint32_t)(LOWBITS(data[0], 5) << 6) + LOWBITS(data[1], 6);
	else if ((data[0] & 0xF0) == 0xE0)
		return (uint32_t)(LOWBITS(data[0], 4) << 12) + (LOWBITS(data[1], 6) << 6) + LOWBITS(data[2], 6);
	else if ((data[0] & 0xF8) == 0xF0)
		return (uint32_t)(LOWBITS(data[0], 3) << 18) + (LOWBITS(data[1], 6) << 12) + (LOWBITS(data[2], 6) << 6) + LOWBITS(data[3], 6);
	else
		return -1;
}

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