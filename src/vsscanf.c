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

#include <vsscanf.h>

#include <stdbool.h>
#include <stdint.h>

static int kisspace(unsigned char ch)
{
	return ch == ' ' || ch == '\f' || ch == '\n' || ch == '\r' || ch == '\t' || ch == '\v';
}

#define IS_SIGNED(type) \
	((type)-1 < (type)0)

#define PARSE_NUM(buf, out, type, utype) \
	do													\
	{													\
		utype value = 0;								\
		bool neg = false;								\
		if (IS_SIGNED(type) & *buf == '-')				\
		{												\
			neg = true;									\
			buf++;										\
		}												\
		if (!(*buf >= '0' && *buf <= '9'))				\
			return count;								\
		while (*buf >= '0' && *buf <= '9')				\
		{												\
			utype v = value * 10 + *buf - '0';			\
			if (v < value)								\
				return count;							\
			value = v;									\
			buf++;										\
		}												\
		if (neg)										\
		{												\
			if ((type)value < 0 && -(type)value != 0)	\
				return count;							\
			*out = -(type)value;						\
		}												\
		else if (IS_SIGNED(type))						\
		{												\
			if ((type)value < 0)						\
				return count;							\
			*out = (type)value;							\
		}												\
		else											\
			*out = value;								\
		count++;										\
	} while (false)

int kvsscanf(const char *buffer, const char *format, va_list args)
{
	const char *buf = buffer;
	int count = 0;
	while (*format)
	{
		if (kisspace(*format))
		{
			while (kisspace(*buf))
				buf++;
		}
		else if (*format == '%')
		{
			format++;
			switch (*format++)
			{
			case '%':
			{
				if (*buffer++ != '%')
					return count;
			}

			case 'n':
			{
				int *out = va_arg(args, int *);
				*out = buf - buffer;
			}

			case 'd':
			{
				int32_t *out = va_arg(args, int32_t *);
				PARSE_NUM(buf, out, int32_t, uint32_t);
			}

			case 'u':
			{
				uint32_t *out = va_arg(args, uint32_t *);
				PARSE_NUM(buf, out, uint32_t, uint32_t);
			}
			}
		}
		else
		{
			if (*buffer++ != *format++)
				break;
		}
	}
	return count;
}
