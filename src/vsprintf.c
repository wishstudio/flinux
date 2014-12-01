#include <vsprintf.h>

#include <stdint.h>

static const char *lowercase = "0123456789abcdef";
static const char *uppercase = "0123456789ABCDEF";

#define IS_SIGNED(type) \
	((type)-1 < (type)0)

#define PRINT_NUM(buf, x, type, utype, base, ch, width, fillchar) \
	do											\
	{											\
		int b = (base);							\
		char nbuf[128];							\
		type y = (x);							\
		int sign = 0;							\
		if (IS_SIGNED(type) && y < 0)			\
		{										\
			sign = 1;							\
			y = -y;								\
		}										\
		utype z = (utype)y;						\
		int len = 0;							\
		if (y == 0)								\
			nbuf[len++] = '0';					\
		else									\
		{										\
			while (y > 0)						\
			{									\
				nbuf[len++] = ch[y % b];		\
				y /= b;							\
			}									\
		}										\
		if (sign)								\
			nbuf[len++] = '-';					\
		int w = (width) - len;					\
		while (w-- > 0)							\
			*buf++ = fillchar;					\
		while (len--)							\
			*buf++ = nbuf[len];					\
	} while (0)

int kvsprintf(char *buffer, const char *format, va_list args)
{
	char *buf = buffer;
	while (*format)
	{
		if (*format == '%')
		{
			const char *f = format + 1;
			switch (*f++)
			{
			case '%':
				*buf++ = '%';
				continue;

			case 's':
			{
				format = f;
				const char *ch = va_arg(args, const char *);
				while (*ch)
					*buf++ = *ch++;
				continue;
			}

			case 'd':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, int32_t), int32_t, uint32_t, 10, lowercase, 0, ' ');
				continue;
			}

			case 'u':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, uint32_t), uint32_t, uint32_t, 10, lowercase, 0, ' ');
				continue;
			}

			case 'x':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, uint32_t), uint32_t, uint32_t, 16, lowercase, 0, ' ');
				continue;
			}

			case 'X':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, uint32_t), uint32_t, uint32_t, 16, uppercase, 0, ' ');
				continue;
			}

			case 'l':
			{
				if (f[0] == 'l' && f[1] == 'x')
				{
					format = f + 2;
					PRINT_NUM(buf, va_arg(args, uint64_t), uint64_t, uint64_t, 16, lowercase, 0, ' ');
					continue;
				}
			}

			case 'p':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, uintptr_t), uintptr_t, uintptr_t, 16, lowercase, sizeof(void *) * 2, '0');
				continue;
			}
			}
		}
		*buf++ = *format++;
	}
	return (int)(buf - buffer);
}
