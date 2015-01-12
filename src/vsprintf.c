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
			char fillchar = ' ';
			if (*f == '0')
			{
				fillchar = '0';
				f++;
			}
			int width = 0;
			if (*f >= '1' && *f <= '9')
			{
				while (*f >= '0' && *f <= '9')
					width = width * 10 + (*f++ - '0');
			}
			switch (*f++)
			{
			case '%':
				format = f;
				*buf++ = '%';
				continue;

			case 'c':
			{
				format = f;
				*buf++ = va_arg(args, const char *);
				continue;
			}

			case 's':
			{
				format = f;
				const char *ch = va_arg(args, const char *);
				if (!ch)
					continue;
				while (*ch)
					*buf++ = *ch++;
				continue;
			}

			case 'd':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, int32_t), int32_t, uint32_t, 10, lowercase, width, fillchar);
				continue;
			}

			case 'u':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, uint32_t), uint32_t, uint32_t, 10, lowercase, width, fillchar);
				continue;
			}

			case 'x':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, uint32_t), uint32_t, uint32_t, 16, lowercase, width, fillchar);
				continue;
			}

			case 'X':
			{
				format = f;
				PRINT_NUM(buf, va_arg(args, uint32_t), uint32_t, uint32_t, 16, uppercase, width, fillchar);
				continue;
			}

			case 'l':
			{
				if (f[0] == 'l' && f[1] == 'x')
				{
					format = f + 2;
					PRINT_NUM(buf, va_arg(args, uint64_t), uint64_t, uint64_t, 16, lowercase, width, fillchar);
					continue;
				}
				if (f[0] == 'l' && f[1] == 'd')
				{
					format = f + 2;
					PRINT_NUM(buf, va_arg(args, int64_t), int64_t, uint64_t, 10, lowercase, width, fillchar);
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
