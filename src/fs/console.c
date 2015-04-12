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

#include <common/errno.h>
#include <common/fcntl.h>
#include <common/ioctls.h>
#include <common/poll.h>
#include <common/termios.h>
#include <fs/console.h>
#include <syscall/mm.h>
#include <syscall/sig.h>
#include <heap.h>
#include <log.h>
#include <str.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ntdll.h>
#include <malloc.h>

/* xterm like VT terminal emulation on Win32 console
 *
 * Because things like scrolling region information is completely emulated, data
 * must be shared across all processes in the same console. We then use mutexes
 * to ensure the shared region is modifiable to only one process at one time.
 *
 * The basic assumption is that no other Win32 console applications are writing
 * to the same console simultaneously. The only thing we need to take care of is
 * when user changes the size of the window during application operation.
 */

#define CONSOLE_MAX_PARAMS	16
#define MAX_INPUT			256
#define MAX_CANON			256
#define MAX_STRING			256
#define DEFAULT_ATTRIBUTE	0

typedef uint32_t (*charset_func)(uint32_t ch);
struct console_cursor /* DECSC */
{
	int x, y;
	int at_right_margin;
	int bright, reverse, foreground, background;
	int charset;
	int origin_mode;
	int wraparound_mode;
};
struct console_data
{
	HANDLE section, mutex;
	HANDLE in, out;
	HANDLE normal_buffer, alternate_buffer;
	/* console mode settings */
	struct termios termios;
	int bright, reverse, foreground, background;
	charset_func g0_charset, g1_charset;
	int charset;
	int insert_mode;
	int cursor_key_mode;
	int origin_mode;
	int wraparound_mode;

	/* Based on our assumption, these values are not modifiable by other processes
	 * during a console operation.
	 * We'll need only read these values once in one operation
	 */
	int x, y; /* current position, in window coordinate */
	int at_right_margin; /* whether we are at the right margin, i.e. the invisible column after the rightmost */
	WORD attr; /* text attribute */
	int width, height; /* current size of the console window */
	int buffer_height; /* current height of the screen buffer */
	int top; /* the row number of current emulated top line in buffer coordinate */
	int scroll_top, scroll_bottom; /* the row numbers of the margins of the scroll region */
	int scroll_full_screen; /* whether the scrolling region is the full screen */
	char utf8_buf[4]; /* for storing unfinished utf-8 character */
	int utf8_buf_size;
	struct console_cursor saved_cursor;
	int saved_top;

	/* escape sequence processor */
	int params[CONSOLE_MAX_PARAMS];
	int param_count;
	int string_len;
	char string_buffer[MAX_STRING];
	char input_buffer[MAX_INPUT];
	size_t input_buffer_head, input_buffer_tail;
	char csi_prefix; /* prefix after CSI, e.g. '?', '>' */
	void (*processor)(char ch);
};

static struct console_data *const console = (struct console_data *)CONSOLE_DATA_BASE;

static uint32_t default_charset(uint32_t ch)
{
	return ch;
}

static uint32_t dec_special_graphics_charset(uint32_t ch)
{
	static const uint32_t table[32] = {
		0x2666, 0x2591, 0x0000, 0x0000, 0x0000, 0x0000, 0x00B0, 0x00B1,
		0x0000, 0x0000, 0x2518, 0x2510, 0x250C, 0x2514, 0x253C, 0x23BA,
		0x23BB, 0x2500, 0x23BC, 0x23BD, 0x251C, 0x2524, 0x2534, 0x252C,
		0x2502, 0x2264, 0x2265, 0x03C0, 0x2260, 0x00A3, 0x00B7, 0x00FF,
	};
	if (ch >= 0x60 && ch <= 0x7F)
		return table[ch - 0x60];
	else
		return ch;
}

static charset_func parse_charset(char ch)
{
	switch (ch)
	{
	case '0': return dec_special_graphics_charset;
	case 'B': return default_charset;
	default: return NULL;
	}
}

static BOOL WINAPI console_ctrlc_handler(DWORD dwCtrlType)
{
	if (dwCtrlType != CTRL_C_EVENT)
		return FALSE;
	struct siginfo info;
	info.si_signo = SIGINT;
	info.si_code = 0;
	info.si_errno = 0;
	signal_kill(GetCurrentProcessId(), &info);
	return TRUE;
}

static void save_cursor();
void console_init()
{
	log_info("Initializing console shared memory region.\n");
	/* TODO: mm_mmap() does not support MAP_SHARED yet */
	HANDLE section;
	LARGE_INTEGER section_size;
	section_size.QuadPart = sizeof(struct console_data);
	OBJECT_ATTRIBUTES obj_attr;
	obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);
	obj_attr.RootDirectory = NULL;
	obj_attr.ObjectName = NULL;
	obj_attr.Attributes = OBJ_INHERIT;
	obj_attr.SecurityDescriptor = NULL;
	obj_attr.SecurityQualityOfService = NULL;
	NTSTATUS status;
	status = NtCreateSection(&section, SECTION_MAP_READ | SECTION_MAP_WRITE, &obj_attr, &section_size, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		log_error("NtCreateSection() failed, status: %x\n", status);
		return;
	}
	PVOID base_addr = console;
	SIZE_T view_size = sizeof(struct console_data);
	status = NtMapViewOfSection(section, NtCurrentProcess(), &base_addr, 0, sizeof(struct console_data), NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		log_error("NtMapViewOfSection() failed, status: %x\n", status);
		return;
	}

	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.lpSecurityDescriptor = NULL;
	attr.bInheritHandle = TRUE;

	HANDLE mutex = CreateMutexW(&attr, FALSE, NULL);
	if (mutex == NULL)
	{
		log_error("CreateMutexW() failed, error code: %d\n", GetLastError());
		return;
	}

	HANDLE in = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (in == INVALID_HANDLE_VALUE)
	{
		log_error("CreateFile(\"CONIN$\") failed, error code: %d\n", GetLastError());
		return;
	}
	HANDLE out = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (out == INVALID_HANDLE_VALUE)
	{
		log_error("CreateFile(\"CONOUT$\") failed, error code: %d\n", GetLastError());
		return;
	}
	console->section = section;
	console->mutex = mutex;
	console->in = in;
	console->out = out;
	console->normal_buffer = out;
	console->alternate_buffer = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attr, CONSOLE_TEXTMODE_BUFFER, NULL);
	console->termios.c_iflag = INLCR | ICRNL;
	console->termios.c_oflag = ONLCR | OPOST;
	console->termios.c_cflag = CREAD | CSIZE | B38400;
	console->termios.c_lflag = ICANON | ECHO | ECHOCTL;
	memset(console->termios.c_cc, 0, sizeof(console->termios.c_cc));
	console->termios.c_cc[VINTR] = 3;
	console->termios.c_cc[VERASE] = 8;
	console->termios.c_cc[VEOF] = 4;
	console->termios.c_cc[VSUSP] = 26;

	console->bright = 0;
	console->reverse = 0;
	console->foreground = 7;
	console->background = 0;
	console->g0_charset = console->g1_charset = default_charset;
	console->charset = 0;
	console->insert_mode = 0;
	console->cursor_key_mode = 0;
	console->origin_mode = 0;
	console->wraparound_mode = 1;

	/* Only essential values are initialized here, others are automatically set to the correct value in console_retrieve_state() */
	console->at_right_margin = 0;
	console->top = 0;
	console->scroll_full_screen = 1;
	console->utf8_buf_size = 0;

	save_cursor();

	console->input_buffer_head = console->input_buffer_tail = 0;
	console->processor = NULL;

	SetConsoleMode(in, ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT);
	SetConsoleMode(out, ENABLE_PROCESSED_OUTPUT);
	SetConsoleCtrlHandler(console_ctrlc_handler, TRUE);

	log_info("Console shared memory region successfully initialized.\n");
}

int console_fork(HANDLE process)
{
	log_info("Mapping console shared memory region to child process...\n");
	PVOID base_addr = console;
	SIZE_T view_size = sizeof(struct console_data);
	NTSTATUS status;
	status = NtMapViewOfSection(console->section, process, &base_addr, 0, sizeof(struct console_data), NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		log_error("NtMapViewOfSection() failed, status: %x\n", status);
		return 0;
	}
	return 1;
}

void console_afterfork()
{
	SetConsoleCtrlHandler(console_ctrlc_handler, TRUE);
}

static void console_lock()
{
	WaitForSingleObject(console->mutex, INFINITE);
}

static void console_unlock()
{
	ReleaseMutex(console->mutex);
}

struct console_file
{
	struct file base_file;
};

static WORD get_text_attribute()
{
	WORD attr = 0;
	if (console->bright)
		attr |= FOREGROUND_INTENSITY;
	switch (console->reverse ? console->background : console->foreground)
	{
	case 0: /* Black */
		break;

	case 1: /* Red */
		attr |= FOREGROUND_RED;
		break;

	case 2: /* Green */
		attr |= FOREGROUND_GREEN;
		break;

	case 3: /* Yellow */
		attr |= FOREGROUND_RED | FOREGROUND_GREEN;
		break;

	case 4: /* Blue */
		attr |= FOREGROUND_BLUE;
		break;

	case 5: /* Magenta */
		attr |= FOREGROUND_RED | FOREGROUND_BLUE;
		break;

	case 6: /* Cyan */
		attr |= FOREGROUND_GREEN | FOREGROUND_BLUE;
		break;

	case 7: /* White */
		attr |= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
		break;
	}
	switch (console->reverse ? console->foreground : console->background)
	{
	case 0: /* Black */
		break;

	case 1: /* Red */
		attr |= BACKGROUND_RED;
		break;

	case 2: /* Green */
		attr |= BACKGROUND_GREEN;
		break;

	case 3: /* Yellow */
		attr |= BACKGROUND_RED | BACKGROUND_GREEN;
		break;

	case 4: /* Blue */
		attr |= BACKGROUND_BLUE;
		break;

	case 5: /* Magenta */
		attr |= BACKGROUND_RED | BACKGROUND_BLUE;
		break;

	case 6: /* Cyan */
		attr |= BACKGROUND_GREEN | BACKGROUND_BLUE;
		break;

	case 7: /* White */

		attr |= BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE;
		break;
	}
	return attr;
}

static void console_retrieve_state()
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	int new_width = info.dwSize.X;
	int new_height = info.srWindow.Bottom - info.srWindow.Top + 1;
	if (console->width != new_width || console->height != new_height)
	{
		console->width = new_width;
		console->height = new_height;
		struct siginfo info;
		info.si_signo = SIGWINCH;
		info.si_code = 0;
		info.si_errno = 0;
		signal_kill(GetCurrentProcessId(), &info);
	}
	console->buffer_height = info.dwSize.Y;
	int top_min = max(0, info.dwCursorPosition.Y - console->height + 1);
	int top_max = min(info.dwCursorPosition.Y, console->buffer_height - console->height);
	if (console->top < top_min)
		console->top = top_min;
	if (console->top > top_max)
		console->top = top_max;
	if (console->x != info.dwCursorPosition.X || console->y + console->top != info.dwCursorPosition.Y)
	{
		/* The cursor position is changed by another unknown process
		 * Just re-retrieve the position, clear at margin flag,
		 * and bless it won't get in our way
		 */
		console->x = info.dwCursorPosition.X;
		console->y = info.dwCursorPosition.Y - console->top;
		console->at_right_margin = 0;
	}
	if (console->height <= console->scroll_bottom)
	{
		/* The current window height is smaller than the scrolling region,
		 * Change to full screen scrolling mode
		 */
		console->scroll_full_screen = 1;
	}
	if (console->scroll_full_screen)
	{
		console->scroll_top = 0;
		console->scroll_bottom = console->height - 1;
	}
}

static void backspace(BOOL erase)
{
	if (console->x > 0)
	{
		console->at_right_margin = 0;
		console->x--;
		COORD pos;
		pos.X = console->x;
		pos.Y = console->y + console->top;
		if (erase && console->x)
		{
			DWORD bytes_written;
			WriteConsoleOutputCharacterA(console->out, " ", 1, pos, &bytes_written);
		}
		SetConsoleCursorPosition(console->out, pos);
	}
}

static void set_pos(int x, int y)
{
	COORD pos;
	pos.X = x;
	pos.Y = y + console->top;
	SetConsoleCursorPosition(console->out, pos);
	console->x = x;
	console->y = y;
	console->at_right_margin = 0;
}

static void console_set_size(int width, int height)
{
	console->top = min(console->top, console->buffer_height - height);
	COORD size;
	size.X = width;
	size.Y = console->buffer_height;
	SMALL_RECT rect;
	rect.Left = 0;
	rect.Right = width - 1;
	rect.Top = console->top;
	rect.Bottom = console->top + height - 1;

	if (width > console->width)
	{
		/* Enlarge buffer then window */
		SetConsoleScreenBufferSize(console->out, size);
		SetConsoleWindowInfo(console->out, TRUE, &rect);
	}
	else
	{
		/* Reduce window then buffer */
		SetConsoleWindowInfo(console->out, TRUE, &rect);
		SetConsoleScreenBufferSize(console->out, size);
	}
	set_pos(console->x, console->y);
	console->width = width;
	console->height = height;
}

static void save_cursor()
{
	console->saved_cursor.x = console->x;
	console->saved_cursor.y = console->y;
	console->saved_cursor.at_right_margin = console->at_right_margin;
	console->saved_cursor.bright = console->bright;
	console->saved_cursor.reverse = console->reverse;
	console->saved_cursor.foreground = console->foreground;
	console->saved_cursor.background = console->background;
	console->saved_cursor.charset = console->charset;
	console->saved_cursor.origin_mode = console->origin_mode;
	console->saved_cursor.wraparound_mode = console->wraparound_mode;
	console->saved_top = console->top;
}

static void restore_cursor()
{
	console->x = console->saved_cursor.x;
	console->y = console->saved_cursor.y;
	console->at_right_margin = console->saved_cursor.at_right_margin;
	console->bright = console->saved_cursor.bright;
	console->reverse = console->saved_cursor.reverse;
	console->foreground = console->saved_cursor.foreground;
	console->background = console->saved_cursor.background;
	console->charset = console->saved_cursor.charset;
	console->origin_mode = console->saved_cursor.origin_mode;
	console->wraparound_mode = console->saved_cursor.wraparound_mode;

	console->top = console->saved_top;
	set_pos(console->x, console->y);

	SetConsoleTextAttribute(console->out, get_text_attribute());
}

static void switch_to_normal_buffer()
{
	console->out = console->normal_buffer;
	SetConsoleActiveScreenBuffer(console->out);
}

static void switch_to_alternate_buffer()
{
	console->out = console->alternate_buffer;
	SetConsoleActiveScreenBuffer(console->out);
}

static void move_left(int count)
{
	set_pos(max(console->x - count, 0), console->y);
}

static void move_right(int count)
{
	set_pos(min(console->x + count, console->width - 1), console->y);
}

static void move_up(int count)
{
	set_pos(console->x, max(console->y - count, 0));
}

static void move_down(int count)
{
	set_pos(console->x, min(console->y + count, console->height - 1));
}

static void erase_screen_lines(int top, int bottom)
{
	int len = (bottom - top + 1) * console->width;
	COORD pos;
	pos.X = 0;
	pos.Y = console->top + top;
	DWORD written;
	FillConsoleOutputAttribute(console->out, DEFAULT_ATTRIBUTE, len, pos, &written);
}

static void scroll(int left, int right, int top, int bottom, int xoffset, int yoffset)
{
	CHAR_INFO fill_char;
	fill_char.Attributes = DEFAULT_ATTRIBUTE;
	fill_char.Char.UnicodeChar = L' ';
	SMALL_RECT rect;
	rect.Left = left;
	rect.Right = right;
	rect.Top = console->top + top;
	rect.Bottom = console->top + bottom;
	COORD origin;
	origin.X = left + xoffset;
	origin.Y = console->top + top + yoffset;
	ScrollConsoleScreenBufferW(console->out, &rect, &rect, origin, &fill_char);
}

static BOOL is_inside_scroll_area()
{
	return console->y >= console->scroll_top && console->y <= console->scroll_bottom;
}

static void scroll_up(int count)
{
	scroll(0, console->width - 1, console->scroll_top, console->scroll_bottom, 0, -count);
}

static void scroll_down(int count)
{
	scroll(0, console->width - 1, console->scroll_top, console->scroll_bottom, 0, count);
}

static void cr()
{
	DWORD bytes_written;
	WriteConsoleA(console->out, "\r", 1, &bytes_written, NULL);
	console->x = 0;
	console->at_right_margin = 0;
}

static void nl()
{
	if (console->scroll_full_screen || console->y < console->scroll_bottom)
	{
		DWORD bytes_written;
		WriteConsoleA(console->out, "\n", 1, &bytes_written, NULL);
		if (console->y == console->height - 1)
		{
			/* The entire screen is scrolled */
			console->top = min(console->top + 1, console->buffer_height - console->height);
		}
		else
			console->y++;
	}
	else
		scroll_up(1);
	console->at_right_margin = 0;
}

static void crnl()
{
	cr();
	nl();
}

static void console_add_input(char *str, size_t size)
{
	/* TODO: Detect input buffer overflow */
	for (size_t i = 0; i < size; i++)
	{
		console->input_buffer[console->input_buffer_head] = str[i];
		console->input_buffer_head = (console->input_buffer_head + 1) % MAX_INPUT;
	}
}

static void write_normal(const char *buf, int size)
{
	if (size == 0)
		return;

	charset_func charset = console->charset == 0? console->g0_charset: console->g1_charset;
	WCHAR data[1024];
	int len = 0, displen = 0;
	int i = 0;
	while (i < size)
	{
		if (console->at_right_margin && console->wraparound_mode)
			crnl();
		/* Write to line end at most */
		int line_remain = min(size - i, console->width - console->x);
		len = 0;
		displen = 0;
		int seqlen = -1;
		while (displen < line_remain && i < size)
		{
			console->utf8_buf[console->utf8_buf_size++] = buf[i++];
			if (console->utf8_buf_size == 1)
				seqlen = utf8_get_sequence_len(console->utf8_buf[0]);
			if (seqlen < 0)
				console->utf8_buf_size = 0;
			if (seqlen == console->utf8_buf_size)
			{
				uint32_t codepoint = utf8_decode(console->utf8_buf);
				if (codepoint >= 0 && codepoint <= 0x10FFFF)
				{
					/* TODO: Handle non BMP characters (not supported by conhost) */
					int l = wcwidth(codepoint);
					if (l > 0)
					{
						if (displen + l > line_remain && console->wraparound_mode)
						{
							i--;
							console->utf8_buf_size--;
							break;
						}
						displen += l;
						data[len++] = charset(codepoint);
					}
				}
				console->utf8_buf_size = 0;
			}
		}

		if (console->insert_mode && console->x + displen < console->width)
			scroll(console->x, console->width - 1, console->y, console->y, displen, 0);
		
		DWORD chars_written;
		WriteConsoleW(console->out, data, len, &chars_written, NULL);
		console->x += displen;
		if (console->x == console->width)
		{
			console->x--;
			console->at_right_margin = 1;
		}
	}
}

#define ERASE_SCREEN_CUR_TO_END		0
#define ERASE_SCREEN_BEGIN_TO_CUR	1
#define ERASE_SCREEN_BEGIN_TO_END	2
static void erase_screen(int mode)
{
	COORD start;
	int count;
	if (mode == 0)
	{
		/* Erase current line to bottom */
		start.X = console->x;
		start.Y = console->y + console->top;
		count = (console->width - console->x + 1) + (console->height - console->y - 1) * console->width;
	}
	else if (mode == 1)
	{
		/* Erase top to current line */
		start.X = 0;
		start.Y = console->top;
		count = console->y * console->width + console->x + 1;
	}
	else if (mode == 2)
	{
		/* Erase entire screen */
		start.X = 0;
		start.Y = console->top;
		count = console->width * console->height;
	}
	else
	{
		log_error("erase_screen(): Invalid mode %d\n", mode);
		return;
	}
	DWORD num_written;
	FillConsoleOutputAttribute(console->out, get_text_attribute(console), count, start, &num_written);
	FillConsoleOutputCharacterW(console->out, L' ', count, start, &num_written);
}

#define ERASE_LINE_CUR_TO_END		0
#define ERASE_LINE_BEGIN_TO_CUR		1
#define ERASE_LINE_BEGIN_TO_END		2
static void erase_line(int mode)
{
	COORD start;
	start.Y = console->y + console->top;
	int count;
	if (mode == 0)
	{
		/* Erase to end */
		start.X = console->x;
		count = console->width - console->x;
	}
	else if (mode == 1)
	{
		/* Erase to begin */
		start.X = 0;
		count = console->x + 1;
	}
	else if (mode == 2)
	{
		/* Erase whole line */
		start.X = 0;
		count = console->width;
	}
	else
	{
		log_error("erase_line(): Invalid mode %d\n", mode);
		return;
	}
	DWORD num_written;
	FillConsoleOutputAttribute(console->out, get_text_attribute(console), count, start, &num_written);
	FillConsoleOutputCharacterW(console->out, L' ', count, start, &num_written);
}

static void insert_line(int count)
{
	if (is_inside_scroll_area())
		scroll(0, console->width - 1, console->y, console->scroll_bottom, 0, count);
}

static void delete_line(int count)
{
	if (is_inside_scroll_area())
		scroll(0, console->width - 1, console->y, console->scroll_bottom, 0, -count);
}

static void insert_character(int count)
{
	if (is_inside_scroll_area())
		scroll(console->x, console->width - 1, console->y, console->y, count, 0);
}

static void delete_character(int count)
{
	if (is_inside_scroll_area())
		scroll(console->x, console->width - 1, console->y, console->y, -count, 0);
}

static void change_mode(int mode, int set)
{
	switch (mode)
	{
	case 4: /* IRM */
		console->insert_mode = set;
		break;

	case 20: /* LNM */
		/* TODO: When LNM is set, CR should be translated to CR LF on input
		 * But there isn't a corresponding termios flag for this
		 */
		if (set)
			console->termios.c_oflag |= ONLCR;
		else
			console->termios.c_oflag &= ~ONLCR;
		break;

	default:
		log_error("change_mode(): mode %d not supported.\n", mode);
	}
}

static void change_private_mode(int mode, int set)
{
	switch (mode)
	{
	case 1: /* DECCKM */
		console->cursor_key_mode = set;
		break;

	case 3:
		if (set) /* 132 column mode */
			console_set_size(132, 24);
		else /* 80 column mode */
			console_set_size(80, 24);
		/* Clear window content and reset scrolling regions */
		erase_screen(2);
		set_pos(0, 0);
		break;
		
	case 6:
		console->origin_mode = set;
		break;

	case 7:
		console->wraparound_mode = set;
		break;

	case 47:
		if (set)
			switch_to_alternate_buffer();
		else
			switch_to_normal_buffer();
		break;

	case 1047:
		if (set)
		{
			if (console->out == console->normal_buffer)
			{
				switch_to_alternate_buffer();
				erase_screen(ERASE_SCREEN_BEGIN_TO_END);
			}
		}
		else
		{
			if (console->out == console->alternate_buffer)
			{
				switch_to_normal_buffer();
				erase_screen(ERASE_SCREEN_BEGIN_TO_END);
			}
		}
		break;

	case 1048:
		if (set)
			save_cursor();
		else
			restore_cursor();
		break;

	case 1049:
		if (set)
		{
			save_cursor();
			if (console->out == console->normal_buffer)
			{
				switch_to_alternate_buffer();
				erase_screen(ERASE_SCREEN_BEGIN_TO_END);
			}
		}
		else
		{
			if (console->out == console->alternate_buffer)
			{
				switch_to_normal_buffer();
				erase_screen(ERASE_SCREEN_BEGIN_TO_END);
			}
			restore_cursor();
		}
		break;

	default:
		log_error("change_private_mode(): private mode %d not supported.\n", mode);
	}
}

/* Handler for control sequencie introducer, "ESC [" */
static void control_escape_csi(char ch)
{
	switch (ch)
	{
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		console->params[console->param_count] = 10 * console->params[console->param_count] + (ch - '0');
		break;

	case ';':
		if (console->param_count + 1 == CONSOLE_MAX_PARAMS)
			log_error("Too many console parameters.\n");
		else
			console->param_count++;
		break;

	case 'A': /* CUU */
		move_up(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'B': /* CUD */
	case 'e': /* VPR */
		move_down(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'C': /* CUF */
	case 'a': /* HPR */
		move_right(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'D': /* CUB */
		move_left(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'd': /* VPA */
	{
		int y = console->params[0]? console->params[0]: 1;
		if (y > console->height)
			y = console->height;
		set_pos(console->x, y - 1);
		console->processor = NULL;
		break;
	}

	case 'G': /* CHA */
	case '`': /* HPA */
	{
		int x = console->params[0] ? console->params[0] : 1;
		if (x > console->width)
			x = console->width;
		set_pos(x - 1, console->y);
		console->processor = NULL;
		break;
	}

	case 'H':
	case 'f':
		/* Zero or one both represents the first row/column */
		if (console->params[0] > 0)
			console->params[0]--;
		if (console->params[1] > 0)
			console->params[1]--;
		if (console->origin_mode)
			set_pos(console->params[1], console->scroll_top + console->params[0]);
		else
			set_pos(console->params[1], console->params[0]);
		console->processor = NULL;
		break;

	case 'h':
		if (console->csi_prefix == '?')
			for (int i = 0; i <= console->param_count; i++)
				change_private_mode(console->params[i], 1);
		else
			for (int i = 0; i <= console->param_count; i++)
				change_mode(console->params[i], 1);
		console->processor = NULL;
		break;

	case 'J':
		erase_screen(console->params[0]);
		console->processor = NULL;
		break;

	case 'K':
		erase_line(console->params[0]);
		console->processor = NULL;
		break;

	case 'l':
		if (console->csi_prefix == '?')
			for (int i = 0; i <= console->param_count; i++)
				change_private_mode(console->params[i], 0);
		else
			for (int i = 0; i <= console->param_count; i++)
				change_mode(console->params[i], 0);
		console->processor = NULL;
		break;

	case 'L': /* IL */
		insert_line(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'M': /* DL */
		delete_line(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case '@': /* ICH */
		insert_character(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'P': /* DCH */
		delete_character(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'c':
		if (console->csi_prefix == '>') /* DA2 */
		{
			if (console->params[0] == 0)
				console_add_input("\x1B[>61;95;0c", 11);
			else
				log_warning("DA2 parameter is not zero.\n");
		}
		else /* DA1 */
		{
			if (console->params[0] == 0)
				log_error("DA1 not supported.\n");
			else
				log_warning("DA1 parameter is not zero.\n");
		}
		console->processor = NULL;
		break;

	case 'm':
		for (int i = 0; i <= console->param_count; i++)
		{
			switch (console->params[i])
			{
			case 0: /* Reset */
				console->bright = 0;
				console->reverse = 0;
				console->foreground = 7;
				console->background = 0;
				break;

			case 1:
				console->bright = 1;
				break;

			case 2:
				console->bright = 0;
				break;

			case 7:
				console->reverse = 1;
				break;

			case 27:
				console->reverse = 0;
				break;

			case 30:
			case 31:
			case 32:
			case 33:
			case 34:
			case 35:
			case 36:
			case 37:
				console->foreground = console->params[i] - 30;
				break;

			case 40:
			case 41:
			case 42:
			case 43:
			case 44:
			case 45:
			case 46:
			case 47:
				console->background = console->params[i] - 40;
				break;

			default:
				log_error("Unknown console attribute: %d\n", console->params[i]);
			}
		}
		/* Set updated text attribute */
		SetConsoleTextAttribute(console->out, get_text_attribute(console));
		console->processor = NULL;
		break;

	case 'r':
		if (console->params[0] == 0)
			console->params[0] = 1;
		if (console->params[1] == 0)
			console->params[1] = console->height;
		console->scroll_full_screen = (console->params[0] == 1 && console->params[1] == console->height);
		console->scroll_top = console->params[0] - 1;
		console->scroll_bottom = console->params[1] - 1;
		set_pos(0, 0);
		console->processor = NULL;
		break;

	case 'S': /* SU */
		scroll_up(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case '?':
		console->csi_prefix = '?';
		break;

	case '>':
		console->csi_prefix = '?';
		break;

	default:
		log_error("control_escape_csi(): Unhandled character %c\n", ch);
		console->processor = NULL;
	}
}

/* Handler for operating system commands, "ESC ]" */
static void control_escape_osc(char ch)
{
	if (console->string_len == -1)
	{
		if (ch == ';')
		{
			console->string_len = 0;
			return;
		}
		else if (ch >= '0' && ch <= '9')
		{
			console->params[0] = console->params[0] * 10 + (ch - '0');
			return;
		}
	}
	else if (ch == 7) /* BEL, marks the end */
	{
		if (console->params[0] == 0 || console->params[0] == 2) /* Change window title (and icon name) */
		{
			WCHAR title[MAX_STRING + 1];
			int r = utf8_to_utf16(console->string_buffer, console->string_len, title, MAX_STRING + 1);
			if (r < 0)
			{
				log_error("Invalid UTF-8 sequence.\n");
				return;
			}
			title[r] = 0;
			SetConsoleTitleW(title);
			console->processor = NULL;
			return;
		}
	}
	else
	{
		console->string_buffer[console->string_len++] = ch;
		return;
	}
	log_error("control_escape_osc(): Unhandled character %c\n", ch);
	console->processor = NULL;
}

static void control_escape_sharp(char ch)
{
	switch (ch)
	{
	case '8':
	{
		/* DECALN: DEC screen alignment test */
		/* Fill screen with 'E' */
		COORD start;
		start.X = 0;
		start.Y = 0;
		DWORD bytes_written;
		FillConsoleOutputAttribute(console->out, get_text_attribute(), console->width * console->height, start, &bytes_written);
		FillConsoleOutputCharacterW(console->out, L'E', console->width * console->height, start, &bytes_written);
		console->processor = NULL;
	}

	default:
		log_error("control_escape_sharp(): Unhandled character %c\n", ch);
		console->processor = NULL;
	}
}

static void control_escape_set_default_character_set(char ch)
{
	charset_func c = parse_charset(ch);
	if (c)
		console->g0_charset = c;
	else
		log_warning("console: set default character set: %c, ignored.\n", ch);
	console->processor = NULL;
}

static void control_escape_set_alternate_character_set(char ch)
{
	charset_func c = parse_charset(ch);
	if (c)
		console->g1_charset = c;
	else
		log_warning("console: set alternate character set: %c, ignored.\n", ch);
	console->processor = NULL;
}

static void control_escape(char ch)
{
	switch (ch)
	{
	case '[':
		for (int i = 0; i < CONSOLE_MAX_PARAMS; i++)
			console->params[i] = 0;
		console->param_count = 0;
		console->csi_prefix = 0;
		console->processor = control_escape_csi;
		break;

	case ']':
		console->params[0] = 0;
		console->string_len = -1;
		console->processor = control_escape_osc;
		break;

	case 'D': /* IND */
		nl();
		console->processor = NULL;
		break;

	case 'E': /* NEL */
		crnl();
		console->processor = NULL;
		break;

	case 'M': /* RI */
		if (console->y == console->scroll_top)
			scroll_down(1);
		else
			set_pos(console->x, console->y - 1);
		console->processor = NULL;
		break;

	case '(':
		console->processor = control_escape_set_default_character_set;
		break;

	case ')':
		console->processor = control_escape_set_alternate_character_set;
		break;

	case '#':
		console->processor = control_escape_sharp;
		break;

	case '7': /* DECSC */
		save_cursor();
		console->processor = NULL;
		break;

	case '8': /* DECRC */
		restore_cursor();
		console->processor = NULL;
		break;

	default:
		log_error("control_escape(): Unhandled character %c\n", ch);
		console->processor = NULL;
	}
}

static void console_buffer_add_string(char *buf, size_t *bytes_read, size_t *count, char *str, size_t size)
{
	while (*count > 0 && size > 0)
	{
		buf[(*bytes_read)++] = *str;
		(*count)--;
		str++;
		size--;
	}
	if (size > 0)
		console_add_input(str, size);
}

static int console_get_poll_status(struct file *f)
{
	/* Writing is always ready */
	struct console_file *console_file = (struct console_file *) f;
	if (console->input_buffer_head != console->input_buffer_tail)
		return LINUX_POLLIN | LINUX_POLLOUT;

	console_lock();
	INPUT_RECORD ir;
	DWORD num_read;
	while (PeekConsoleInputW(console->in, &ir, 1, &num_read) && num_read > 0)
	{
		/* Test if the event will be discarded */
		if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
		{
			console_unlock();
			return LINUX_POLLIN | LINUX_POLLOUT;
		}
		else if (ir.EventType == WINDOW_BUFFER_SIZE_EVENT)
			console_retrieve_state();
		/* Discard the event */
		ReadConsoleInputW(console->in, &ir, 1, &num_read);
	}
	/* We don't find any readable events */
	console_unlock();
	return LINUX_POLLOUT;
}

static HANDLE console_get_poll_handle(struct file *f, int *poll_events)
{
	struct console_file *console_file = (struct console_file *)f;
	*poll_events = LINUX_POLLIN | LINUX_POLLOUT;
	return console->in;
}

static int console_close(struct file *f)
{
	kfree(f, sizeof(struct console_file));
	return 0;
}

static size_t console_read(struct file *f, void *b, size_t count)
{
	char *buf = (char *)b;
	struct console_file *console_file = (struct console_file *)f;

	console_lock();
	console_retrieve_state();

	size_t bytes_read = 0;
	while (console->input_buffer_head != console->input_buffer_tail && count > 0)
	{
		count--;
		buf[bytes_read++] = console->input_buffer[console->input_buffer_tail];
		console->input_buffer_tail = (console->input_buffer_tail + 1) % MAX_INPUT;
	}
	if (console->termios.c_lflag & ICANON)
	{
		char line[MAX_CANON + 1]; /* One more for storing CR or LF */
		size_t len = 0;
		while (count > 0)
		{
			INPUT_RECORD ir;
			DWORD read;
			ReadConsoleInputA(console->in, &ir, 1, &read);
			if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
			{
				switch (ir.Event.KeyEvent.wVirtualKeyCode)
				{
				case VK_RETURN:
				{
					if (!(console->termios.c_iflag & IGNCR))
						line[len++] = console->termios.c_iflag & ICRNL ? '\n' : '\r';
					size_t r = min(count, len);
					memcpy(buf + bytes_read, line, r);
					bytes_read += r;
					count -= r;
					if (r < len)
					{
						/* Some bytes not fit, add to input buffer */
						console_add_input(line + r, len - r);
					}
					if (console->termios.c_lflag & ECHO)
						crnl();
					goto read_done;
				}

				case VK_BACK:
				{
					if (len > 0)
					{
						len--;
						if (console->termios.c_lflag & ECHO)
							backspace(TRUE);
					}
				}
				default:
				{
					char ch = ir.Event.KeyEvent.uChar.AsciiChar;
					if (ch >= 0x20)
					{
						if (len < MAX_CANON)
						{
							line[len++] = ch;
							if (console->termios.c_lflag & ECHO)
								write_normal(&ch, 1);
						}
					}
				}
				}
			}
			else if (ir.EventType == WINDOW_BUFFER_SIZE_EVENT)
				console_retrieve_state();
		}
	}
	else /* Non canonical mode */
	{
		int vtime = console->termios.c_cc[VTIME];
		int vmin = console->termios.c_cc[VMIN];
		while (count > 0)
		{
			if (bytes_read > 0 && bytes_read >= vmin)
				break;
			if ((vmin == 0 && vtime == 0)			/* Polling read */
				|| (vtime > 0 && bytes_read > 0))	/* Read with interbyte timeout. Apply after reading first character */
			{
				DWORD r = signal_wait(1, &console->in, vtime * 100);
				if (r == WAIT_TIMEOUT)
					break;
				if (r == WAIT_INTERRUPTED)
				{
					if (bytes_read == 0)
						bytes_read = -EINTR;
					break;
				}
			}
			else
			{
				/* Blocking read */
				if (signal_wait(1, &console->in, INFINITE) == WAIT_INTERRUPTED)
				{
					if (bytes_read == 0)
						bytes_read = -EINTR;
					break;
				}
			}
			INPUT_RECORD ir;
			DWORD read;
			ReadConsoleInputA(console->in, &ir, 1, &read);
			if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
			{
				switch (ir.Event.KeyEvent.wVirtualKeyCode)
				{
				case VK_UP:
					console_buffer_add_string(buf, &bytes_read, &count, console->cursor_key_mode ? "\x1BOA" : "\x1B[A", 3);
					break;

				case VK_DOWN:
					console_buffer_add_string(buf, &bytes_read, &count, console->cursor_key_mode ? "\x1BOB" : "\x1B[B", 3);
					break;

				case VK_RIGHT:
					console_buffer_add_string(buf, &bytes_read, &count, console->cursor_key_mode ? "\x1BOC" : "\x1B[C", 3);
					break;

				case VK_LEFT:
					console_buffer_add_string(buf, &bytes_read, &count, console->cursor_key_mode ? "\x1BOD" : "\x1B[D", 3);
					break;

				case VK_HOME:
					console_buffer_add_string(buf, &bytes_read, &count, console->cursor_key_mode ? "\x1BOH" : "\x1B[H", 3);
					break;

				case VK_END:
					console_buffer_add_string(buf, &bytes_read, &count, console->cursor_key_mode ? "\x1BOF" : "\x1B[F", 3);
					break;

				case VK_INSERT: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[2~", 4); break;
				case VK_DELETE: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[3~", 4); break;
				case VK_PRIOR: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[5~", 4); break;
				case VK_NEXT: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[6~", 4); break;

				case VK_F1: console_buffer_add_string(buf, &bytes_read, &count, "\x1BOP", 3); break;
				case VK_F2: console_buffer_add_string(buf, &bytes_read, &count, "\x1BOQ", 3); break;
				case VK_F3: console_buffer_add_string(buf, &bytes_read, &count, "\x1BOR", 3); break;
				case VK_F4: console_buffer_add_string(buf, &bytes_read, &count, "\x1BOS", 3); break;
				case VK_F5: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[15~", 5); break;
				case VK_F6: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[17~", 5); break;
				case VK_F7: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[18~", 5); break;
				case VK_F8: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[19~", 5); break;
				case VK_F9: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[20~", 5); break;
				case VK_F10: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[21~", 5); break;
				case VK_F11: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[23~", 5); break;
				case VK_F12: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[24~", 5); break;
				case VK_F13: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[25~", 5); break;
				case VK_F14: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[26~", 5); break;
				case VK_F15: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[28~", 5); break;
				case VK_F16: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[29~", 5); break;
				case VK_F17: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[31~", 5); break;
				case VK_F18: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[32~", 5); break;
				case VK_F19: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[33~", 5); break;
				case VK_F20: console_buffer_add_string(buf, &bytes_read, &count, "\x1B[34~", 5); break;

				default:
				{
					char ch = ir.Event.KeyEvent.uChar.AsciiChar;
					if (ch == '\r' && console->termios.c_iflag & IGNCR)
						break;
					if (ch == '\r' && console->termios.c_iflag & ICRNL)
						ch = '\n';
					else if (ch == '\n' && console->termios.c_iflag & ICRNL)
						ch = '\r';
					if (ch > 0)
					{
						count--;
						buf[bytes_read++] = ch;
						if (console->termios.c_lflag & ECHO)
							write_normal(&ch, 1);
					}
				}
				}
			}
			else if (ir.EventType == WINDOW_BUFFER_SIZE_EVENT)
				console_retrieve_state();
			else
			{
				/* TODO: Other types of input */
			}
		}
	}
read_done:
	/* This will make the caret immediately visible */
	set_pos(console->x, console->y);
	console_unlock();
	return bytes_read;
}

static size_t console_write(struct file *f, const void *b, size_t count)
{
	const char *buf = (const char *)b;
	struct console_file *console_file = (struct console_file *)f;

	console_lock();
	console_retrieve_state();
	#define OUTPUT() \
		if (last != -1) \
		{ \
			write_normal(buf + last, i - last); \
			last = -1; \
		}
	size_t last = -1;
	size_t i;
	for (i = 0; i < count; i++)
	{
		unsigned char ch = buf[i];
		if (ch == 0x1B) /* Escape */
		{
			OUTPUT();
			console->processor = control_escape;
		}
		else if (ch == '\t')
		{
			OUTPUT();
			int x = (console->x + 8) & ~7;
			if (x < console->width)
				set_pos(x, console->y);
			else
				set_pos(console->width - 1, console->y);
		}
		else if (ch == '\b')
		{
			OUTPUT();
			backspace(FALSE);
		}
		else if (ch == '\r')
		{
			OUTPUT();
			if (console->termios.c_oflag & OCRNL)
				nl();
			else
				cr();
		}
		else if (ch == '\n' || ch == '\v' || ch == '\f')
		{
			OUTPUT();
			if (console->termios.c_oflag & ONLCR)
				crnl();
			else
				nl();
		}
		else if (ch == 0x0E)
		{
			/* Shift Out */
			OUTPUT();
			console->charset = 1;
		}
		else if (ch == 0x0F)
		{
			/* Shift In */
			OUTPUT();
			console->charset = 0;
		}
		else if (console->processor)
			console->processor(ch);
		else if (ch < 0x20)
		{
			OUTPUT();
			log_error("Unhandled control character '\\x%x'\n", ch);
		}
		else if (last == -1)
			last = i;
	}
	OUTPUT();
	/* This will make the caret immediately visible */
	set_pos(console->x, console->y);
	console_unlock();
#if 0
	char str[4096];
	memcpy(str, buf, count);
	str[count] = '\n';
	str[count + 1] = 0;
	log_debug(str);
#endif
	return count;
}

static int console_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IFCHR + 0644;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = mkdev(5, 1);
	buf->st_size = 0;
	buf->st_blksize = 4096;
	buf->st_blocks = 0;
	buf->st_atime = 0;
	buf->st_atime_nsec = 0;
	buf->st_mtime = 0;
	buf->st_mtime_nsec = 0;
	buf->st_ctime = 0;
	buf->st_ctime_nsec = 0;
	return 0;
}

static void console_update_termios()
{
	/* Nothing to do for now */
}

static int console_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	console_lock();

	int r;
	/* TODO: What is the different between S/SW/SF variants? */
	switch (cmd)
	{
	case TCGETS:
	{
		struct termios *t = (struct termios *)arg;
		memcpy(t, &console->termios, sizeof(struct termios));
		r = 0;
		break;
	}

	case TCSETS:
	case TCSETSW:
	case TCSETSF:
	{
		struct termios *t = (struct termios *)arg;
		memcpy(&console->termios, t, sizeof(struct termios));
		console_update_termios();
		r = 0;
		break;
	}

	case TIOCGPGRP:
	{
		log_warning("Unsupported TIOCGPGRP: Return fake result.\n");
		*(pid_t *)arg = GetCurrentProcessId();
		r = 0;
		break;
	}

	case TIOCSPGRP:
	{
		log_warning("Unsupported TIOCSPGRP: Do nothing.\n");
		r = 0;
		break;
	}

	case TIOCGWINSZ:
	{
		struct winsize *win = (struct winsize *)arg;
		CONSOLE_SCREEN_BUFFER_INFO info;
		GetConsoleScreenBufferInfo(console->out, &info);

		win->ws_col = info.srWindow.Right - info.srWindow.Left + 1;
		win->ws_row = info.srWindow.Bottom - info.srWindow.Top + 1;
		win->ws_xpixel = 0;
		win->ws_ypixel = 0;
		r = 0;
		break;
	}

	case TIOCSWINSZ:
	{
		const struct winsize *win = (const struct winsize *)arg;
		console_set_size(win->ws_col, win->ws_row);
		r = 0;
		break;
	}

	default:
		log_error("console: unknown ioctl command: %x\n", cmd);
		r = -EINVAL;
		break;
	}
	console_unlock();
	return r;
}

static const struct file_ops console_ops = {
	.get_poll_status = console_get_poll_status,
	.get_poll_handle = console_get_poll_handle,
	.close = console_close,
	.read = console_read,
	.write = console_write,
	.stat = console_stat,
	.ioctl = console_ioctl,
};

struct file *console_alloc()
{
	struct console_file *f = (struct console_file *)kmalloc(sizeof(struct console_file));
	f->base_file.op_vtable = &console_ops;
	f->base_file.ref = 1;
	f->base_file.flags = O_LARGEFILE | O_RDWR;
	return (struct file *)f;
}
