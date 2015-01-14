#include <common/errno.h>
#include <common/fcntl.h>
#include <common/ioctls.h>
#include <common/poll.h>
#include <common/termios.h>
#include <fs/console.h>
#include <syscall/mm.h>
#include <heap.h>
#include <log.h>
#include <str.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ntdll.h>

/* xterm like VT terminal emulation on Win32 console
 *
 * Because things like scrolling region information is completely emulated, data
 * must be shared across all processes in the same console. We then use mutexes
 * to ensure the shared region is modifiable to only one process at one time.
 *
 * The basic assumption is that no other Win32 console applications are running
 * in the same console simultaneously. The only thing we need to take care of is
 * when user changes the size of the window during application operation.
 */
/* TODO: UTF-8 support */

#define CONSOLE_MAX_PARAMS	16
#define MAX_INPUT			256
#define MAX_CANON			256
#define MAX_STRING			256

struct console_data
{
	HANDLE section, mutex;
	HANDLE in, out;
	int params[CONSOLE_MAX_PARAMS];
	int param_count;
	int bright, reverse, foreground, background;
	char input_buffer[MAX_INPUT];
	int string_len;
	char string_buffer[MAX_STRING];
	size_t input_buffer_head, input_buffer_tail;
	struct termios termios;
	void (*processor)(char ch);
};

static struct console_data *const console = (struct console_data *)CONSOLE_DATA_BASE;

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
	if (status != STATUS_SUCCESS)
	{
		log_error("NtCreateSection() failed, status: %x\n", status);
		return;
	}
	PVOID base_addr = console;
	SIZE_T view_size = sizeof(struct console_data);
	status = NtMapViewOfSection(section, NtCurrentProcess(), &base_addr, 0, sizeof(struct console_data), NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);
	if (status != STATUS_SUCCESS)
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
	console->bright = 0;
	console->reverse = 0;
	console->foreground = 7;
	console->background = 0;
	console->input_buffer_head = console->input_buffer_tail = 0;
	console->termios.c_iflag = INLCR;
	console->termios.c_oflag = ONLCR | OPOST;
	console->termios.c_cflag = 0;
	console->termios.c_lflag = ICANON | ECHO | ECHOCTL;
	memset(console->termios.c_cc, 0, sizeof(console->termios.c_cc));
	console->termios.c_cc[VINTR] = 3;
	console->termios.c_cc[VERASE] = 8;
	console->termios.c_cc[VEOF] = 4;
	console->termios.c_cc[VSUSP] = 26;
	console->processor = NULL;
	SetConsoleMode(in, 0);
	SetConsoleMode(out, ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

	log_info("Console shared memory region successfully initialized.\n");
}

int console_fork(HANDLE process)
{
	log_info("Mapping console shared memory region to child process...\n");
	PVOID base_addr = console;
	SIZE_T view_size = sizeof(struct console_data);
	NTSTATUS status;
	status = NtMapViewOfSection(console->section, process, &base_addr, 0, sizeof(struct console_data), NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);
	if (status != STATUS_SUCCESS)
	{
		log_error("NtMapViewOfSection() failed, status: %x\n", status);
		return 0;
	}
	return 1;
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
	int is_read;
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

static void backspace(BOOL erase)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	if (info.dwCursorPosition.X == 0)
	{
		if (info.dwCursorPosition.Y > 0)
		{
			info.dwCursorPosition.X = info.dwSize.X - 1;
			info.dwCursorPosition.Y--;
		}
		else
			return;
	}
	else
		info.dwCursorPosition.X--;
	if (erase)
	{
		DWORD bytes_written;
		WriteConsoleOutputCharacterA(console->out, " ", 1, info.dwCursorPosition, &bytes_written);
	}
	SetConsoleCursorPosition(console->out, info.dwCursorPosition);
}

static void move_left(int count)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	info.dwCursorPosition.X = max(info.dwCursorPosition.X - count, 0);
	SetConsoleCursorPosition(console->out, info.dwCursorPosition);
}

static void move_right(int count)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	info.dwCursorPosition.X = min(info.dwCursorPosition.X + count, info.dwSize.X - 1);
	SetConsoleCursorPosition(console->out, info.dwCursorPosition);
}

static void move_up(int count)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	info.dwCursorPosition.Y = max(info.dwCursorPosition.Y - count, 0);
	SetConsoleCursorPosition(console->out, info.dwCursorPosition);
}

static void move_down(int count)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	info.dwCursorPosition.Y = min(info.dwCursorPosition.Y + count, info.dwSize.Y - 1);
	SetConsoleCursorPosition(console->out, info.dwCursorPosition);
}

static void set_cursor_pos(int row, int column)
{
	COORD pos;
	pos.X = column;
	pos.Y = row;
	SetConsoleCursorPosition(console->out, pos);
}

static void erase_screen(int mode)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	COORD start;
	int count;
	if (mode == 0)
	{
		/* Erase current line to bottom */
		start = info.dwCursorPosition;
		count = (info.dwSize.X - info.dwCursorPosition.X) + (info.srWindow.Bottom - info.dwCursorPosition.Y) * info.dwSize.X;
	}
	else if (mode == 1)
	{
		/* Erase top to current line */
		start.X = 0;
		start.Y = 0;
		count = (info.dwCursorPosition.Y - info.srWindow.Top) * info.dwSize.X + info.dwCursorPosition.X;
	}
	else if (mode == 2)
	{
		/* Erase entire screen */
		start.X = 0;
		start.Y = 0;
		count = (info.srWindow.Bottom - info.srWindow.Top + 1) * info.dwSize.X;
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

static void erase_line(int mode)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	COORD start;
	start.Y = info.dwCursorPosition.Y;
	int count;
	if (mode == 0)
	{
		/* Erase to end */
		start.X = info.dwCursorPosition.X;
		count = info.dwSize.X - start.X;
	}
	else if (mode == 1)
	{
		/* Erase to begin */
		start.X = 0;
		count = info.dwCursorPosition.X;
	}
	else if (mode == 2)
	{
		/* Erase whole line */
		start.X = 0;
		count = info.dwSize.X;
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

	case 'A':
		move_up(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'B':
		move_down(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'C':
		move_right(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'D':
		move_left(console->params[0]? console->params[0]: 1);
		console->processor = NULL;
		break;

	case 'H':
		/* Zero or one both represents the first row/column */
		if (console->params[0] > 0)
			console->params[0]--;
		if (console->params[1] > 0)
			console->params[1]--;
		set_cursor_pos(console->params[0], console->params[1]);
		console->processor = NULL;
		break;

	case 'h':
		log_warning("console: fake disabling mode %d\n", console->params[0]);
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
		log_warning("console: fake disabling mode %d\n", console->params[0]);
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

	case '?':
		log_error("warning: ignored '?'.\n");
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

static void control_escape_set_default_character_set(char ch)
{
	log_warning("console: set default character set: %c, ignored.\n", ch);
	console->processor = NULL;
}

static void control_escape_set_alternate_character_set(char ch)
{
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
		console->processor = control_escape_csi;
		break;

	case ']':
		console->params[0] = 0;
		console->string_len = -1;
		console->processor = control_escape_osc;
		break;

	case '(':
		console->processor = control_escape_set_default_character_set;
		break;

	case ')':
		console->processor = control_escape_set_alternate_character_set;
		break;

	default:
		log_error("control_escape(): Unhandled character %c\n", ch);
		console->processor = NULL;
	}
}

static void console_add_input(char *str, size_t size)
{
	/* TODO: Detect input buffer wrapping */
	for (size_t i = 0; i < size; i++)
	{
		console->input_buffer[console->input_buffer_head] = str[i];
		console->input_buffer_head = (console->input_buffer_head + 1) % MAX_INPUT;
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
	struct console_file *console_file = (struct console_file *) f;
	/* A writing fd, always ready */
	if (!console_file->is_read)
		return LINUX_POLLOUT;

	if (console->input_buffer_head != console->input_buffer_tail)
		return LINUX_POLLIN;

	console_lock();
	INPUT_RECORD ir;
	DWORD num_read;
	while (PeekConsoleInputW(console->in, &ir, 1, &num_read) && num_read > 0)
	{
		/* Test if the event will be discarded */
		if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
		{
			console_unlock();
			return LINUX_POLLIN;
		}
		/* Discard the event */
		ReadConsoleInputW(console->in, &ir, 1, &num_read);
	}
	/* We don't find any readable events */
	console_unlock();
	return 0;
}

static HANDLE console_get_poll_handle(struct file *f, int *poll_events)
{
	struct console_file *console_file = (struct console_file *)f;
	if (console_file->is_read)
	{
		*poll_events = LINUX_POLLIN;
		return console->in;
	}
	else
	{
		*poll_events = LINUX_POLLOUT;
		return console->out;
	}
}

static int console_close(struct file *f)
{
	kfree(f, sizeof(struct console_file));
	return 0;
}

static size_t console_read(struct file *f, char *buf, size_t count)
{
	struct console_file *console_file = (struct console_file *)f;
	if (!console_file->is_read)
		return -EBADF;

	console_lock();

	size_t bytes_read = 0;
	while (console->input_buffer_head != console->input_buffer_tail && count > 0)
	{
		count--;
		buf[bytes_read++] = console->input_buffer[console->input_buffer_tail];
		console->input_buffer_tail = (console->input_buffer_tail + 1) % MAX_INPUT;
	}
	char line[MAX_CANON + 1]; /* One more for storing CR or LF */
	size_t len = 0;
	while (count > 0)
	{
		INPUT_RECORD ir;
		DWORD read;
		ReadConsoleInputA(console->in, &ir, 1, &read);
		if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
		{
			char ch = ir.Event.KeyEvent.uChar.AsciiChar;
			if (console->termios.c_lflag & ICANON)
			{
				switch (ir.Event.KeyEvent.wVirtualKeyCode)
				{
				case VK_RETURN:
				{
					line[len++] = console->termios.c_iflag & INLCR ? '\n' : '\r';
					size_t r = min(count, len);
					memcpy(buf + bytes_read, line, r);
					bytes_read += r;
					count -= r;
					if (r < len)
					{
						/* Some bytes not fit, add to input buffer */
						console_add_input(line + r, len - r);
					}
					/* TODO: Do we need to write CRLF in non-echo mode? */
					DWORD bytes_written;
					WriteConsoleA(console->out, "\r\n", 2, &bytes_written, NULL);
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
					if (ch >= 0x20)
					{
						if (len < MAX_CANON)
						{
							line[len++] = ch;
							if (console->termios.c_lflag & ECHO)
								WriteConsoleA(console->out, &ch, 1, NULL, NULL);
						}
					}
				}
			}
			else /* ICANON */
			{
				switch (ir.Event.KeyEvent.wVirtualKeyCode)
				{
				case VK_UP:
					console_buffer_add_string(buf, &bytes_read, &count, "\x1B[A", 3);
					break;

				case VK_DOWN:
					console_buffer_add_string(buf, &bytes_read, &count, "\x1B[B", 3);
					break;

				case VK_RIGHT:
					console_buffer_add_string(buf, &bytes_read, &count, "\x1B[C", 3);
					break;

				case VK_LEFT:
					console_buffer_add_string(buf, &bytes_read, &count, "\x1B[D", 3);
					break;
					
				default:
					if (ch == '\r' && console->termios.c_iflag & IGNCR)
						break;
					if (ch == '\r' && console->termios.c_iflag & INLCR)
						ch = '\n';
					else if (ch == '\n' && console->termios.c_iflag & ICRNL)
						ch = '\r';
					if (ch > 0)
					{
						count--;
						buf[bytes_read++] = ch;
						if (console->termios.c_lflag & ECHO)
							WriteConsoleA(console->out, &ch, 1, NULL, NULL);
					}
				}
			}
		}
		else
		{
			/* TODO */
		}
	}
read_done:
	console_unlock();
	return bytes_read;
}

static size_t console_write(struct file *f, const char *buf, size_t count)
{
	struct console_file *console_file = (struct console_file *)f;
	if (console_file->is_read)
		return -EBADF;

	console_lock();
	#define OUTPUT() \
		if (last != -1) \
		{ \
			DWORD bytes_written; \
			WriteConsoleA(console->out, buf + last, i - last, &bytes_written, NULL); \
			last = -1; \
		}
	size_t last = -1;
	size_t i;
	for (i = 0; i < count; i++)
	{
		char ch = buf[i];
		if (console->processor)
			console->processor(ch);
		else if (ch == 0x1B) /* Escape */
		{
			OUTPUT();
			console->processor = control_escape;
		}
		/* TODO: Untested
		else if (ch == '\t')
		{
			OUTPUT();
			CONSOLE_SCREEN_BUFFER_INFO info;
			GetConsoleScreenBufferInfo(console->out, &info);
			info.dwCursorPosition.X = (info.dwCursorPosition.X + 8) & -8;
			SetConsoleCursorPosition(console->out, info.dwCursorPosition);
		}*/
		else if (ch == 0x0E || ch == 0x0F)
		{
			/* Shift In and Shift Out */
			OUTPUT();
		}
		else if (last == -1)
			last = i;
	}
	OUTPUT();
	/* This will make the caret immediately visible */
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(console->out, &info);
	SetConsoleCursorPosition(console->out, info.dwCursorPosition);
	console_unlock();
#if 0
	char str[1024];
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

static struct file *console_alloc_file(int is_read)
{
	struct console_file *f = (struct console_file *)kmalloc(sizeof(struct console_file));
	f->base_file.op_vtable = &console_ops;
	f->base_file.ref = 1;
	f->base_file.flags = O_LARGEFILE | O_RDWR;
	f->is_read = is_read;
	return (struct file*)f;
}

int console_alloc(struct file **in_file, struct file **out_file)
{
	*in_file = console_alloc_file(1);
	*out_file = console_alloc_file(0);
	return 0;
}
