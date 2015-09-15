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
#include <fs/virtual.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/sig.h>
#include <heap.h>
#include <log.h>
#include <str.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ntdll.h>
#include <malloc.h>

struct console_data
{
	HANDLE read_pipe, write_pipe;
	HANDLE control_pipe;
	HANDLE control_mutex;
};

static struct console_data *console;

void console_init()
{
	console = (struct console_data *)mm_static_alloc(sizeof(struct console_data));

	/* Get parent PID */
	PROCESS_BASIC_INFORMATION info;
	NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &info, sizeof(info), NULL);
	int parent = (int)info.InheritedFromUniqueProcessId;
	log_info("console parent pid: %d", parent);

	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.bInheritHandle = TRUE;
	attr.lpSecurityDescriptor = NULL;
	char pipe_name[256];
	ksprintf(pipe_name, "\\\\.\\pipe\\fconsole-write-%d", parent);
	console->write_pipe = CreateFileA(pipe_name, GENERIC_WRITE, FILE_SHARE_WRITE,
		&attr, OPEN_EXISTING, 0, NULL);
	ksprintf(pipe_name, "\\\\.\\pipe\\fconsole-read-%d", parent);
	console->read_pipe = CreateFileA(pipe_name, GENERIC_READ, FILE_SHARE_READ,
		&attr, OPEN_EXISTING, 0, NULL);
	ksprintf(pipe_name, "\\\\.\\pipe\\fconsole-control-%d", parent);
	console->control_pipe = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		&attr, OPEN_EXISTING, 0, NULL);
	console->control_mutex = CreateMutexW(&attr, FALSE, NULL);
}

int console_fork(HANDLE hProcess)
{
	/* Nothing to do here */
	return 1;
}

void console_afterfork()
{
	console = (struct console_data *)mm_static_alloc(sizeof(struct console_data));
}

struct console_file
{
	struct virtualfs_custom custom_file;
};

static HANDLE console_get_poll_handle(struct file *f, int *poll_events)
{
	*poll_events = LINUX_POLLIN | LINUX_POLLOUT;
	return console->read_pipe;
}

static int console_close(struct file *f)
{
	kfree(f, sizeof(struct console_file));
	return 0;
}

static size_t console_read(struct file *f, void *buf, size_t count)
{
	DWORD read;
	ReadFile(console->read_pipe, buf, count, &read, NULL);
	return (size_t)read;
}

static size_t console_write(struct file *f, const void *buf, size_t count)
{
#if 1
	char str[1024];
	memcpy(str, buf, count);
	str[count] = 0;
	log_debug(str);
#endif
	DWORD written;
	WriteFile(console->write_pipe, buf, count, &written, NULL);
	FlushFileBuffers(console->write_pipe);
	return (size_t)written;
}

struct console_control_packet
{
	uint32_t cmd;
	char data[0];
};

static int console_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	WaitForSingleObject(console->control_mutex, INFINITE);
	int r;
	/* TODO: What is the different between S/SW/SF variants? */
	switch (cmd)
	{
	case L_TCGETS:
	{
		struct termios *t = (struct termios *)arg;
		if (!mm_check_write(t, sizeof(struct termios)))
			r = -L_EFAULT;
		else
		{
			struct console_control_packet packet;
			packet.cmd = L_TCGETS;
			DWORD bytes;
			WriteFile(console->control_pipe, &packet, sizeof(packet), &bytes, NULL);
			ReadFile(console->control_pipe, t, sizeof(struct termios), &bytes, NULL);
			r = 0;
		}
		break;
	}

	case L_TCSETS:
	case L_TCSETSW:
	case L_TCSETSF:
	{
		struct termios *t = (struct termios *)arg;
		if (!mm_check_read(t, sizeof(struct termios)))
			r = -L_EFAULT;
		else
		{
			int size = sizeof(struct console_control_packet) + sizeof(struct termios);
			struct console_control_packet *packet = (struct console_control_packet *)alloca(size);
			packet->cmd = L_TCSETS;
			memcpy(packet->data, t, sizeof(struct termios));
			DWORD bytes;
			char byte;
			WriteFile(console->control_pipe, packet, size, &bytes, NULL);
			ReadFile(console->control_pipe, &byte, 1, &bytes, NULL);
			r = 0;
		}
		break;
	}

	case L_TIOCGPGRP:
	{
		log_warning("Unsupported TIOCGPGRP: Return fake result.");
		*(pid_t *)arg = process_get_pgid(0);
		r = 0;
		break;
	}

	case L_TIOCSPGRP:
	{
		log_warning("Unsupported TIOCSPGRP: Do nothing.");
		r = 0;
		break;
	}

	case L_TIOCGWINSZ:
	{
		struct winsize *win = (struct winsize *)arg;
		if (!mm_check_write(win, sizeof(struct winsize)))
			r = -L_EFAULT;
		else
		{
			struct console_control_packet packet;
			packet.cmd = L_TIOCGWINSZ;
			DWORD bytes;
			WriteFile(console->control_pipe, &packet, sizeof(packet), &bytes, NULL);
			ReadFile(console->control_pipe, win, sizeof(struct winsize), &bytes, NULL);
			r = 0;
		}
		break;
	}

	case L_TIOCSWINSZ:
	{
		const struct winsize *win = (const struct winsize *)arg;
		if (!mm_check_read(win, sizeof(struct winsize)))
			r = -L_EFAULT;
		else
		{
			int size = sizeof(struct console_control_packet) + sizeof(struct winsize);
			struct console_control_packet *packet = (struct console_control_packet *)alloca(size);
			packet->cmd = L_TIOCSWINSZ;
			memcpy(packet->data, win, sizeof(struct winsize));
			DWORD bytes;
			char byte;
			WriteFile(console->control_pipe, packet, size, &bytes, NULL);
			ReadFile(console->control_pipe, &byte, 1, &bytes, NULL);
			r = 0;
		}
		break;
	}

	default:
		log_error("console: unknown ioctl command: %x", cmd);
		r = -L_EINVAL;
		break;
	}
	ReleaseMutex(console->control_mutex);
	return r;
}

static const struct file_ops console_ops = {
	.get_poll_handle = console_get_poll_handle,
	.close = console_close,
	.read = console_read,
	.write = console_write,
	.stat = virtualfs_custom_stat,
	.ioctl = console_ioctl,
};

struct virtualfs_custom_desc console_desc = VIRTUALFS_CUSTOM(mkdev(5, 1), console_alloc);

struct file *console_alloc()
{
	struct console_file *f = (struct console_file *)kmalloc(sizeof(struct console_file));
	file_init(&f->custom_file.base_file, &console_ops, O_LARGEFILE | O_RDWR);
	virtualfs_init_custom(f, &console_desc);
	return (struct file *)f;
}
