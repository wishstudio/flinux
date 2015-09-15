#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void console_init();
HANDLE get_console_poll_handle();
void console_write(const void *buf, size_t count);
size_t console_read(void *buf, size_t count);
int console_has_unread_input();
int console_control(int cmd, void *arg);
