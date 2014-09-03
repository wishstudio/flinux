#pragma once

#include <stdint.h>
#include <Windows.h>

uint64_t filetime_to_unix_sec(const FILETIME *filetime);
uint64_t filetime_to_unix_nsec(const FILETIME *filetime);
void filetime_to_unix_timeval(const FILETIME *filetime, struct timeval *tv);
void unix_timeval_to_filetime(const struct timeval *time, FILETIME *filetime);
