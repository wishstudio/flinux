#pragma once

#include <common/time.h>

#include <stdint.h>
#include <Windows.h>

#define NANOSECONDS_PER_TICK	100ULL
#define NANOSECONDS_PER_SECOND	1000000000ULL

uint64_t filetime_to_unix_sec(const FILETIME *filetime);
uint64_t filetime_to_unix_nsec(const FILETIME *filetime);
void filetime_to_unix_timeval(const FILETIME *filetime, struct timeval *tv);
void filetime_to_unix_timespec(const FILETIME *filetime, struct timespec *tv);
void unix_timeval_to_filetime(const struct timeval *time, FILETIME *filetime);
