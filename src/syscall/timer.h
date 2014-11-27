#pragma once

#include <common/types.h>
#include <common/time.h>

int sys_time(int *r);
struct timezone;
int sys_gettimeofday(struct timeval *tv, struct timezone *tz);

int sys_nanosleep(const struct timespec *req, struct timespec *rem);

int sys_clock_gettime(int clk_id, struct timespec *tp);
