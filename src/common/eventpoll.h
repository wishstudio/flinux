#pragma once

#include <common/fcntl.h>
#include <common/types.h>

/* Flags for epoll_create1.  */
#define EPOLL_CLOEXEC	O_CLOEXEC

/* Valid opcodes to issue to sys_epoll_ctl() */
#define EPOLL_CTL_ADD	1
#define EPOLL_CTL_DEL	2
#define EPOLL_CTL_MOD	3

#define EPOLLWAKEUP		(1 << 29)
#define EPOLLONESHOT	(1 << 30)
#define EPOLLET			(1 << 31)

struct epoll_event
{
	uint32_t events; /* Epoll events */
	uint32_t data; /* User data variable */
};
