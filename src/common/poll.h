#pragma once

/* These are specified by iBCS2 */
#define LINUX_POLLIN		0x0001
#define LINUX_POLLPRI		0x0002
#define LINUX_POLLOUT		0x0004
#define LINUX_POLLERR		0x0008
#define LINUX_POLLHUP		0x0010
#define LINUX_POLLNVAL		0x0020

/* The rest seem to be more-or-less nonstandard. Check them! */
#define LINUX_POLLRDNORM	0x0040
#define LINUX_POLLRDBAND	0x0080
#define LINUX_POLLWRNORM	0x0100
#define LINUX_POLLWRBAND	0x0200
#define LINUX_POLLMSG		0x0400
#define LINUX_POLLREMOVE	0x1000
#define LINUX_POLLRDHUP		0x2000

#define LINUX_POLLFREE		0x4000	/* currently only for epoll */

#define LINUX_POLL_BUSY_LOOP	0x8000

struct linux_pollfd {
	int fd;
	short events;
	short revents;
};
