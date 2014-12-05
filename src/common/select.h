#pragma once

#define LINUX_FD_SETSIZE	1024
#define LINUX_FD_BITPERLONG	(8 * sizeof(unsigned long))

struct fdset
{
	unsigned long fds_bits[(LINUX_FD_SETSIZE + LINUX_FD_BITPERLONG) / LINUX_FD_BITPERLONG];
};

#define LINUX_FD_ZERO(nfds, set) memset((set)->fds_bits, 0, ((nfds) + LINUX_FD_BITPERLONG) / LINUX_FD_BITPERLONG)
#define LINUX_FD_CLR(fd, set) (set)->fds_bits[(fd) / LINUX_FD_BITPERLONG] &= ~(1 << ((fd) % LINUX_FD_BITPERLONG))
#define LINUX_FD_SET(fd, set) (set)->fds_bits[(fd) / LINUX_FD_BITPERLONG] |= 1 << ((fd) % LINUX_FD_BITPERLONG)
#define LINUX_FD_ISSET(fd, set) (((set)->fds_bits[(fd) / LINUX_FD_BITPERLONG] >> ((fd) % LINUX_FD_BITPERLONG)) & 1)
