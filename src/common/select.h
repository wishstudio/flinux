#pragma once

#define LINUX_FD_SETSIZE	1024
#define LINUX_FD_BITPERLONG	(8 * sizeof(unsigned long))

struct fdset
{
	unsigned long fds_bits[(LINUX_FD_SETSIZE + LINUX_FD_BITPERLONG - 1) / LINUX_FD_BITPERLONG];
};

#define LINUX_FD_ZERO(nfds, set) \
	do \
	{	\
		int _count = ((nfds) + LINUX_FD_BITPERLONG - 1) / LINUX_FD_BITPERLONG; \
		for (int _i = 0; _i < _count; ++_i) \
			(set)->fds_bits[_i] = 0; \
	} while (0)
#define LINUX_FD_CLR(fd, set) (set)->fds_bits[(fd) / LINUX_FD_BITPERLONG] &= ~(1 << ((fd) % LINUX_FD_BITPERLONG))
#define LINUX_FD_SET(fd, set) (set)->fds_bits[(fd) / LINUX_FD_BITPERLONG] |= 1 << ((fd) % LINUX_FD_BITPERLONG)
#define LINUX_FD_ISSET(fd, set) (((set)->fds_bits[(fd) / LINUX_FD_BITPERLONG] >> ((fd) % LINUX_FD_BITPERLONG)) & 1)
