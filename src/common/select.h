#pragma once

#define FD_SETSIZE	1024
#define FD_BITPERLONG	(8 * sizeof(unsigned long))

struct fdset
{
	unsigned long fds_bits[(FD_SETSIZE + FD_BITPERLONG) / FD_BITPERLONG];
};
