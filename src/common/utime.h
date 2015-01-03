#pragma once

struct utimbuf
{
	long actime;
	long modtime;
};

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
/* Defined in WinSock2.h
struct timeval
{
	long tv_sec;
	long tv_usec;
};
*/
