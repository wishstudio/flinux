#pragma once

struct utimbuf
{
	long actime;
	long modtime;
};

#include <Windows.h>
/* Defined in WinSock2.h
struct timeval
{
	long tv_sec;
	long tv_usec;
};
*/
