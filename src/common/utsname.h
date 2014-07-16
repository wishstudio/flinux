#ifndef _COMMON_UTSNAME_H
#define _COMMON_UTSNAME_H

#define __OLD_UTS_LEN 8
#define __NEW_UTS_LEN 64

struct oldold_utsname
{
	char sysname[9];
	char nodename[9];
	char release[9];
	char version[9];
	char machine[9];
};

struct old_utsname
{
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
};

struct utsname
{
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

#endif
