#pragma once

#define PROT_NONE		0
#define PROT_READ		1
#define PROT_WRITE		2
#define PROT_EXEC		4

#define MAP_FILE		0
#define MAP_SHARED		1
#define MAP_PRIVATE		2
#define MAP_TYPE		0xf
#define MAP_FIXED		0x10
#define MAP_ANONYMOUS	0x20
#define MAP_ANON		MAP_ANONYMOUS

#define MAP_FAILED		((void *)-1)

/* Flags for msync. */
#define MS_ASYNC		1
#define MS_SYNC			2
#define MS_INVALIDATE	4
