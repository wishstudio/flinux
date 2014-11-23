#pragma once

#include <stddef.h>

#define container_of(ptr, type, member) \
	(type *)((char *)(ptr) - offsetof(type, member))
