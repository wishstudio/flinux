#pragma once

#include <common/types.h>

typedef struct {
	int val[2];
} __kernel_fsid_t;

#pragma pack(push, 4)
struct statfs {
	uintptr_t f_type;
	uintptr_t f_bsize;
	uintptr_t f_blocks;
	uintptr_t f_bfree;
	uintptr_t f_bavail;
	uintptr_t f_files;
	uintptr_t f_ffree;
	__kernel_fsid_t f_fsid;
	uintptr_t f_namelen;
	uintptr_t f_frsize;
	uintptr_t f_flags;
	uintptr_t f_spare[4];
};

struct statfs64 {
	uintptr_t f_type;
	uintptr_t f_bsize;
	uint64_t f_blocks;
	uint64_t f_bfree;
	uint64_t f_bavail;
	uint64_t f_files;
	uint64_t f_ffree;
	__kernel_fsid_t f_fsid;
	uintptr_t f_namelen;
	uintptr_t f_frsize;
	uintptr_t f_flags;
	uintptr_t f_spare[4];
};
#pragma pack(pop)
