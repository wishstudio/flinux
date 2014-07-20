#ifndef _COMMON_LDT_H
#define _COMMON_LDT_H

struct user_desc
{
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit: 1;
	unsigned int contents: 2;
	unsigned int read_exec_only: 1;
	unsigned int limit_in_pages: 1;
	unsigned int seg_not_present: 1;
	unsigned int useable: 1;
};

#endif
