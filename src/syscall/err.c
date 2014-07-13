#include "err.h"
#include "errno.h"
#include "../log.h"

#include <stdlib.h>

int sys_unimplemented()
{
	exit(1);
	return EFAULT;
}
