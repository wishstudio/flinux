#include "err.h"
#include "errno.h"
#include "../log.h"

#include <Windows.h>

int sys_unimplemented()
{
	ExitProcess(1);
	return EFAULT;
}
