#include "err.h"
#include "errno.h"
#include <log.h>

#include <Windows.h>

__declspec(noreturn) int sys_unimplemented(int _1, int _2, int _3, int _4, int _5, int _6, PCONTEXT context)
{
	log_debug("FATAL: Unimplemented syscall: %d\n", context->Eax);
	ExitProcess(1);
}
