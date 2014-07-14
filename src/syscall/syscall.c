#include "syscall.h"
#include "../log.h"

#include <stdint.h>
#include <Windows.h>

typedef int syscall_fn(int ebx, int ecx, int edx, int esi, int edi);

#define SYSCALL_COUNT 338
#define SYSCALL(name) extern int name(int ebx, int ecx, int edx, int esi, int edi);
#include "syscall_table.h"
#undef SYSCALL

#define SYSCALL(name) name,
static syscall_fn* syscall_table[SYSCALL_COUNT] =
{
	sys_unimplemented, /* syscall 0 */
#include "syscall_table.h"
};
#undef SYSCALL

static void dispatch_syscall(PCONTEXT context)
{
#ifdef _DEBUG
	if (syscall_table[context->Eax] == sys_unimplemented)
		log_debug("FATAL: Unimplemented syscall: %d\n", context->Eax);
#endif
	log_debug("%x\n", context->Eip);
	context->Eax = (*syscall_table[context->Eax])(context->Ebx, context->Ecx, context->Edx, context->Esi, context->Edi);
}

static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		uint8_t* code = (uint8_t *)ep->ContextRecord->Eip;
		if (code >= 0 && code < 0x80000000U)
		{
			if (code[0] == 0xCD && code[1] == 0x80) /* INT 80h */
			{
				ep->ContextRecord->Eip += 2;
				dispatch_syscall(ep->ContextRecord);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void install_syscall_handler()
{
	AddVectoredExceptionHandler(TRUE, exception_handler);
}
