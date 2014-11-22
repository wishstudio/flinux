#include <syscall/syscall.h>
#include <syscall/tls.h>
#include <log.h>

#include <stdint.h>
#include <Windows.h>

typedef int syscall_fn(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context);

#define SYSCALL_COUNT 338
#define SYSCALL(name) extern int name(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context);
#include "syscall_table.h"
#undef SYSCALL

#define SYSCALL(name) name,
static syscall_fn* syscall_table[SYSCALL_COUNT] =
{
	sys_unimplemented, /* syscall 0 */
#include "syscall_table.h"
};
#undef SYSCALL

int sys_unimplemented(int _1, int _2, int _3, int _4, int _5, int _6, PCONTEXT context)
{
	log_error("FATAL: Unimplemented syscall: %d\n", context->Eax);
	ExitProcess(1);
}

static void dispatch_syscall(PCONTEXT context)
{
	context->Eax = (*syscall_table[context->Eax])(context->Ebx, context->Ecx, context->Edx, context->Esi, context->Edi, context->Ebp, context);
}

static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		uint8_t* code = (uint8_t *)ep->ContextRecord->Eip;
		if (code >= 0 && code < 0x80000000U)
		{
			log_info("EIP: 0x%x\n", ep->ContextRecord->Eip);
			if (code[0] == 0xCD && code[1] == 0x80) /* INT 80h */
			{
				ep->ContextRecord->Eip += 2;
				dispatch_syscall(ep->ContextRecord);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (tls_gs_emulation(ep->ContextRecord, code))
				return EXCEPTION_CONTINUE_EXECUTION;
			else if (mm_handle_page_fault(ep->ExceptionRecord->ExceptionInformation[1]))
				return EXCEPTION_CONTINUE_EXECUTION;
		}
		if (ep->ExceptionRecord->ExceptionInformation[0] == 0)
			log_error("Page fault(read): %x at %x\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Eip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 1)
			log_error("Page fault(write): %x at %x\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Eip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 2)
			log_error("Page fault(DEP): %x at %x\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Eip);
	}
	log_info("Application crashed, dumping debug information...\n");
	//dump_virtual_memory(GetCurrentProcess());
	mm_dump_stack_trace(ep->ContextRecord);
	log_info("EAX: 0x%x\n", ep->ContextRecord->Eax);
	log_info("EBX: 0x%x\n", ep->ContextRecord->Ebx);
	log_info("ECX: 0x%x\n", ep->ContextRecord->Ecx);
	log_info("EDX: 0x%x\n", ep->ContextRecord->Edx);
	log_info("ESI: 0x%x\n", ep->ContextRecord->Esi);
	log_info("EDI: 0x%x\n", ep->ContextRecord->Edi);
	log_info("EBP: 0x%x\n", ep->ContextRecord->Eax);
	log_info("ESP: 0x%x\n", ep->ContextRecord->Esp);
	/* If we come here we're sure to crash, so gracefully close logging */
	log_shutdown();
	return EXCEPTION_CONTINUE_SEARCH;
}

void install_syscall_handler()
{
	AddVectoredExceptionHandler(TRUE, exception_handler);
}
