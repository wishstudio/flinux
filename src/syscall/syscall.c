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
#ifdef _WIN64
	log_error("FATAL: Unimplemented syscall: %d\n", (int)context->Rax);
#else
	log_error("FATAL: Unimplemented syscall: %d\n", context->Eax);
#endif
	ExitProcess(1);
}

static void dispatch_syscall(PCONTEXT context)
{
#ifdef _WIN64
	context->Rax = (*syscall_table[context->Rax])(context->Rdi, context->Rsi, context->Rdx, context->R10, context->R8, context->R9, context);
#else
	context->Eax = (*syscall_table[context->Eax])(context->Ebx, context->Ecx, context->Edx, context->Esi, context->Edi, context->Ebp, context);
#endif
}

static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
#ifdef _WIN64
		uint8_t* code = (uint8_t *)ep->ContextRecord->Rip;
#else
		uint8_t* code = (uint8_t *)ep->ContextRecord->Eip;
#endif
		if (code >= 0 && code < 0x80000000U)
		{
#ifdef _WIN64
			log_info("RIP: 0x%x\n", ep->ContextRecord->Rip);
#else
			log_info("EIP: 0x%x\n", ep->ContextRecord->Eip);
#endif
			if (code[0] == 0xCD && code[1] == 0x80) /* INT 80h */
			{
#ifdef _WIN64
				ep->ContextRecord->Rip += 2;
#else
				ep->ContextRecord->Eip += 2;
#endif
				dispatch_syscall(ep->ContextRecord);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (tls_gs_emulation(ep->ContextRecord, code))
				return EXCEPTION_CONTINUE_EXECUTION;
			else if (mm_handle_page_fault(ep->ExceptionRecord->ExceptionInformation[1]))
				return EXCEPTION_CONTINUE_EXECUTION;
		}
#ifdef _WIN64
		if (ep->ExceptionRecord->ExceptionInformation[0] == 0)
			log_error("Page fault(read): %x at %llx\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Rip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 1)
			log_error("Page fault(write): %x at %llx\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Rip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 2)
			log_error("Page fault(DEP): %x at %llx\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Rip);
#else
		if (ep->ExceptionRecord->ExceptionInformation[0] == 0)
			log_error("Page fault(read): %x at %x\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Eip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 1)
			log_error("Page fault(write): %x at %x\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Eip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 2)
			log_error("Page fault(DEP): %x at %x\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Eip);
#endif
	}
	log_info("Application crashed, dumping debug information...\n");
	//dump_virtual_memory(GetCurrentProcess());
	mm_dump_stack_trace(ep->ContextRecord);
#ifdef _WIN64
	log_info("RAX: 0x%llx\n", ep->ContextRecord->Rax);
	log_info("RBX: 0x%llx\n", ep->ContextRecord->Rbx);
	log_info("RCX: 0x%llx\n", ep->ContextRecord->Rcx);
	log_info("RDX: 0x%llx\n", ep->ContextRecord->Rdx);
	log_info("RSI: 0x%llx\n", ep->ContextRecord->Rsi);
	log_info("RDI: 0x%llx\n", ep->ContextRecord->Rdi);
	log_info("RBP: 0x%llx\n", ep->ContextRecord->Rax);
	log_info("RSP: 0x%llx\n", ep->ContextRecord->Rsp);
	log_info("R8:  0x%llx\n", ep->ContextRecord->R8);
	log_info("R9:  0x%llx\n", ep->ContextRecord->R9);
	log_info("R10: 0x%llx\n", ep->ContextRecord->R10);
	log_info("R11: 0x%llx\n", ep->ContextRecord->R11);
	log_info("R12: 0x%llx\n", ep->ContextRecord->R12);
	log_info("R13: 0x%llx\n", ep->ContextRecord->R13);
	log_info("R14: 0x%llx\n", ep->ContextRecord->R14);
	log_info("R15: 0x%llx\n", ep->ContextRecord->R15);
#else
	log_info("EAX: 0x%x\n", ep->ContextRecord->Eax);
	log_info("EBX: 0x%x\n", ep->ContextRecord->Ebx);
	log_info("ECX: 0x%x\n", ep->ContextRecord->Ecx);
	log_info("EDX: 0x%x\n", ep->ContextRecord->Edx);
	log_info("ESI: 0x%x\n", ep->ContextRecord->Esi);
	log_info("EDI: 0x%x\n", ep->ContextRecord->Edi);
	log_info("EBP: 0x%x\n", ep->ContextRecord->Eax);
	log_info("ESP: 0x%x\n", ep->ContextRecord->Esp);
#endif
	/* If we come here we're sure to crash, so gracefully close logging */
	log_shutdown();
	return EXCEPTION_CONTINUE_SEARCH;
}

void install_syscall_handler()
{
	AddVectoredExceptionHandler(TRUE, exception_handler);
}
