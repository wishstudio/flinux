#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/syscall_dispatch.h>
#include <syscall/tls.h>
#include <log.h>
#include <platform.h>

#include <stdint.h>
#include <Windows.h>

extern void *mm_check_read_begin, *mm_check_read_end, *mm_check_read_fail;
extern void *mm_check_read_string_begin, *mm_check_read_string_end, *mm_check_read_string_fail;
extern void *mm_check_write_begin, *mm_check_write_end, *mm_check_write_fail;

static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		uint8_t* code = (uint8_t *)ep->ContextRecord->Xip;
		if (ep->ExceptionRecord->ExceptionInformation[0] == 8)
		{
			if (mm_handle_page_fault(code))
				return EXCEPTION_CONTINUE_EXECUTION;
			else if (mm_handle_page_fault(code + 0x1000)) // TODO: Use PAGE_SIZE
				return EXCEPTION_CONTINUE_EXECUTION;
		}
		else
		{
			log_info("IP: 0x%p\n", ep->ContextRecord->Xip);
			if (code[0] == 0xCD && code[1] == 0x80) /* INT 80h */
			{
				ep->ContextRecord->Xip += 2;
				dispatch_syscall(ep->ContextRecord);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (tls_emulation(ep->ContextRecord, code))
				return EXCEPTION_CONTINUE_EXECUTION;
			else if (mm_handle_page_fault(ep->ExceptionRecord->ExceptionInformation[1]))
				return EXCEPTION_CONTINUE_EXECUTION;
			if (ep->ContextRecord->Xip >= &mm_check_read_begin && ep->ContextRecord->Xip <= &mm_check_read_end)
			{
				ep->ContextRecord->Xip = &mm_check_read_fail;
				log_warning("mm_check_read() failed at location 0x%x\n", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			if (ep->ContextRecord->Xip >= &mm_check_read_string_begin && ep->ContextRecord->Xip <= &mm_check_read_string_end)
			{
				ep->ContextRecord->Xip = &mm_check_read_string_fail;
				log_warning("mm_check_read_string() failed at location 0x%x\n", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			if (ep->ContextRecord->Xip >= &mm_check_write_begin && ep->ContextRecord->Xip <= &mm_check_write_end)
			{
				ep->ContextRecord->Xip = &mm_check_write_fail;
				log_warning("mm_check_write() failed at location 0x%x\n", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		if (ep->ExceptionRecord->ExceptionInformation[0] == 0)
			log_error("Page fault(read): %p at %p\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Xip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 1)
			log_error("Page fault(write): %p at %p\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Xip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 8)
			log_error("Page fault(DEP): %p at %p\n", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Xip);
	}
	log_info("Application crashed, dumping debug information...\n");
	dump_virtual_memory(GetCurrentProcess());
	mm_dump_stack_trace(ep->ContextRecord);
#ifdef _WIN64
	log_info("RAX: 0x%p\n", ep->ContextRecord->Rax);
	log_info("RBX: 0x%p\n", ep->ContextRecord->Rbx);
	log_info("RCX: 0x%p\n", ep->ContextRecord->Rcx);
	log_info("RDX: 0x%p\n", ep->ContextRecord->Rdx);
	log_info("RSI: 0x%p\n", ep->ContextRecord->Rsi);
	log_info("RDI: 0x%p\n", ep->ContextRecord->Rdi);
	log_info("RBP: 0x%p\n", ep->ContextRecord->Rbp);
	log_info("RSP: 0x%p\n", ep->ContextRecord->Rsp);
	log_info("R8:  0x%p\n", ep->ContextRecord->R8);
	log_info("R9:  0x%p\n", ep->ContextRecord->R9);
	log_info("R10: 0x%p\n", ep->ContextRecord->R10);
	log_info("R11: 0x%p\n", ep->ContextRecord->R11);
	log_info("R12: 0x%p\n", ep->ContextRecord->R12);
	log_info("R13: 0x%p\n", ep->ContextRecord->R13);
	log_info("R14: 0x%p\n", ep->ContextRecord->R14);
	log_info("R15: 0x%p\n", ep->ContextRecord->R15);
#else
	log_info("EAX: 0x%p\n", ep->ContextRecord->Eax);
	log_info("EBX: 0x%p\n", ep->ContextRecord->Ebx);
	log_info("ECX: 0x%p\n", ep->ContextRecord->Ecx);
	log_info("EDX: 0x%p\n", ep->ContextRecord->Edx);
	log_info("ESI: 0x%p\n", ep->ContextRecord->Esi);
	log_info("EDI: 0x%p\n", ep->ContextRecord->Edi);
	log_info("EBP: 0x%p\n", ep->ContextRecord->Eax);
	log_info("ESP: 0x%p\n", ep->ContextRecord->Esp);
#endif
	/* If we come here we're sure to crash, so gracefully close logging */
	log_shutdown();
	return EXCEPTION_CONTINUE_SEARCH;
}

void install_syscall_handler()
{
	AddVectoredExceptionHandler(TRUE, exception_handler);
}
