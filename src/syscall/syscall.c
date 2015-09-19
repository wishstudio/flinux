/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/syscall_dispatch.h>
#include <syscall/tls.h>
#include <log.h>
#include <platform.h>

#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

extern void *mm_check_read_begin, *mm_check_read_end, *mm_check_read_fail;
extern void *mm_check_read_string_begin, *mm_check_read_string_end, *mm_check_read_string_fail;
extern void *mm_check_write_begin, *mm_check_write_end, *mm_check_write_fail;

extern int sys_gettimeofday(struct timeval *tv, struct timezone *tz);
extern intptr_t sys_time(intptr_t *t);

static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == DBG_CONTROL_C)
		return EXCEPTION_CONTINUE_SEARCH;
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
		return EXCEPTION_CONTINUE_SEARCH;
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		uint8_t* code = (uint8_t *)ep->ContextRecord->Xip;
		if (ep->ExceptionRecord->ExceptionInformation[0] == 8)
		{
			/* DEP problem */
			if (mm_handle_page_fault(code, false))
				return EXCEPTION_CONTINUE_EXECUTION;
			else
			{
				/* The problem may be actually in the next page */
				if (mm_handle_page_fault(code + PAGE_SIZE, false))
					return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		else
		{
			/* Read/write problem */
			log_info("IP: 0x%p", ep->ContextRecord->Xip);
			bool is_write = (ep->ExceptionRecord->ExceptionInformation[0] == 1);
			if (mm_handle_page_fault((void *)ep->ExceptionRecord->ExceptionInformation[1], is_write))
				return EXCEPTION_CONTINUE_EXECUTION;
			void *ip = (void *)ep->ContextRecord->Xip;
			if (ip >= &mm_check_read_begin && ip <= &mm_check_read_end)
			{
				ep->ContextRecord->Xip = (XWORD)&mm_check_read_fail;
				log_warning("mm_check_read() failed at location 0x%x", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			if (ip >= &mm_check_read_string_begin && ip <= &mm_check_read_string_end)
			{
				ep->ContextRecord->Xip = (XWORD)&mm_check_read_string_fail;
				log_warning("mm_check_read_string() failed at location 0x%x", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			if (ip >= &mm_check_write_begin && ip <= &mm_check_write_end)
			{
				ep->ContextRecord->Xip = (XWORD)&mm_check_write_fail;
				log_warning("mm_check_write() failed at location 0x%x", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		if (ep->ExceptionRecord->ExceptionInformation[0] == 0)
			log_error("Page fault(read): %p at %p", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Xip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 1)
			log_error("Page fault(write): %p at %p", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Xip);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 8)
			log_error("Page fault(DEP): %p at %p", ep->ExceptionRecord->ExceptionInformation[1], ep->ContextRecord->Xip);
	}
	log_info("Application crashed, dumping debug information...");
	mm_dump_memory_mappings();
	mm_dump_windows_memory_mappings(GetCurrentProcess());
	mm_dump_stack_trace(ep->ContextRecord);
#ifdef _WIN64
	log_info("RAX: 0x%p", ep->ContextRecord->Rax);
	log_info("RCX: 0x%p", ep->ContextRecord->Rcx);
	log_info("RDX: 0x%p", ep->ContextRecord->Rdx);
	log_info("RBX: 0x%p", ep->ContextRecord->Rbx);
	log_info("RSP: 0x%p", ep->ContextRecord->Rsp);
	log_info("RBP: 0x%p", ep->ContextRecord->Rbp);
	log_info("RSI: 0x%p", ep->ContextRecord->Rsi);
	log_info("RDI: 0x%p", ep->ContextRecord->Rdi);
	log_info("R8:  0x%p", ep->ContextRecord->R8);
	log_info("R9:  0x%p", ep->ContextRecord->R9);
	log_info("R10: 0x%p", ep->ContextRecord->R10);
	log_info("R11: 0x%p", ep->ContextRecord->R11);
	log_info("R12: 0x%p", ep->ContextRecord->R12);
	log_info("R13: 0x%p", ep->ContextRecord->R13);
	log_info("R14: 0x%p", ep->ContextRecord->R14);
	log_info("R15: 0x%p", ep->ContextRecord->R15);
#else
	log_info("EAX: 0x%p", ep->ContextRecord->Eax);
	log_info("ECX: 0x%p", ep->ContextRecord->Ecx);
	log_info("EDX: 0x%p", ep->ContextRecord->Edx);
	log_info("EBX: 0x%p", ep->ContextRecord->Ebx);
	log_info("ESP: 0x%p", ep->ContextRecord->Esp);
	log_info("EBP: 0x%p", ep->ContextRecord->Ebp);
	log_info("ESI: 0x%p", ep->ContextRecord->Esi);
	log_info("EDI: 0x%p", ep->ContextRecord->Edi);
#endif
	/* If we come here we're sure to crash, so gracefully close logging */
	log_shutdown();
	return EXCEPTION_CONTINUE_SEARCH;
}

void install_syscall_handler()
{
	if (!AddVectoredExceptionHandler(TRUE, exception_handler))
		log_error("AddVectoredExceptionHandler() failed.");
}
