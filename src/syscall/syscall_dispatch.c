#include <syscall/syscall_dispatch.h>

#include <stdint.h>

#ifdef _WIN64

typedef int64_t syscall_fn(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int r8, int r9, PCONTEXT context);

#define SYSCALL_COUNT 312
#define SYSCALL(name) extern int64_t name(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int r8, int r9, PCONTEXT context);
SYSCALL(sys_read) /* syscall 0 */
#include "syscall_table_x64.h"
#undef SYSCALL

#define SYSCALL(name) name,
static syscall_fn* syscall_table[SYSCALL_COUNT] =
{
	sys_read, /* syscall 0 */
#include "syscall_table_x64.h"
};
#undef SYSCALL

#else

typedef int syscall_fn(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context);

#define SYSCALL_COUNT 338
#define SYSCALL(name) extern int name(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context);
#include "syscall_table_x86.h"
#undef SYSCALL

#define SYSCALL(name) name,
static syscall_fn* syscall_table[SYSCALL_COUNT] =
{
	sys_unimplemented, /* syscall 0 */
#include "syscall_table_x86.h"
};
#undef SYSCALL
#endif

size_t sys_unimplemented(size_t _1, size_t _2, size_t _3, size_t _4, size_t _5, size_t _6, PCONTEXT context)
{
#ifdef _WIN64
	log_error("FATAL: Unimplemented syscall: %d\n", (int)context->Rax);
#else
	log_error("FATAL: Unimplemented syscall: %d\n", context->Eax);
#endif
	ExitProcess(1);
}

void dispatch_syscall(PCONTEXT context)
{
#ifdef _WIN64
	context->Rax = (*syscall_table[context->Rax])(context->Rdi, context->Rsi, context->Rdx, context->R10, context->R8, context->R9, context);
#else
	context->Eax = (*syscall_table[context->Eax])(context->Ebx, context->Ecx, context->Edx, context->Esi, context->Edi, context->Ebp, context);
#endif
}
