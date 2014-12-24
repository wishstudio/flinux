#include <syscall/syscall.h>
#include <syscall/syscall_dispatch.h>
#include <log.h>

#include <stdint.h>

#ifdef _WIN64

typedef int64_t syscall_fn(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, intptr_t r8, intptr_t r9, PCONTEXT context);

#define SYSCALL_COUNT 312
#define SYSCALL(name) extern int64_t sys_##name(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, intptr_t r8, intptr_t r9, PCONTEXT context);
SYSCALL(read) /* syscall 0 */
#include "syscall_table_x64.h"
#undef SYSCALL

#define SYSCALL(name) sys_##name,
static syscall_fn* syscall_table[SYSCALL_COUNT] =
{
	SYSCALL(read) /* syscall 0 */
#include "syscall_table_x64.h"
};
#undef SYSCALL

#else

typedef int syscall_fn(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context);

#define SYSCALL_COUNT 338
#define SYSCALL(name) extern int sys_##name(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context);
#include "syscall_table_x86.h"
#undef SYSCALL

#define SYSCALL(name) sys_##name,
syscall_fn* syscall_table[SYSCALL_COUNT] =
{
	SYSCALL(unimplemented) /* syscall 0 */
#include "syscall_table_x86.h"
};
#undef SYSCALL
#endif

void sys_unimplemented_imp(intptr_t id)
{
	log_error("FATAL: Unimplemented syscall: %d\n", id);
	ExitProcess(1);
}

void dispatch_syscall(PCONTEXT context)
{
#ifdef _WIN64
	context->Rax = (*syscall_table[context->Rax])(context->Rdi, context->Rsi, context->Rdx, context->R10, context->R8, context->R9, context);
#endif
}
