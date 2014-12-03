#pragma once

#include <stdint.h>

#define _MACROCALL()

#define _SYSCALL_NARG(...) _SYSCALL_NARG_ _MACROCALL() (__VA_ARGS__, _SYSCALL_RSEQ_N())
#define _SYSCALL_NARG_(...) _SYSCALL_ARG_N _MACROCALL() (__VA_ARGS__)
#define _SYSCALL_ARG_N(_T1, _N1, _T2, _N2, _T3, _N3, _T4, _N4, _T5, _N5, _T6, _N6, _T7, _N7, _T8, _N8, _N, ...) _N
#define _SYSCALL_RSEQ_N() \
	_SYSCALL_MAP8, _SYSCALL_MAP8, \
	_SYSCALL_MAP7, _SYSCALL_MAP7, \
	_SYSCALL_MAP6, _SYSCALL_MAP6, \
	_SYSCALL_MAP5, _SYSCALL_MAP5, \
	_SYSCALL_MAP4, _SYSCALL_MAP4, \
	_SYSCALL_MAP3, _SYSCALL_MAP3, \
	_SYSCALL_MAP2, _SYSCALL_MAP2, \
	_SYSCALL_MAP1, _SYSCALL_MAP0

#define _SYSCALL_MAP0(f)
#define _SYSCALL_MAP1(f, t, n, ...) f(t, n)
#define _SYSCALL_MAP2(f, t, n, ...) f(t, n), _SYSCALL_MAP1 _MACROCALL() (f, __VA_ARGS__)
#define _SYSCALL_MAP3(f, t, n, ...) f(t, n), _SYSCALL_MAP2 _MACROCALL() (f, __VA_ARGS__)
#define _SYSCALL_MAP4(f, t, n, ...) f(t, n), _SYSCALL_MAP3 _MACROCALL() (f, __VA_ARGS__)
#define _SYSCALL_MAP5(f, t, n, ...) f(t, n), _SYSCALL_MAP4 _MACROCALL() (f, __VA_ARGS__)
#define _SYSCALL_MAP6(f, t, n, ...) f(t, n), _SYSCALL_MAP5 _MACROCALL() (f, __VA_ARGS__)
#define _SYSCALL_MAP7(f, t, n, ...) f(t, n), _SYSCALL_MAP6 _MACROCALL() (f, __VA_ARGS__)
#define _SYSCALL_MAP8(f, t, n, ...) f(t, n), _SYSCALL_MAP7 _MACROCALL() (f, __VA_ARGS__)
#define _SYSCALL_MAP(f, ...) \
	_SYSCALL_NARG _MACROCALL() (__VA_ARGS__) _MACROCALL() (f, __VA_ARGS__)

#define _SYSCALL_WRAPPER(t, n) intptr_t n
#define _SYSCALL_CALL(t, n) (t)n
#define _SYSCALL_ACTUAL(t, n) t n

#define DEFINE_SYSCALL(name, ...) \
	intptr_t sys_##name(_SYSCALL_MAP _MACROCALL() (_SYSCALL_ACTUAL, __VA_ARGS__)); \
	static intptr_t _sys_##name(_SYSCALL_MAP _MACROCALL() (_SYSCALL_WRAPPER, __VA_ARGS__)) \
	{ \
		return sys_##name(_SYSCALL_MAP _MACROCALL() (_SYSCALL_CALL, __VA_ARGS__)); \
	} \
	intptr_t sys_##name(_SYSCALL_MAP _MACROCALL() (_SYSCALL_ACTUAL, __VA_ARGS__))

void install_syscall_handler();
