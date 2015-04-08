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

#include <common/errno.h>
#include <common/sigcontext.h>
#include <common/sigframe.h>
#include <common/signal.h>
#include <syscall/mm.h>
#include <syscall/sig.h>
#include <syscall/syscall.h>
#include <log.h>
#include <str.h>

#include <stdbool.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct signal_data
{
	HANDLE thread;
	HANDLE sigread, sigwrite;
	CRITICAL_SECTION mutex;
	
	HANDLE main_thread;
	struct sigaction actions[_NSIG];
	sigset_t mask, pending;
	siginfo_t info[_NSIG]; /* siginfo which is currently pending */
	siginfo_t current_siginfo; /* Current siginfo to be delivered */
	bool can_accept_signal;
};

#define SIGNAL_PACKET_SHUTDOWN		0 /* Shutdown signal thread */
#define SIGNAL_PACKET_KILL			1 /* Send signal */
struct signal_packet
{
	int type;
	siginfo_t info;
};

static struct signal_data *const signal = (struct signal_data *)SIGNAL_DATA_BASE;

static DWORD WINAPI signal_thread(LPVOID parameter)
{
	/* CAUTION: Never use logging in signal thread */
	for (;;)
	{
		struct signal_packet packet;
		DWORD read;
		if (!ReadFile(signal->sigread, &packet, sizeof(struct signal_packet), &read, NULL)
			|| read != sizeof(struct signal_packet))
		{
			/* TODO: Log error message */
			return 1;
		}
		switch (packet.type)
		{
		case SIGNAL_PACKET_SHUTDOWN: return 0;
		case SIGNAL_PACKET_KILL:
		{
			int signo = packet.info.si_signo;
			EnterCriticalSection(&signal->mutex);
			if (!sigismember(&signal->pending, signo))
			{
				if (sigismember(&signal->mask, signo) || !signal->can_accept_signal)
				{
					/* Cannot deliver the signal, mark it as pending and save the info */
					sigaddset(&signal->pending, signo);
					signal->info[signo] = packet.info;
				}
				else
				{
					signal->can_accept_signal = false;
					CONTEXT context;
					SuspendThread(signal->main_thread);
					GetThreadContext(signal->main_thread, &context);
					dbt_deliver_signal(signal->main_thread, &context);
					signal->current_siginfo = packet.info;
					SetThreadContext(signal->main_thread, &context);
					ResumeThread(signal->main_thread);
				}
			}
			LeaveCriticalSection(&signal->mutex);
			break;
		}
		default:
		{
			/* TODO: Log error message */
			return 1;
		}
		}
	}
}

void fpu_fxsave(void *save_area);
void fpu_fxrstor(void *save_area);
void signal_restorer();
static void signal_save_sigcontext(struct sigcontext *sc, struct syscall_context *context, void *fpstate, uint32_t mask)
{
	/* TODO: Add missing register values */
	sc->gs = 0;
	sc->fs = 0;
	sc->es = 0;
	sc->ds = 0;
	sc->di = context->edi;
	sc->si = context->esi;
	sc->bp = context->ebp;
	sc->sp = context->esp;
	sc->bx = context->ebx;
	sc->dx = context->edx;
	sc->cx = context->ecx;
	sc->ax = context->eax;
	sc->trapno = 0;
	sc->err = 0;
	sc->ip = context->eip;
	sc->cs = 0;
	sc->flags = context->eflags;
	sc->sp_at_signal = context->esp;
	sc->ss = 0;
	sc->fpstate = fpstate;
	sc->oldmask = mask;
	sc->cr2 = 0;
}

void signal_setup_handler(struct syscall_context *context)
{
	int sig = signal->current_siginfo.si_signo;
	uintptr_t sp = context->esp;
	/* TODO: Make fpstate layout the same as in Linux kernel */
	/* Allocate fpstate space */
	sp -= sizeof(struct fpstate);
	/* Align fpstate to 512 byte boundary */
	sp = sp & -512UL;
	void *fpstate = (void*)sp;
	fpu_fxsave(fpstate);

	/* Allocate sigcontext space */
	sp -= sizeof(struct rt_sigframe);
	/* align: ((sp + 4) & 15) == 0 */
	sp = ((sp + 4) & -16UL) - 4;

	struct rt_sigframe *frame = (struct rt_sigframe *)sp;
	frame->pretcode = (uint32_t)signal->actions[sig].sa_restorer; /* FIXME: fix race */
	if (frame->pretcode == 0)
		frame->pretcode = (uint32_t)signal_restorer;
	frame->sig = sig;
	frame->info = signal->current_siginfo;
	frame->pinfo = (uint32_t)&frame->info;
	frame->puc = (uint32_t)&frame->uc;

	frame->uc.uc_flags = 0;
	frame->uc.uc_link = 0;
	/* TODO: frame->uc.uc_stack */
	EnterCriticalSection(&signal->mutex);
	frame->uc.uc_sigmask = signal->mask;
	signal_save_sigcontext(&frame->uc.uc_mcontext, context, fpstate, (uint32_t)signal->mask);
	sigaddset(&signal->mask, frame->sig);
	signal->mask |= signal->actions[sig].sa_mask; /* FIXME: fix race */
	signal->can_accept_signal = true;
	LeaveCriticalSection(&signal->mutex);
	/* TODO: frame->retcode */

	/* Redirect control flow to handler */
	context->esp = (DWORD)frame;
	context->eip = (DWORD)signal->actions[sig].sa_handler; /* FIXME: fix race */
	context->eax = (DWORD)sig;
	context->edx = (DWORD)&frame->info;
	context->ecx = (DWORD)&frame->uc;
}

DEFINE_SYSCALL(rt_sigreturn, uintptr_t, bx, uintptr_t, cx, uintptr_t, dx, uintptr_t, si, uintptr_t, di,
	uintptr_t, bp, uintptr_t, sp, uintptr_t, ip)
{
	struct rt_sigframe *frame = (struct rt_sigframe *)(sp - sizeof(uintptr_t));
	if (!mm_check_read(frame, sizeof(*frame)))
	{
		log_error("sigreturn: Invalid frame.\n");
		return -EFAULT;
	}
	/* TODO: Check validity of fpstate */
	fpu_fxrstor(frame->uc.uc_mcontext.fpstate);
	EnterCriticalSection(&signal->mutex);
	signal->mask = frame->uc.uc_sigmask;
	LeaveCriticalSection(&signal->mutex);
	
	dbt_sigreturn(&frame->uc.uc_mcontext);
}

/* Create a uni-direction, message based pipe */
static volatile long process_pipe_count = 0;
static bool create_pipe(HANDLE *read, HANDLE *write)
{
	char pipe_name[256];
	long pipe_id = InterlockedIncrement(&process_pipe_count);
	ksprintf(pipe_name, "\\\\.\\pipe\\flinux-fsig%d-%d", GetCurrentProcessId(), pipe_id);
	HANDLE server = CreateNamedPipeA(pipe_name,
		PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		PAGE_SIZE,
		PAGE_SIZE,
		0,
		NULL);
	if (server == INVALID_HANDLE_VALUE)
		return false;
	HANDLE client = CreateFileA(pipe_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (client == INVALID_HANDLE_VALUE)
	{
		CloseHandle(server);
		return false;
	}
	if (!ConnectNamedPipe(server, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
	{
		CloseHandle(server);
		CloseHandle(client);
	}
	*read = server;
	*write = client;
	return true;
}

static void send_packet(HANDLE sigwrite, struct signal_packet *packet)
{
	DWORD written;
	WriteFile(sigwrite, packet, sizeof(struct signal_packet), &written, NULL);
	/* TODO: Handle error */
}

static void signal_init_private()
{
	/* Initialize private structures and handles */
	sigemptyset(&signal->pending);
	if (!create_pipe(&signal->sigread, &signal->sigwrite))
	{
		log_error("Signal pipe creation failed, error code: %d\n", GetLastError());
		return;
	}
	signal->can_accept_signal = true;

	/* Get the handle to main thread */
	if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &signal->main_thread,
		0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		log_error("Get main thread handle failed, error code: %d\n", GetLastError());
		return;
	}

	/* Create signal thread */
	InitializeCriticalSection(&signal->mutex);
	signal->thread = CreateThread(NULL, PAGE_SIZE, signal_thread, NULL, 0, NULL);
	if (!signal->thread)
		log_error("Signal thread creation failed, error code: %d.\n", GetLastError());
}

void signal_init()
{
	/* Initialize signal structures */
	mm_mmap(signal, sizeof(struct signal_data), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, NULL, 0);
	for (int i = 0; i < _NSIG; i++)
	{
		signal->actions[i].sa_sigaction = NULL;
		sigemptyset(&signal->actions[i].sa_mask);
		signal->actions[i].sa_flags = 0;
		signal->actions[i].sa_restorer = NULL;
	}
	sigemptyset(&signal->mask);
	signal_init_private();
}

void signal_afterfork()
{
	signal_init_private();
}

void signal_shutdown()
{
	struct signal_packet packet;
	packet.type = SIGNAL_PACKET_SHUTDOWN;
	send_packet(signal->sigwrite, &packet);

	WaitForSingleObject(signal->thread, INFINITE);
	DeleteCriticalSection(&signal->mutex);
	CloseHandle(signal->sigread);
	CloseHandle(signal->sigwrite);
	mm_munmap(signal, sizeof(struct signal_data));
}

int signal_kill(pid_t pid, siginfo_t *info)
{
	if (pid == GetCurrentProcessId())
	{
		struct signal_packet packet;
		packet.type = SIGNAL_PACKET_KILL;
		packet.info = *info;
		send_packet(signal->sigwrite, &packet);
		return 0;
	}
	else
	{
		log_error("signal_kill: Killing other processes are not supported.\n");
		return -ESRCH;
	}
}

DEFINE_SYSCALL(alarm, unsigned int, seconds)
{
	log_info("alarm(%d)\n", seconds);
	log_error("alarm() not implemented.\n");
	return 0;
}

DEFINE_SYSCALL(kill, pid_t, pid, int, sig)
{
	log_info("kill(%d, %d)\n", pid, sig);
	log_error("kill() not implemented.\n");
	return 0;
}

DEFINE_SYSCALL(tgkill, pid_t, tgid, pid_t, pid, int, sig)
{
	log_info("tgkill(%d, %d, %d)\n", tgid, pid, sig);
	log_error("tgkill() not implemented.\n");
	return 0;
}

DEFINE_SYSCALL(personality, unsigned long, persona)
{
	log_info("personality(%d)\n", persona);
	if (persona != 0 && persona != 0xFFFFFFFFU)
	{
		log_error("ERROR: persona != 0");
		return -EINVAL;
	}
	return 0;
}

DEFINE_SYSCALL(rt_sigaction, int, signum, const struct sigaction *, act, struct sigaction *, oldact, size_t, sigsetsize)
{
	log_info("rt_sigaction(%d, %p, %p)\n", signum, act, oldact);
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;
	if (signum < 0 || signum >= _NSIG || signum == SIGKILL || signum == SIGSTOP)
		return -EINVAL;
	if (act && !mm_check_read(act, sizeof(*act)))
		return -EFAULT;
	if (oldact && !mm_check_write(oldact, sizeof(*oldact)))
		return -EFAULT;
	EnterCriticalSection(&signal->mutex);
	if (oldact)
		memcpy(oldact, &signal->actions[signum], sizeof(struct sigaction));
	if (act)
		memcpy(&signal->actions[signum], act, sizeof(struct sigaction));
	LeaveCriticalSection(&signal->mutex);
	return 0;
}

DEFINE_SYSCALL(rt_sigprocmask, int, how, const sigset_t *, set, sigset_t *, oldset, size_t, sigsetsize)
{
	log_info("rt_sigprocmask(%d, 0x%p, 0x%p)\n", how, set, oldset);
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;
	if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK)
		return -EINVAL;
	if (set && !mm_check_read(set, sizeof(*set)))
		return -EFAULT;
	if (oldset && !mm_check_write(oldset, sizeof(*oldset)))
		return -EFAULT;
	EnterCriticalSection(&signal->mutex);
	if (oldset)
		*oldset = signal->mask;
	if (set)
	{
		switch (how)
		{
		case SIG_BLOCK:
			signal->mask |= *set;
			break;

		case SIG_UNBLOCK:
			signal->mask &= ~*set;
			break;

		case SIG_SETMASK:
			signal->mask = *set;
			break;
		}
	}
	/* TODO: Deliver signal when masked pending signal is being unmasked */
	LeaveCriticalSection(&signal->mutex);
	return 0;
}

DEFINE_SYSCALL(sigaltstack, const stack_t *, ss, stack_t *, oss)
{
	log_info("sigaltstack(ss=%p, oss=%p)\n", ss, oss);
	log_error("sigaltstack() not implemented.\n");
	return -ENOSYS;
}
