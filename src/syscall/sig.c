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
#include <syscall/process.h>
#include <syscall/process_info.h>
#include <syscall/sig.h>
#include <syscall/syscall.h>
#include <log.h>
#include <str.h>

#include <limits.h>
#include <stdbool.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct signal_data
{
	HANDLE thread;
	HANDLE iocp;
	HANDLE sigread, sigwrite;
	HANDLE process_wait_semaphore;
	HANDLE query_mutex;
	CRITICAL_SECTION mutex;

	struct sigaction actions[_NSIG];
	sigset_t pending;
	siginfo_t pending_info[_NSIG]; /* siginfo which is currently pending */
};

#define SIGNAL_PACKET_SHUTDOWN		0 /* Shutdown signal thread */
#define SIGNAL_PACKET_KILL			1 /* Send signal */
#define SIGNAL_PACKET_DELIVER		2 /* Deliver existing pending signal to thread */
#define SIGNAL_PACKET_ADD_PROCESS	3 /* Add a child process for listening */
#define SIGNAL_PACKET_QUERY			4 /* Inter-process information query (used for /proc/[pid]) */
struct signal_packet
{
	int type;
	union
	{
		siginfo_t info;
		struct child_process *proc;
		int query_type;
	};
};

static struct signal_data *signal;

/* Create a uni-direction, message based pipe */
static volatile long process_pipe_count = 0;
static bool create_pipe(HANDLE *read, HANDLE *write, bool is_duplex)
{
	DWORD open_mode = is_duplex ? PIPE_ACCESS_DUPLEX : PIPE_ACCESS_INBOUND;
	char pipe_name[256];
	long pipe_id = InterlockedIncrement(&process_pipe_count);
	ksprintf(pipe_name, "\\\\.\\pipe\\flinux-fsig%d-%d", GetCurrentProcessId(), pipe_id);
	HANDLE server = CreateNamedPipeA(pipe_name,
		open_mode | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		PAGE_SIZE,
		PAGE_SIZE,
		0,
		NULL);
	if (server == INVALID_HANDLE_VALUE)
		return false;
	DWORD desired_access = is_duplex ? GENERIC_READ | GENERIC_WRITE : GENERIC_WRITE;
	HANDLE client = CreateFileA(pipe_name, desired_access, 0, NULL, OPEN_EXISTING, 0, NULL);
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

static void signal_default_handler(siginfo_t *info)
{
	switch (info->si_signo)
	{
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGILL:
	case SIGABRT:
	case SIGFPE:
	case SIGKILL:
	case SIGSEGV:
	case SIGPIPE:
	case SIGALRM:
	case SIGTERM:
	case SIGUSR1:
	case SIGUSR2:
		process_exit(0, info->si_signo);
		break;
	}
}

/* Try to deliver a signal, return true if it is successfully delivered */
/* Caller ensures signal mutex is acquired */
static bool signal_thread_deliver_signal(siginfo_t *info)
{
	int sig = info->si_signo;
	if (signal->actions[sig].sa_handler == SIG_IGN)
		return true;
	else if (signal->actions[sig].sa_handler == SIG_DFL)
	{
		signal_default_handler(info);
		return true;
	}

	/* Find a thread which can accept the signal */
	struct thread *thread = NULL;
	struct list_node *cur;
	list_iterate(&process->thread_list, cur)
	{
		struct thread *t = list_entry(cur, struct thread, list);
		if (!sigismember(&t->sigmask, sig) && t->can_accept_signal)
		{
			thread = t;
			break;
		}
	}
	if (!thread)
		return false;

	thread->can_accept_signal = false;
	CONTEXT context;
	context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
	SuspendThread(thread->handle);
	GetThreadContext(thread->handle, &context);
	dbt_deliver_signal(thread->handle, &context);
	thread->current_siginfo = *info;
	SetEvent(thread->sigevent);
	SetThreadContext(thread->handle, &context);
	ResumeThread(thread->handle);
	return true;
}

static void signal_thread_handle_kill(struct siginfo *info)
{
	int signo = info->si_signo;
	EnterCriticalSection(&signal->mutex);
	if (!signal_thread_deliver_signal(info))
	{
		/* Cannot deliver the signal, mark it as pending and save the info */
		sigaddset(&signal->pending, signo);
		signal->pending_info[signo] = *info;
	}
	LeaveCriticalSection(&signal->mutex);
}

static void signal_thread_handle_child_terminated(struct child_process *proc)
{
	struct siginfo info;
	info.si_signo = SIGCHLD;
	info.si_code = 0;
	info.si_errno = 0;
	signal_thread_handle_kill(&info);
	proc->terminated = true;
	ReleaseSemaphore(signal->process_wait_semaphore, 1, NULL);
}

static DWORD WINAPI signal_thread(LPVOID parameter)
{
	log_init_thread();
	log_info("Signal thread started.");
	OVERLAPPED packet_overlapped;
	memset(&packet_overlapped, 0, sizeof(OVERLAPPED));
	char buf[1];
	struct signal_packet packet;
	ReadFile(signal->sigread, &packet, sizeof(struct signal_packet), NULL, &packet_overlapped);
	for (;;)
	{
		DWORD bytes;
		ULONG_PTR key;
		LPOVERLAPPED overlapped;
		BOOL succeed = GetQueuedCompletionStatus(signal->iocp, &bytes, &key, &overlapped, INFINITE);
		if (key == 0)
		{
			/* Signal packet */
			switch (packet.type)
			{
			case SIGNAL_PACKET_SHUTDOWN: return 0;
			case SIGNAL_PACKET_KILL:
			{
				signal_thread_handle_kill(&packet.info);
				break;
			}
			case SIGNAL_PACKET_DELIVER:
			{
				EnterCriticalSection(&signal->mutex);
				AcquireSRWLockShared(&process->rw_lock);
				for (int i = 0; i < _NSIG; i++)
					if (sigismember(&signal->pending, i))
					{
						if (signal_thread_deliver_signal(&signal->pending_info[i]))
							sigdelset(&signal->pending, i);
					}
				ReleaseSRWLockShared(&process->rw_lock);
				LeaveCriticalSection(&signal->mutex);
				break;
			}
			case SIGNAL_PACKET_ADD_PROCESS:
			{
				struct child_process *proc = packet.proc;
				CreateIoCompletionPort(proc->hPipe, signal->iocp, (ULONG_PTR)proc, 1);
				memset(&proc->overlapped, 0, sizeof(OVERLAPPED));
				if (!ReadFile(proc->hPipe, buf, 1, NULL, &proc->overlapped) && GetLastError() != ERROR_IO_PENDING)
					signal_thread_handle_child_terminated(proc);
				break;
			}
			case SIGNAL_PACKET_QUERY:
			{
				struct
				{
					int len;
					char buf[65536];
				} data;
				data.len = process_query(packet.query_type, data.buf);
				DWORD written;
				WriteFile(signal->sigread, &data, sizeof(int) + data.len, &written, NULL);
				/* TODO: Avoid blocking when the other end died */
				break;
			}
			default:
			{
				/* TODO: Log error message */
				return 1;
			}
			}
			ReadFile(signal->sigread, &packet, sizeof(struct signal_packet), NULL, &packet_overlapped);
		}
		else
		{
			/* One child died */
			struct child_process *proc = (struct child_process *)key;
			signal_thread_handle_child_terminated(proc);
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
	int sig = current_thread->current_siginfo.si_signo;
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
	frame->info = current_thread->current_siginfo;
	frame->pinfo = (uint32_t)&frame->info;
	frame->puc = (uint32_t)&frame->uc;

	frame->uc.uc_flags = 0;
	frame->uc.uc_link = 0;
	/* TODO: frame->uc.uc_stack */
	EnterCriticalSection(&signal->mutex);
	frame->uc.uc_sigmask = current_thread->sigmask;
	signal_save_sigcontext(&frame->uc.uc_mcontext, context, fpstate, (uint32_t)current_thread->sigmask);
	sigaddset(&current_thread->sigmask, frame->sig);
	current_thread->sigmask |= signal->actions[sig].sa_mask; /* FIXME: fix race */
	current_thread->can_accept_signal = true;
	ResetEvent(current_thread->sigevent);
	LeaveCriticalSection(&signal->mutex);
	/* TODO: frame->retcode */

	/* Redirect control flow to handler */
	context->esp = (DWORD)frame;
	context->eip = (DWORD)signal->actions[sig].sa_handler; /* FIXME: fix race */
	context->eax = (DWORD)sig;
	context->edx = (DWORD)&frame->info;
	context->ecx = (DWORD)&frame->uc;
}

static void send_packet(HANDLE sigwrite, struct signal_packet *packet)
{
	DWORD written;
	WriteFile(sigwrite, packet, sizeof(struct signal_packet), &written, NULL);
	/* TODO: Handle error */
}

HANDLE signal_get_process_wait_semaphore()
{
	return signal->process_wait_semaphore;
}

HANDLE signal_get_process_sigwrite()
{
	return signal->sigwrite;
}

HANDLE signal_get_process_query_mutex()
{
	return signal->query_mutex;
}

/* Process waiting mechanism:
 * We create a pipe and duplicate the write end in the child.
 * Then we read the pipe through signal IOCP.
 * When the child terminates, the write end of the pipe will be closed,
 * which will cause the read to error and we have a chance to know that the child died.
 * This works even the child terminates abnormally, and supports an arbitrary number of child processes.
 */
void signal_init_child(struct child_process *proc)
{
	HANDLE read, write;
	create_pipe(&read, &write, false);
	proc->hPipe = read;
	/* Duplicate and leak write end handle in the child process */
	HANDLE target;
	DuplicateHandle(GetCurrentProcess(), write, proc->hProcess, &target, 0, FALSE,
		DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
	struct signal_packet packet;
	packet.type = SIGNAL_PACKET_ADD_PROCESS;
	packet.proc = proc;
	send_packet(signal->sigwrite, &packet);
}

/* Deliver signal when masked pending signal is being unmasked */
/* Caller ensures the signal mutex is acquired */
static void send_pending_signal()
{
	if (signal->pending & ~current_thread->sigmask)
	{
		struct signal_packet packet;
		packet.type = SIGNAL_PACKET_DELIVER;
		send_packet(signal->sigwrite, &packet);
	}
}

DEFINE_SYSCALL(rt_sigreturn, uintptr_t, bx, uintptr_t, cx, uintptr_t, dx, uintptr_t, si, uintptr_t, di,
	uintptr_t, bp, uintptr_t, sp, uintptr_t, ip)
{
	struct rt_sigframe *frame = (struct rt_sigframe *)(sp - sizeof(uintptr_t));
	if (!mm_check_read(frame, sizeof(*frame)))
	{
		log_error("sigreturn: Invalid frame.");
		return -L_EFAULT;
	}
	/* TODO: Check validity of fpstate */
	fpu_fxrstor(frame->uc.uc_mcontext.fpstate);
	EnterCriticalSection(&signal->mutex);
	current_thread->sigmask = frame->uc.uc_sigmask;
	send_pending_signal();
	LeaveCriticalSection(&signal->mutex);
	
	dbt_sigreturn(&frame->uc.uc_mcontext);
}

static void signal_init_private()
{
	/* Initialize private structures and handles */
	if (!create_pipe(&signal->sigread, &signal->sigwrite, true))
	{
		log_error("Signal pipe creation failed, error code: %d", GetLastError());
		return;
	}
	signal->process_wait_semaphore = CreateSemaphoreW(NULL, 0, LONG_MAX, NULL);
	signal->iocp = CreateIoCompletionPort(signal->sigread, NULL, 0, 1);
	signal->query_mutex = CreateMutexW(NULL, FALSE, L"");

	/* Create signal thread */
	sigemptyset(&signal->pending);
	InitializeCriticalSection(&signal->mutex);
	signal->thread = CreateThread(NULL, 0, signal_thread, NULL, 0, NULL);
	if (!signal->thread)
		log_error("Signal thread creation failed, error code: %d.", GetLastError());
}

void signal_init()
{
	/* Initialize signal structures */
	signal = mm_static_alloc(sizeof(struct signal_data));
	for (int i = 0; i < _NSIG; i++)
	{
		signal->actions[i].sa_sigaction = NULL;
		sigemptyset(&signal->actions[i].sa_mask);
		signal->actions[i].sa_flags = 0;
		signal->actions[i].sa_restorer = NULL;
	}
	signal_init_private();
}

void signal_afterfork_child()
{
	signal = mm_static_alloc(sizeof(struct signal_data));
	signal_init_private();
}

int signal_fork(HANDLE process)
{
	EnterCriticalSection(&signal->mutex);
	return 1;
}

void signal_afterfork_parent()
{
	LeaveCriticalSection(&signal->mutex);
}

void signal_shutdown()
{
	struct signal_packet packet;
	packet.type = SIGNAL_PACKET_SHUTDOWN;
	send_packet(signal->sigwrite, &packet);
	WaitForSingleObject(signal->thread, INFINITE);

	CloseHandle(signal->query_mutex);
	DeleteCriticalSection(&signal->mutex);
	CloseHandle(signal->sigread);
	CloseHandle(signal->sigwrite);
}

void signal_init_thread(struct thread *thread)
{
	thread->sigevent = CreateEvent(NULL, TRUE, FALSE, NULL);
	sigemptyset(&thread->sigmask); /* TODO: Keep signal mask on fork */
	thread->can_accept_signal = true;
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
		log_error("signal_kill: Killing other processes are not supported.");
		return -L_ESRCH;
	}
}

DWORD signal_wait(int count, HANDLE *handles, DWORD milliseconds)
{
	HANDLE h[MAXIMUM_WAIT_OBJECTS];
	for (int i = 0; i < count; i++)
		h[i] = handles[i];
	h[count] = current_thread->sigevent;
	DWORD result = WaitForMultipleObjects(count + 1, h, FALSE, milliseconds);
	if (result == count + WAIT_OBJECT_0)
		return WAIT_INTERRUPTED;
	else
		return result;
}

void signal_before_pwait(const sigset_t *sigmask, sigset_t *oldmask)
{
	/* This function is called from ppoll() */
	/* We reset the signal event object first, any signals received before this
	* is regarded as received before the original system call.
	*/
	EnterCriticalSection(&signal->mutex);
	*oldmask = current_thread->sigmask;
	current_thread->sigmask = *sigmask;
	send_pending_signal();
	ResetEvent(current_thread->sigevent);
	LeaveCriticalSection(&signal->mutex);
}

void signal_after_pwait(const sigset_t *oldmask)
{
	EnterCriticalSection(&signal->mutex);
	current_thread->sigmask = *oldmask;
	send_pending_signal();
	LeaveCriticalSection(&signal->mutex);
}

int signal_query(DWORD win_pid, HANDLE sigwrite, HANDLE query_mutex, int query_type, char *buf)
{
	HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, win_pid);
	if (process == NULL)
		return -L_ENOENT;
	HANDLE pipe, mutex;
	DuplicateHandle(process, sigwrite, GetCurrentProcess(), &pipe, 0, FALSE, DUPLICATE_SAME_ACCESS);
	DuplicateHandle(process, query_mutex, GetCurrentProcess(), &mutex, 0, FALSE, DUPLICATE_SAME_ACCESS);

	/* The query mutex ensures only one process is communicating with the target
	 * to avoid race conditions on the signal pipe
	 */
	if (WaitForSingleObject(mutex, INFINITE) == WAIT_ABANDONED_0)
	{
		/* TODO: Previous query instance crashed while querying
		 * Needs to find one way to properly clear the unread pipe buffer in this case
		 */
		__debugbreak();
	}
	struct signal_packet packet;
	packet.type = SIGNAL_PACKET_QUERY;
	packet.query_type = query_type;
	DWORD written;
	WriteFile(pipe, &packet, sizeof(packet), &written, NULL);
	int len;
	DWORD read;
	ReadFile(pipe, &len, sizeof(int), &read, NULL);
	if (len > 0)
		ReadFile(pipe, buf, len, &read, NULL);
	ReleaseMutex(mutex);

	CloseHandle(mutex);
	CloseHandle(pipe);
	CloseHandle(process);

	if (len == 0)
		return -L_ENOENT;
	else
		return len;
}

DEFINE_SYSCALL(alarm, unsigned int, seconds)
{
	log_info("alarm(%d)", seconds);
	log_error("alarm() not implemented.");
	return 0;
}

DEFINE_SYSCALL(kill, pid_t, pid, int, sig)
{
	log_info("kill(%d, %d)", pid, sig);
	log_error("kill() not implemented.");
	return 0;
}

DEFINE_SYSCALL(tgkill, pid_t, tgid, pid_t, pid, int, sig)
{
	log_info("tgkill(%d, %d, %d)", tgid, pid, sig);
	log_error("tgkill() not implemented.");
	return 0;
}

DEFINE_SYSCALL(personality, unsigned long, persona)
{
	log_info("personality(%d)", persona);
	if (persona != 0 && persona != 0xFFFFFFFFU)
	{
		log_error("ERROR: persona != 0");
		return -L_EINVAL;
	}
	return 0;
}

DEFINE_SYSCALL(rt_sigaction, int, signum, const struct sigaction *, act, struct sigaction *, oldact, size_t, sigsetsize)
{
	log_info("rt_sigaction(%d, %p, %p)", signum, act, oldact);
	if (sigsetsize != sizeof(sigset_t))
		return -L_EINVAL;
	if (signum < 0 || signum >= _NSIG || signum == SIGKILL || signum == SIGSTOP)
		return -L_EINVAL;
	if (act && !mm_check_read(act, sizeof(*act)))
		return -L_EFAULT;
	if (oldact && !mm_check_write(oldact, sizeof(*oldact)))
		return -L_EFAULT;
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
	log_info("rt_sigprocmask(%d, 0x%p, 0x%p)", how, set, oldset);
	if (sigsetsize != sizeof(sigset_t))
		return -L_EINVAL;
	if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK)
		return -L_EINVAL;
	if (set && !mm_check_read(set, sizeof(*set)))
		return -L_EFAULT;
	if (oldset && !mm_check_write(oldset, sizeof(*oldset)))
		return -L_EFAULT;
	EnterCriticalSection(&signal->mutex);
	if (oldset)
		*oldset = current_thread->sigmask;
	if (set)
	{
		switch (how)
		{
		case SIG_BLOCK:
			current_thread->sigmask |= *set;
			break;

		case SIG_UNBLOCK:
			current_thread->sigmask &= ~*set;
			break;

		case SIG_SETMASK:
			current_thread->sigmask = *set;
			break;
		}
	}
	send_pending_signal();
	LeaveCriticalSection(&signal->mutex);
	return 0;
}

DEFINE_SYSCALL(rt_sigsuspend, const sigset_t *, mask)
{
	log_info("rt_sigsuspend(%p)", mask);
	if (!mm_check_read(mask, sizeof(*mask)))
		return -L_EFAULT;
	sigset_t oldmask;
	/* TODO: Is this race free? */
	EnterCriticalSection(&signal->mutex);
	oldmask = current_thread->sigmask;
	current_thread->sigmask = *mask;
	LeaveCriticalSection(&signal->mutex);
	signal_wait(0, NULL, INFINITE);
	EnterCriticalSection(&signal->mutex);
	current_thread->sigmask = oldmask;
	LeaveCriticalSection(&signal->mutex);
	return -L_EINTR;
}

DEFINE_SYSCALL(sigaltstack, const stack_t *, ss, stack_t *, oss)
{
	log_info("sigaltstack(ss=%p, oss=%p)", ss, oss);
	log_error("sigaltstack() not implemented.");
	return -L_ENOSYS;
}
