#include <syscall/sig.h>
#include <log.h>

#include <Windows.h>

int sys_personality(unsigned long persona)
{
	log_debug("personality(%d)\n", persona);
	if (persona != 0 && persona != 0xFFFFFFFFU)
	{
		log_debug("ERROR: persona != 0");
		/* TODO: Set errno */
		return -1;
	}
	return 0;
}

int sys_rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	log_debug("rt_sigaction(%d, %x, %x)\n", signum, act, oldact);
	/* TODO */
	return 0;
}

int sys_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	log_debug("rt_sigprocmask(%d, 0x%x, 0x%x)\n", how, set, oldset);
	/* TODO */
	return 0;
}
