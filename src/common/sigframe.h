#pragma once

#include <common/types.h>
#include <common/signal.h>
#include <common/sigcontext.h>

struct sigframe
{
	uint32_t pretcode;
	int sig;
	struct sigcontext sc;
	struct fpstate fpstate_unused;
	uint32_t extramask;
	char retcode[8];
	/* fp state follows here */
};

struct rt_sigframe
{
	uint32_t pretcode;
	int sig;
	uint32_t pinfo;
	uint32_t puc;
	struct siginfo info;
	struct ucontext uc;
	char retcode[8];
	/* fp state follows here */
};
