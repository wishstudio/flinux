#include "signal.h"

#include "errno.h"
#include "../log.h"
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
