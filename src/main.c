#include "syscall/fork.h"
#include "syscall/mm.h"
#include "syscall/process.h"
#include "syscall/syscall.h"
#include "syscall/vfs.h"
#include "log.h"
#include "heap.h"
#include <common/auxvec.h>

#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <ntdll.h>

int main(int argc, const char *argv[])
{
	log_init();
	fork_init();
	/* fork_init() will directly jump to restored thread context if we are a fork child */

	const char *filename = NULL;
	for (int i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
		}
		else if (!filename)
			filename = argv[i];
	}
	mm_init();
	heap_init();
	vfs_init();
	tls_init();
	char *env[1] = { NULL };
	do_execve(filename, argc - 1, argv + 1, env);
	printf("Execution failed.\n");
	return 0;
}
