#include <common/auxvec.h>
#include <syscall/exec.h>
#include <syscall/fork.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/tls.h>
#include <syscall/vfs.h>
#include <log.h>
#include <heap.h>
#include <str.h>

#include <Windows.h>

#pragma comment(linker,"/entry:main")

static char *const startup = (char *)STARTUP_DATA_BASE;

void main()
{
	log_init();
	fork_init();
	/* fork_init() will directly jump to restored thread context if we are a fork child */

	mm_init();
	heap_init();
	vfs_init();
	tls_init();
	process_init(NULL);

	/* Parse command line */
	const char *cmdline = GetCommandLineA();
	int len = strlen(cmdline);
	if (len > BLOCK_SIZE) /* TODO: Test if there is sufficient space for argv[] array */
	{
		kprintf("Command line too long.\n");
		ExitProcess(1);
	}

	mm_mmap(STARTUP_DATA_BASE, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, NULL, 0);
	memcpy(startup, cmdline, len + 1);
	int argc = 0;
	const char **argv = (const char **)((uintptr_t)(startup + len + 1 + sizeof(void*) - 1) & -sizeof(void*));

	int in_quote = 0;
	const char *j = startup;
	for (char *i = startup; i <= startup + len; i++)
		if (!in_quote && (*i == ' ' || *i == '\t' || *i == '\r' || *i == '\n' || *i == 0))
		{
			*i = 0;
			if (i > j)
				argv[argc++] = j;
			j = i + 1;
		}
		else if (*i == '"')
		{
			*i = 0;
			if (in_quote)
				argv[argc++] = j;
			in_quote = !in_quote;
			j = i + 1;
		}
	argv[argc] = NULL;
	const char **envp = argv + argc + 1;
	envp[0] = NULL;

	const char *filename = NULL;
	for (int i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
		}
		else if (!filename)
			filename = argv[i];
	}
	install_syscall_handler();
	if (filename)
		do_execve(filename, argc - 1, argv + 1, 0, envp, NULL);
	kprintf("Execution failed.\n");
	ExitProcess(1);
}
