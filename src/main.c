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

#define ALIGN_TO(x, a) ((uintptr_t)((x) + (a) - 1) & -(a))

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
	/* TODO: This works now, but looks too ugly */
	char *envbuf = ALIGN_TO(startup + len + 1, sizeof(void*));
	envbuf[0] = 'T';
	envbuf[1] = 'E';
	envbuf[2] = 'R';
	envbuf[3] = 'M';
	envbuf[4] = '=';
	envbuf[5] = 'v';
	envbuf[6] = 't';
	envbuf[7] = '1';
	envbuf[8] = '0';
	envbuf[9] = '0';
	envbuf[10] = 0;
	int argc = 0;
	const char **argv = (const char **)(envbuf + 16);

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
	const char **envp = argv + argc + 2;
	int env_size = 1;
	envp[0] = envbuf;
	envp[1] = NULL;

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
		do_execve(filename, argc - 1, argv + 1, env_size, envp, NULL);
	kprintf("Execution failed.\n");
	ExitProcess(1);
}
