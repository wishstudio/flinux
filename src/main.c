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

#include <common/auxvec.h>
#include <common/errno.h>
#include <syscall/exec.h>
#include <syscall/fork.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/sig.h>
#include <syscall/tls.h>
#include <syscall/vfs.h>
#include <flags.h>
#include <log.h>
#include <heap.h>
#include <shared.h>
#include <str.h>
#include <version.h>
#include <win7compat.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#pragma comment(linker,"/entry:main")
#pragma comment(lib,"delayimp")
 /* VS 2015 does not pull this in when manually specifying entrypoint, don't know why. */
#ifdef _DEBUG
#pragma comment(lib,"libucrtd")
#else
#pragma comment(lib,"libucrt")
#endif

static void print_usage()
{
	kprintf("Usage: flinux [options] <executable>\n");
	kprintf("Use with --help option to print a list of all available options.\n");
}

static void print_version()
{
	kprintf("Foreign LINUX " GIT_VERSION "\n");
	kprintf("\n");
	kprintf("This program is distributed in the hope that it will be useful,\n");
	kprintf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	kprintf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n");
	kprintf("GNU General Public License for more details.\n");
}

static void print_help()
{
	kprintf("Foreign LINUX: Run Linux userspace application.\n");
	kprintf("\n");
	kprintf("Usage: flinux [options] <executable> [arguments]\n");
	kprintf("Use the current directory as the root directory.\n");
	kprintf("<executable> is the executable path relative to the root directory.\n");
	kprintf("\n");
	kprintf("Main options:\n");
	kprintf("  --session-id <id> Set session id. flinux instances with different session IDs\n");
	kprintf("                    are completely isolated. <id> can be any alphanumeric string\n");
	kprintf("                    not longer than 7 characters. The ID \"default\" is used by\n");
	kprintf("                    default.\n");
	kprintf("\n");
	kprintf("Misc options:\n");
	kprintf("  --help, -h        Print this help message.\n");
	kprintf("  --usage           Print basic usage.\n");
	kprintf("  --version, -v     Print version.\n");
	kprintf("\n");
	kprintf("Debug options:\n");
	kprintf("  --dbt-trace       Trace dbt basic block generation.\n");
	kprintf("  --dbt-trace-all   Full trace of dbt execution. (massive performance drop)\n");
}

/*
 * Startup data is divided into two parts
 * The actual used part is flipped upon execve()
 * This is to prevent data corruption when the arguments of execve() used pointers at data inside the startup area
 * The first uintptr_t data itme in each side is set to 1 when the part is currently in use
 */
char *startup;

static void init_subsystems()
{
	shared_init();
	heap_init();
	signal_init();
	process_init();
	tls_init();
	vfs_init();
	dbt_init();
}

#define ENV(x) \
	do { \
		memcpy(envbuf, x, sizeof(x)); \
		envbuf += sizeof(x); \
	} while (0)

void main()
{
	win7compat_init();
	log_init();
	fork_init();
	/* fork_init() will directly jump to restored thread context if we are a fork child */

	mm_init();
	flags_init();

	/* Parse command line */
	const char *cmdline = GetCommandLineA();
	int len = strlen(cmdline);
	if (len > BLOCK_SIZE) /* TODO: Test if there is sufficient space for argv[] array */
	{
		init_subsystems();
		kprintf("Command line too long.\n");
		process_exit(1, 0);
	}

	startup = mm_mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS,
		INTERNAL_MAP_TOPDOWN | INTERNAL_MAP_NORESET | INTERNAL_MAP_VIRTUALALLOC, NULL, 0);
	*(uintptr_t*) startup = 1;
	char *current_startup_base = startup + sizeof(uintptr_t);
	memcpy(current_startup_base, cmdline, len + 1);
	char *envbuf = (char *)ALIGN_TO(current_startup_base + len + 1, sizeof(void*));
	char *env0 = envbuf;
	ENV("TERM=xterm");
	char *env1 = envbuf;
	ENV("HOME=/root");
	char *env2 = envbuf;
	ENV("DISPLAY=127.0.0.1:0");
	char *env3 = envbuf;
	ENV("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin:/sbin");
	int argc = 0;
	char **argv = (char **)ALIGN_TO(envbuf, sizeof(void*));

	/* Parse command line */
	int in_quote = 0;
	char *j = current_startup_base;
	for (char *i = current_startup_base; i <= current_startup_base + len; i++)
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
	char **envp = argv + argc + 1;
	int env_size = 4;
	envp[0] = env0;
	envp[1] = env1;
	envp[2] = env2;
	envp[3] = env3;
	envp[4] = NULL;
	char *buffer_base = (char*)(envp + env_size + 1);

	const char *filename = NULL;
	int arg_start;
	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "--session-id"))
		{
			if (++i < argc)
			{
				int len = strlen(argv[i]);
				if (len >= MAX_SESSION_ID_LEN)
				{
					init_subsystems();
					kprintf("--session-id: Session ID too long.\n");
					process_exit(1, 0);
				}
				for (int j = 0; j < len; j++)
				{
					char ch = argv[i][j];
					if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
						ch == '_' || ch == '-'))
					{
						init_subsystems();
						kprintf("--session-id: Invalid characters.\n");
						process_exit(1, 0);
					}
				}
				strcpy(cmdline_flags->global_session_id, argv[i]);
			}
			else
			{
				init_subsystems();
				kprintf("--session-id: No ID given.\n");
				process_exit(1, 0);
			}
		}
		else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h"))
		{
			init_subsystems();
			print_help();
			process_exit(1, 0);
		}
		else if (!strcmp(argv[i], "--usage"))
		{
			init_subsystems();
			print_usage();
			process_exit(1, 0);
		}
		else if (!strcmp(argv[i], "--version") || !strcmp(argv[i], "-v"))
		{
			init_subsystems();
			print_version();
			process_exit(1, 0);
		}
		else if (!strcmp(argv[i], "--dbt-trace"))
			cmdline_flags->dbt_trace = true;
		else if (!strcmp(argv[i], "--dbt-trace-all"))
		{
			cmdline_flags->dbt_trace = true;
			cmdline_flags->dbt_trace_all = true;
		}
		else if (argv[i][0] == '-')
		{
			init_subsystems();
			kprintf("Unrecognized option: %s\n", argv[i]);
			process_exit(1, 0);
		}
		else if (!filename)
		{
			filename = argv[i];
			arg_start = i;
			break;
		}
	}

	init_subsystems();
	if (filename)
	{
		install_syscall_handler();
		int r = do_execve(filename, argc - arg_start, argv + arg_start, env_size, envp, buffer_base, NULL);
		if (r == -L_ENOENT)
		{
			kprintf("Executable not found.");
			process_exit(1, 0);
		}
	}
	print_usage();
	process_exit(1, 0);
}
