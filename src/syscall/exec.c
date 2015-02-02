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

#include <binfmt/elf.h>
#include <common/auxvec.h>
#include <common/errno.h>
#include <common/fcntl.h>
#include <dbt/x86.h>
#include <fs/winfs.h>
#include <syscall/exec.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/syscall.h>
#include <syscall/tls.h>
#include <syscall/vfs.h>
#include <log.h>
#include <heap.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#ifdef _WIN64
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#endif

struct elf_header
{
	size_t load_base, low, high;
	Elf_Ehdr eh;
	char pht[];
};

struct binfmt
{
	char *buffer_base;
	const char *argv0, *argv1;
	BOOL replace_argv0;
	struct elf_header *executable, *interpreter;
};

__declspec(noreturn) void goto_entrypoint(const char *stack, void *entrypoint);

/* Macros for easier initial stack mangling */
#define PTR(ptr) *(void**)(stack -= sizeof(void*)) = (void*)(ptr)
#define AUX_VEC(id, value) PTR(value); PTR(id)
#define ALLOC(size) (stack -= (size))

static void run(struct binfmt *binary, int argc, char *argv[], int env_size, char *envp[])
{
	/* Generate initial stack */
	char *stack_base = process_get_stack_base();
	char *stack = stack_base + STACK_SIZE;
	/* 16 random bytes for AT_RANDOM */
	/* TODO: Fill in real content */
	char *random_bytes = ALLOC(16);

	struct elf_header *executable = binary->executable;
	struct elf_header *interpreter = binary->interpreter;

	/* auxiliary vector */
	PTR(NULL);
	AUX_VEC(AT_FLAGS, 0);
	AUX_VEC(AT_SECURE, 0);
	AUX_VEC(AT_RANDOM, random_bytes);
	AUX_VEC(AT_PAGESZ, PAGE_SIZE);
	AUX_VEC(AT_PHDR, executable->pht);
	AUX_VEC(AT_PHENT, executable->eh.e_phentsize);
	AUX_VEC(AT_PHNUM, executable->eh.e_phnum);
	AUX_VEC(AT_ENTRY, executable->load_base + executable->eh.e_entry);
	AUX_VEC(AT_BASE, (interpreter ? interpreter->load_base - interpreter->low : NULL));

	/* environment variables */
	PTR(NULL);
	for (int i = env_size - 1; i >= 0; i--)
		PTR(envp[i]);

	/* argv */
	PTR(NULL);
	for (int i = argc - 1; i >= 0; i--)
		PTR(argv[i]);
	/* Insert additional arguments from special binfmt */
	if (binary->argv1)
	{
		PTR(binary->argv1);
		argc++;
	}
	if (binary->argv0)
	{
		PTR(binary->argv0);
		argc++;
	}

	/* argc */
	PTR(argc);

	/* Call executable entrypoint */
	size_t entrypoint = interpreter? interpreter->load_base + interpreter->eh.e_entry: executable->load_base + executable->eh.e_entry;
	log_info("Entrypoint: %p\n", entrypoint);

	/* TODO: The current way isn't bullet-proof
	 * Basically our 'kernel' routines uses the application's stack
	 * When doing an execve we are overwritting the upper part of the stack while relying on the bottom part!!!
	 * To get proper behaviour, we first have to save and restore esp on kernel/app switches, which is left to be done
	 */
	dbt_run(entrypoint, stack);
}

static int load_elf(struct file *f, struct binfmt *binary)
{
	Elf_Ehdr eh;

	/* Load ELF header */
	f->op_vtable->pread(f, &eh, sizeof(eh), 0);
	if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN)
	{
		log_error("Only ET_EXEC and ET_DYN executables can be loaded.\n");
		return -EACCES;
	}

#ifdef _WIN64
	if (eh.e_machine != EM_X86_64)
	{
		log_error("Not an x86_64 executable.\n");
#else
	if (eh.e_machine != EM_386)
	{
		log_error("Not an i386 executable.\n");
#endif
		return -EACCES;
	}

	/* Load program header table */
	size_t phsize = (size_t)eh.e_phentsize * (size_t)eh.e_phnum;
	struct elf_header *elf = kmalloc(sizeof(struct elf_header) + phsize); /* TODO: Free it at execve */
	if (binary->executable)
		binary->interpreter = elf;
	else
		binary->executable = elf;
	elf->eh = eh;
	f->op_vtable->pread(f, elf->pht, phsize, eh.e_phoff); /* TODO */

	/* Find virtual address range */
	elf->low = 0xFFFFFFFF;
	elf->high = 0;
	for (int i = 0; i < eh.e_phnum; i++)
	{
		Elf_Phdr *ph = (Elf_Phdr *)&elf->pht[eh.e_phentsize * i];
		if (ph->p_type == PT_LOAD)
		{
			elf->low = min(elf->low, ph->p_vaddr);
			elf->high = max(elf->high, ph->p_vaddr + ph->p_memsz);
			log_info("PT_LOAD: vaddr %p, size %p\n", ph->p_vaddr, ph->p_memsz);
		}
		else if (ph->p_type == PT_DYNAMIC)
			log_info("PT_DYNAMIC: vaddr %p, size %p\n", ph->p_vaddr, ph->p_memsz);
		else if (ph->p_type == PT_PHDR) /* Patch phdr pointer in PT_PHDR, glibc uses it to determine load offset */
			ph->p_vaddr = elf->pht;
	}

	/* Find virtual address range for ET_DYN executable */
	elf->load_base = 0;
	if (eh.e_type == ET_DYN)
	{
		size_t free_addr = mm_find_free_pages(elf->high - elf->low) * PAGE_SIZE;
		if (!free_addr)
			return -ENOMEM;
		elf->load_base = free_addr - elf->low;
		log_info("ET_DYN load offset: %p, real range [%p, %p)\n", elf->load_base, elf->load_base + elf->low, elf->load_base + elf->high);
	}

#ifdef _WIN64
	/* Unmap the pre-reserved executable region (see fork_init() for details) */
	size_t region_start = 0x400000;
	VirtualFree(region_start, 0, MEM_RELEASE); /* This will silently fail if it's not the intended case */
#endif

	/* Map executable segments */
	/* TODO: Directly use mmap() */
	for (int i = 0; i < eh.e_phnum; i++)
	{
		Elf_Phdr *ph = (Elf_Phdr *)&elf->pht[eh.e_phentsize * i];
		if (ph->p_type == PT_LOAD)
		{
			size_t addr = ph->p_vaddr & 0xFFFFF000;
			size_t size = ph->p_memsz + (ph->p_vaddr & 0x00000FFF);
			off_t offset_pages = ph->p_offset / PAGE_SIZE;

			int prot = 0;
			if (ph->p_flags & PF_R)
				prot |= PROT_READ;
			if (ph->p_flags & PF_W)
				prot |= PROT_WRITE;
			if (ph->p_flags & PF_X)
				prot |= PROT_EXEC;
			mm_mmap(elf->load_base + addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, NULL, 0);
			void *vaddr = (char *)(elf->load_base + ph->p_vaddr);
			mm_check_write(vaddr, ph->p_filesz); /* TODO */
			f->op_vtable->pread(f, vaddr, ph->p_filesz, ph->p_offset);
			if (!binary->interpreter) /* This is not an interpreter */
				mm_update_brk(elf->load_base + addr + size);
		}
	}

	/* Load interpreter if present */
	for (int i = 0; i < eh.e_phnum; i++)
	{
		Elf_Phdr *ph = (Elf_Phdr *)&elf->pht[eh.e_phentsize * i];
		if (ph->p_type == PT_INTERP)
		{
			if (binary->interpreter) /* This is already an interpreter */
				return -EACCES; /* Bad interpreter */
			char path[MAX_PATH];
			f->op_vtable->pread(f, path, ph->p_filesz, ph->p_offset); /* TODO */
			path[ph->p_filesz] = 0;

			struct file *fi;
			int r = vfs_openat(AT_FDCWD, path, O_RDONLY, 0, &fi);
			if (r < 0)
				return r;
			if (!winfs_is_winfile(fi))
			{
				vfs_release(fi);
				return -EACCES;
			}

			r = load_elf(fi, binary);
			vfs_release(fi);
			if (r < 0)
				return -EACCES; /* Bad interpreter */
		}
	}
	return 0;
}

#define MAX_SHEBANG_LINE	256
static int load_script(struct file *f, struct binfmt *binary)
{
	/* Parse the shebang line */
	int size = f->op_vtable->pread(f, binary->buffer_base, MAX_SHEBANG_LINE, 0);
	char *p = binary->buffer_base, *end = p + size;
	/* Skip shebang */
	p += 2;
	/* Skip spaces */
	while (p < end && *p == ' ')
		p++;
	if (p == end)
		return -EACCES;
	const char *executable = p;
	binary->argv0 = p;
	while (p < end && *p != ' ' && *p != '\n')
		p++;
	if (p == end)
		return -EACCES;
	if (*p == '\n')
		*p = 0; /* It has no argument */
	else
	{
		*p++ = 0;
		while (p < end && *p == ' ')
			p++;
		if (p == end)
			return -EACCES;
		if (*p != '\n')
		{
			/* It has an argument */
			binary->argv1 = p;
			while (p < end && *p != '\n')
				p++;
			if (p == end)
				return -EACCES;
			*p = 0;
		}
	}
	binary->replace_argv0 = TRUE;

	struct file *fe;
	int r = vfs_openat(AT_FDCWD, executable, O_RDONLY, 0, &fe);
	if (r < 0)
		return r;
	if (!winfs_is_winfile(fe))
	{
		vfs_release(fe);
		return -EACCES;
	}
	/* TODO: Recursive interpreters */
	return load_elf(fe, binary);
}

int do_execve(const char *filename, int argc, char *argv[], int env_size, char *envp[], char *buffer_base)
{
	buffer_base = (char*)((uintptr_t)(buffer_base + sizeof(void*) - 1) & -sizeof(void*));

	/* Detect file type */
	int r;
	char magic[4];
	struct file *f;
	r = vfs_openat(AT_FDCWD, filename, O_RDONLY, 0, &f);
	if (r < 0)
		return r;
	if (!winfs_is_winfile(f))
	{
		vfs_release(f);
		return -EACCES;
	}
	r = f->op_vtable->pread(f, magic, 4, 0);
	if (r < 4)
		return -EACCES;

	struct binfmt binary;
	binary.argv0 = NULL;
	binary.argv1 = NULL;
	binary.replace_argv0 = FALSE;
	binary.buffer_base = buffer_base;
	binary.executable = NULL;
	binary.interpreter = NULL;

	/* Load file */
	if (magic[0] == ELFMAG0 && magic[1] == ELFMAG1 && magic[2] == ELFMAG2 && magic[3] == ELFMAG3)
		r = load_elf(f, &binary);
	else if (magic[0] == '#' && magic[1] == '!')
		r = load_script(f, &binary);
	else
	{
		log_error("Unknown binary magic: %c%c%c%c", magic[0], magic[1], magic[2], magic[3]);
		return -EACCES;
	}
	vfs_release(f);
	if (r < 0)
		return r;

	/* Execute file */
	if (binary.replace_argv0)
		argv[0] = filename;
	run(&binary, argc, argv, env_size, envp);
	return 0;
}

static char *const startup = (char *)STARTUP_DATA_BASE;

DEFINE_SYSCALL(execve, const char *, filename, char **, argv, char **, envp)
{
	/* TODO: Deal with argv/envp == NULL */
	/* TODO: Don't destroy things on failure */
	log_info("execve(%s, %p, %p)\n", filename, argv, envp);
	log_info("Reinitializing...\n");

	/* Copy argv[] and envp[] to startup data */
	char *current_startup_base;
	if (*(uintptr_t*)startup)
	{
		*(uintptr_t*)startup = 0;
		*(uintptr_t*)(startup + (BLOCK_SIZE / 2)) = 1;
		current_startup_base = startup + (BLOCK_SIZE / 2) + sizeof(uintptr_t);
	}
	else
	{
		*(uintptr_t*)(startup + (BLOCK_SIZE / 2)) = 0;
		*(uintptr_t*)startup = 1;
		current_startup_base = startup + sizeof(uintptr_t);
	}

	/* Save filename in startup data area */
	int flen = strlen(filename);
	memcpy(current_startup_base, filename, flen + 1);
	filename = current_startup_base;
	current_startup_base += flen + 1;

	char *base = current_startup_base;
	int argc, env_size;
	for (argc = 0; argv[argc]; argc++)
	{
		base += strlen(argv[argc]) + 1;
		log_info("argv[%d] = \"%s\"\n", argc, argv[argc]);
	}
	log_info("argc = %d\n", argc);
	for (env_size = 0; envp[env_size]; env_size++)
	{
		base += strlen(envp[env_size]) + 1;
		log_info("envp[%d] = \"%s\"\n", env_size, envp[env_size]);
	}
	log_info("env_size = %d\n", env_size);

	/* TODO: Test if we have enough size to hold the startup data */
	
	char **new_argv = (char **)((uintptr_t)(base + sizeof(void*) - 1) & -sizeof(void*));
	char **new_envp = new_argv + argc + 1;

	base = current_startup_base;
	for (int i = 0; i < argc; i++)
	{
		new_argv[i] = base;
		int len = strlen(argv[i]);
		memcpy(base, argv[i], len + 1);
		base += len + 1;
	}
	new_argv[argc] = NULL;
	for (int i = 0; i < env_size; i++)
	{
		new_envp[i] = base;
		int len = strlen(envp[i]);
		memcpy(base, envp[i], len + 1);
		base += len + 1;
	}
	new_envp[env_size] = NULL;

	base = (char *)(new_envp + env_size + 1);

	vfs_reset();
	mm_reset();
	tls_reset();
	dbt_reset();
	if (do_execve(filename, argc, new_argv, env_size, new_envp, base) != 0)
	{
		log_warning("execve() failed.\n");
		ExitProcess(0); /* TODO: Recover */
	}
	return 0;
}
