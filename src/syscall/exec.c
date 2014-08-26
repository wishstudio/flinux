#include <binfmt/elf.h>
#include <common/auxvec.h>
#include <common/errno.h>
#include <common/fcntl.h>
#include <fs/winfs.h>
#include <syscall/exec.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/vfs.h>
#include <log.h>
#include <heap.h>

#include <Windows.h>

struct elf_header
{
	uint32_t load_base;
	Elf32_Ehdr eh;
	char pht[];
};

__declspec(noreturn) static void goto_entrypoint(const char *stack, void *entrypoint)
{
	__asm
	{
		mov eax, entrypoint
		mov esp, stack
		push eax
		xor eax, eax
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx
		xor esi, esi
		xor edi, edi
		xor ebp, ebp
		mov gs, ax
		ret
	}
}

static void run(struct elf_header *executable, struct elf_header *interpreter, int argc, char *argv[], int env_size, char *envp[], PCONTEXT context)
{
	/* Generate initial stack */
	int aux_size = 7;
	int initial_stack_size = argc + 1 + env_size + 1 + aux_size * 2 + 1;
	char *stack_base = process_get_stack_base();
	const char **stack = (const char **)(stack_base + STACK_SIZE - initial_stack_size * sizeof(const char *) - sizeof(argc));
	int idx = 0;
	/* argc */
	stack[idx++] = argc;
	/* argv */
	for (int i = 0; i < argc; i++)
		stack[idx++] = argv[i];
	stack[idx++] = NULL;
	/* environment variables */
	for (int i = 0; i < env_size; i++)
		stack[idx++] = envp[i];
	stack[idx++] = NULL;
	/* auxiliary vector */
	stack[idx++] = (const char *)AT_PHDR;
	stack[idx++] = (const char *)executable->pht;
	stack[idx++] = (const char *)AT_PHENT;
	stack[idx++] = (const char *)executable->eh.e_phentsize;
	stack[idx++] = (const char *)AT_PHNUM;
	stack[idx++] = (const char *)executable->eh.e_phnum;
	stack[idx++] = (const char *)AT_PAGESZ;
	stack[idx++] = (const char *)PAGE_SIZE;
	stack[idx++] = (const char *)AT_BASE;
	stack[idx++] = (const char *)(interpreter? interpreter->eh.e_entry: NULL);
	stack[idx++] = (const char *)AT_FLAGS;
	stack[idx++] = (const char *)0;
	stack[idx++] = (const char *)AT_ENTRY;
	stack[idx++] = (const char *)executable->eh.e_entry;
	stack[idx++] = NULL;

	/* Call executable entrypoint */
	uint32_t entrypoint = interpreter? interpreter->load_base + interpreter->eh.e_entry: executable->load_base + executable->eh.e_entry;
	log_debug("Entrypoint: %x\n", entrypoint);
	/* If we're starting from main(), just jump to entrypoint */
	if (!context)
		goto_entrypoint(stack, entrypoint);
	/* Otherwise, we're at execve() in syscall handler context */
	/* TODO: Add a trampoline to free original stack */
	context->Eax = 0;
	context->Ecx = 0;
	context->Edx = 0;
	context->Ebx = 0;
	context->Esp = stack;
	context->Ebp = 0;
	context->Esi = 0;
	context->Edi = 0;
	context->Eip = entrypoint;
}

static int load_elf(const char *filename, struct elf_header **executable, struct elf_header **interpreter)
{
	Elf32_Ehdr eh;
	struct file *f;
	int r = vfs_open(filename, O_RDONLY, 0, &f);
	if (r < 0)
		return r;

	if (!winfs_is_winfile(f))
		return -EACCES;

	/* Load ELF header */
	f->op_vtable->pread(f, &eh, sizeof(eh), 0);
	if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN)
	{
		log_debug("Only ET_EXEC and ET_DYN executables can be loaded.\n");
		vfs_release(f);
		return -EACCES;
	}

	if (eh.e_machine != EM_386)
	{
		log_debug("Not an i386 executable.\n");
		vfs_release(f);
		return -EACCES;
	}

	/* Load program header table */
	uint32_t phsize = (uint32_t)eh.e_phentsize * (uint32_t)eh.e_phnum;
	struct elf_header *elf = kmalloc(sizeof(struct elf_header) + phsize); /* TODO: Free it at execve */
	*executable = elf;
	if (interpreter)
		*interpreter = NULL;
	elf->eh = eh;
	f->op_vtable->pread(f, elf->pht, phsize, eh.e_phoff);

	/* Find virtual address range for ET_DYN executable */
	elf->load_base = 0;
	if (eh.e_type == ET_DYN)
	{
		uint32_t low = 0xFFFFFFFF, high = 0;
		for (int i = 0; i < eh.e_phnum; i++)
		{
			Elf32_Phdr *ph = (Elf32_Phdr *)&elf->pht[eh.e_phentsize * i];
			if (ph->p_type == PT_LOAD)
			{
				low = min(low, ph->p_vaddr);
				high = max(high, ph->p_vaddr + ph->p_memsz);
			}
		}
		uint32_t free_addr = mm_find_free_pages(high - low) * PAGE_SIZE;
		if (!free_addr)
		{
			vfs_release(f);
			return -ENOMEM;
		}
		elf->load_base = free_addr - low;
		log_debug("ET_DYN load base: %x, real range [%x, %x)\n", elf->load_base, elf->load_base + low, elf->load_base + high);
	}

	/* Map executable segments */
	for (int i = 0; i < eh.e_phnum; i++)
	{
		Elf32_Phdr *ph = (Elf32_Phdr *)&elf->pht[eh.e_phentsize * i];
		if (ph->p_type == PT_LOAD)
		{
			uint32_t addr = ph->p_vaddr & 0xFFFFF000;
			uint32_t size = ph->p_memsz + (ph->p_vaddr & 0x00000FFF);
			off_t offset_pages = ph->p_offset / PAGE_SIZE;

			int prot = 0;
			if (ph->p_flags & PF_R)
				prot |= PROT_READ;
			if (ph->p_flags & PF_W)
				prot |= PROT_WRITE;
			if (ph->p_flags & PF_X)
				prot |= PROT_EXEC;
			mm_mmap(elf->load_base + addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_FIXED, NULL, 0);
			f->op_vtable->pread(f, (char *)(elf->load_base + ph->p_vaddr), ph->p_filesz, ph->p_offset);
			mm_update_brk((uint32_t)addr + size);
		}
	}

	/* Load interpreter if present */
	for (int i = 0; i < eh.e_phnum; i++)
	{
		Elf32_Phdr *ph = (Elf32_Phdr *)&elf->pht[eh.e_phentsize * i];
		if (ph->p_type == PT_INTERP)
		{
			if (interpreter == NULL)
			{
				vfs_release(f);
				return -EACCES; /* Bad interpreter */
			}
			char path[MAX_PATH];
			f->op_vtable->pread(f, path, ph->p_filesz, ph->p_offset);
			path[ph->p_filesz] = 0;
			if (load_elf(path, interpreter, NULL) < 0)
			{
				vfs_release(f);
				return -EACCES; /* Bad interpreter */
			}
		}
	}
	vfs_release(f);
	return 0;
}

int do_execve(const char *filename, int argc, char *argv[], int env_size, char *envp[], PCONTEXT context)
{
	struct elf_header *executable, *interpreter;
	int r = load_elf(filename, &executable, &interpreter);
	if (r < 0)
		return r;
	run(executable, interpreter, argc, argv, env_size, envp, context);
	return 0;
}

static char *const startup = (char *)STARTUP_DATA_BASE;

int sys_execve(const char *filename, char *argv[], char *envp[], int _4, int _5, PCONTEXT context)
{
	/* TODO: Deal with argv/envp == NULL */
	/* TODO: Don't destroy things on failure */
	log_debug("execve(%s, %x, %x)\n", filename, argv, envp);
	log_debug("Reinitializing...\n");

	/* Copy argv[] and envp[] to startup data */
	char *base = startup;
	int argc, env_size;
	for (argc = 0; argv[argc]; argc++)
	{
		base += strlen(argv[argc]) + 1;
		log_debug("argv[%d] = \"%s\"\n", argc, argv[argc]);
	}
	log_debug("argc = %d\n", argc);
	for (env_size = 0; envp[env_size]; env_size++)
	{
		base += strlen(envp[env_size]) + 1;
		log_debug("envp[%d] = \"%s\"\n", env_size, envp[env_size]);
	}
	log_debug("env_size = %d\n", env_size);

	/* TODO: Test if we have enough size to hold the startup data */
	
	char **new_argv = (char **)((uintptr_t)(base + sizeof(void*) - 1) & -sizeof(void*));
	char **new_envp = new_argv + argc + 1;

	base = startup;
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

	/* TODO: This is really ugly, we should move it into a specific UTF8->UTF16 conversion routine when we supports unicode */
	/* Normalize filename */
	char fb[1024];
	strcpy(fb, filename);
	char *f = fb;
	while (*f == ' ' || *f == '\t' || *f == '\r' || *f == '\n')
		f++;
	int len = strlen(f);
	while (f[len - 1] == ' ' || f[len - 1] == '\t' || f[len - 1] == '\r' || f[len - 1] == '\n')
		f[--len] = 0;

	vfs_reset();
	mm_reset();
	if (do_execve(f, argc, new_argv, env_size, new_envp, context) != 0)
	{
		log_debug("execve() failed.\n");
		ExitProcess(0); /* TODO: Recover */
	}
	return 0;
}
