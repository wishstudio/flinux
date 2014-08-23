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

static void run(Elf32_Ehdr *eh, void *pht, int argc, char *argv[], int env_size, char *envp[], PCONTEXT context)
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
	stack[idx++] = (const char *)pht;
	stack[idx++] = (const char *)AT_PHENT;
	stack[idx++] = (const char *)eh->e_phentsize;
	stack[idx++] = (const char *)AT_PHNUM;
	stack[idx++] = (const char *)eh->e_phnum;
	stack[idx++] = (const char *)AT_PAGESZ;
	stack[idx++] = (const char *)PAGE_SIZE;
	stack[idx++] = (const char *)AT_BASE;
	stack[idx++] = (const char *)NULL;
	stack[idx++] = (const char *)AT_FLAGS;
	stack[idx++] = (const char *)0;
	stack[idx++] = (const char *)AT_ENTRY;
	stack[idx++] = (const char *)eh->e_entry;
	stack[idx++] = NULL;

	/* Call executable entrypoint */
	uint32_t entrypoint = eh->e_entry;
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

int do_execve(const char *filename, int argc, char *argv[], int env_size, char *envp[], PCONTEXT context)
{
	struct file *f;
	int r = vfs_open(filename, O_RDONLY, 0, &f);
	if (r < 0)
		return r;

	if (!winfs_is_winfile(f))
	{
		return -EACCES;
	}

	/* Load ELF header */
	Elf32_Ehdr eh;
	f->op_vtable->pread(f, &eh, sizeof(eh), 0);
	if (eh.e_type != ET_EXEC)
	{
		log_debug("Not an executable!\n");
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
	void *pht = kmalloc(phsize); /* TODO: Free it at execve */
	f->op_vtable->pread(f, pht, phsize, eh.e_phoff);

	for (int i = 0; i < eh.e_phnum; i++)
	{
		Elf32_Phdr *ph = (Elf32_Phdr *)((uint8_t *)pht + (eh.e_phentsize * i));
		if (ph->p_type == PT_LOAD)
		{
			uint32_t addr = ph->p_vaddr;
			uint32_t size = ph->p_memsz + (addr & 0x00000FFF);
			addr &= 0xFFFFF000;

			int prot = 0;
			if (ph->p_flags & PF_R)
				prot |= PROT_READ;
			if (ph->p_flags & PF_W)
				prot |= PROT_WRITE;
			if (ph->p_flags & PF_X)
				prot |= PROT_EXEC;
			void *mem = sys_mmap((void *)addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS, -1, 0);
			mm_update_brk((uint32_t)addr + size);
			f->op_vtable->pread(f, (char *)ph->p_vaddr, ph->p_filesz, ph->p_offset);
		}
	}
	vfs_release(f);
	run(&eh, pht, argc, argv, env_size, envp, context);
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
