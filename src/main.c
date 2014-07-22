#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include <Windows.h>

#include "binfmt/elf.h"
#include "syscall/mm.h"
#include "syscall/syscall.h"
#include "syscall/vfs.h"
#include "log.h"

void run_elf(const char *filename, int argc, char *argv[])
{
	HANDLE hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	/* Load ELF header */
	Elf32_Ehdr eh;
	ReadFile(hFile, &eh, sizeof(Elf32_Ehdr), NULL, NULL);
	if (eh.e_type != ET_EXEC)
	{
		printf("Not an executable!");
		goto fail;
	}

	if (eh.e_machine != EM_386)
	{
		printf("Not an i386 executable.");
		goto fail;
	}

	/* Load program header table */
	uint32_t phsize = (uint32_t)eh.e_phentsize * (uint32_t)eh.e_phnum;
	void *pht = malloc(phsize);
	SetFilePointer(hFile, eh.e_phoff, NULL, FILE_BEGIN);
	ReadFile(hFile, pht, phsize, NULL, NULL);

	for (int i = 0; i < eh.e_phnum; i++)
	{
		Elf32_Phdr *ph = (Elf32_Phdr *) ((uint8_t *) pht + (eh.e_phentsize * i));
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
			void *mem = sys_mmap((void *) addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS, -1, 0);
			mm_brk = max(mm_brk, (uint32_t)addr + size);
			SetFilePointer(hFile, ph->p_offset, NULL, FILE_BEGIN);
			ReadFile(hFile, (void *) ph->p_vaddr, ph->p_filesz, NULL, NULL);
		}
	}

	free(pht);

	install_syscall_handler();

	/* Generate initial stack */
	int env_size = 0, aux_size = 0;
	int stack_size = argc + 1 + env_size + 1 + aux_size * 2 + 1;
	const char **stack = (const char **)alloca(stack_size * sizeof(void*));
	int idx = 0;
	/* argv */
	for (int i = 0; i < argc; i++)
		stack[idx++] = argv[i];
	stack[idx++] = NULL;
	/* environment variables */
	stack[idx++] = NULL;
	/* auxiliary vector */
	stack[idx++] = NULL;

	/* Call executable entrypoint */
	uint32_t entrypoint = eh.e_entry;
	log_debug("Entrypoint: %x\n", entrypoint);
	__asm
	{
		mov esp, stack
		push argc
		push entrypoint
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

fail:
	return;
}

int main(int argc, const char **argv[])
{
	const char *filename = NULL;
	for (int i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
		}
		else if (!filename)
			filename = argv[i];
	}
	log_init();
	mm_init();
	vfs_init();
	tls_init();
	run_elf(filename, argc - 1, argv + 1);
	return 0;
}
