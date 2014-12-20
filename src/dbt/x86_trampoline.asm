.MODEL FLAT, C
.CODE

dbt_run_internal PROC pc, stackp
	mov eax, pc
	mov esp, stackp
	push eax
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	xor esi, esi
	xor edi, edi
	xor ebp, ebp
	retn
dbt_run_internal ENDP

OPTION PROLOGUE: NONE
OPTION EPILOGUE: NONE
EXTERN dbt_find_direct:NEAR
dbt_find_direct_internal PROC ; pc, patch_addr
	; save context
	push eax
	push ecx
	push edx
	pushfd
	; copy pc and patch_addr
	mov ecx, [esp+20]
	mov edx, [esp+16]
	push ecx
	push edx
	call dbt_find_direct
	mov [esp+24], eax
	; restore context
	add esp, 8
	popfd
	pop edx
	pop ecx
	pop eax
	retn 4 ; we have one extra argument garbage at the stack
dbt_find_direct_internal ENDP

EXTERN dbt_find_next:NEAR
dbt_find_indirect_internal PROC
	; save context
	push eax
	push ecx
	push edx
	pushfd
	mov ecx, [esp+16] ; original address
	push ecx
	call dbt_find_next
	add esp, 4
	mov [esp+16], eax ; translated address
	; restore context
	popfd
	pop edx
	pop ecx
	pop eax
	ret
dbt_find_indirect_internal ENDP

END
