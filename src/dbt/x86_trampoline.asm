.MODEL FLAT, C
.CODE

CONTEXT STRUCT
_Ebx	DWORD ?
_Ecx	DWORD ?
_Edx	DWORD ?
_Esi	DWORD ?
_Edi	DWORD ?
_Ebp	DWORD ?
_Esp	DWORD ?
_Eip	DWORD ?
CONTEXT ENDS

restore_fork_context PROC ctx
	mov eax, ctx
	assume eax:ptr CONTEXT
	mov ecx, [eax]._Ecx
	mov edx, [eax]._Edx
	mov ebx, [eax]._Ebx
	mov esi, [eax]._Esi
	mov edi, [eax]._Edi
	mov esp, [eax]._Esp
	mov ebp, [eax]._Ebp
	push [eax]._Eip
	assume eax:nothing
	xor eax, eax
	jmp dbt_find_indirect_internal
	retn
restore_fork_context ENDP

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

EXTERN sys_unimplemented_imp:NEAR
sys_unimplemented PROC
	push eax
	call sys_unimplemented_imp
sys_unimplemented ENDP

EXTERN sys_fork_imp: NEAR
sys_fork PROC
	; inject context pointer as the first argument
	lea eax, [esp + 4]
	mov [esp], eax
	call sys_fork_imp
	add esp, 4
	jmp syscall_done
sys_fork ENDP

EXTERN sys_vfork_imp: NEAR
sys_vfork PROC
	; inject context pointer as the first argument
	lea eax, [esp + 4]
	mov [esp], eax
	call sys_vfork_imp
	add esp, 4
	jmp syscall_done
sys_vfork ENDP

EXTERN sys_clone_imp: NEAR
sys_clone PROC
	; inject context pointer as the first argument
	lea eax, [esp + 4]
	mov [esp], eax
	call sys_clone_imp
	add esp, 4
	jmp syscall_done
sys_clone ENDP

EXTERN syscall_table: DWORD
syscall_handler PROC
	; save context
	push ecx
	push edx
	; push esp and eip context in case of fork()
	push [esp + 8]
	lea edx, [esp + 16]
	push edx
	mov edx, [esp + 8]
	; push arguments
	push ebp
	push edi
	push esi
	push edx
	push ecx
	push ebx
	; call syscall
	call [syscall_table + eax * 4]
syscall_done::
	add esp, 32
	; restore context
	pop edx
	pop ecx
	jmp dbt_find_indirect_internal
syscall_handler ENDP

; TODO: Thread safety
dbt_save_simd_state PROC
	fxsave dbt_simd_state
	ret
dbt_save_simd_state ENDP

dbt_restore_simd_state PROC
	fxrstor dbt_simd_state
	ret
dbt_restore_simd_state ENDP

.data
dbt_simd_state DB 512 DUP(?)

END
