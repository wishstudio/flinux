;
; This file is part of Foreign Linux.
;
; Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program. If not, see <http://www.gnu.org/licenses/>.
;

.MODEL FLAT, C
.CODE

EXTERN dbt_return_trampoline:NEAR
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
	lea esp, [esp+8]
	; restore context
	popfd
	pop edx
	pop ecx
	pop eax
	lea esp, [esp+8] ; we have two extra argument garbage at the stack
	jmp dword ptr [dbt_return_trampoline]
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
	lea esp, [esp+4]
	; restore context
	popfd
	pop edx
	pop ecx
	pop eax
	lea esp, [esp+4]
	jmp dword ptr [dbt_return_trampoline]
dbt_find_indirect_internal ENDP

EXTERN dbt_find_next_sieve:NEAR
dbt_sieve_fallback PROC
	; stack: address
	; stack: ecx
	push eax
	push edx
	pushfd
	mov ecx, [esp+4*4] ; original address
	push ecx
	call dbt_find_next_sieve
	lea esp, [esp+4]
	; restore context
	popfd
	pop edx
	pop eax
	pop ecx
	lea esp, [esp+4]
	jmp dword ptr [dbt_return_trampoline]
dbt_sieve_fallback ENDP

; TODO: Return through return trampoline
EXTERN dbt_cpuid:NEAR
dbt_cpuid_internal PROC
	; Allocate buffer
	lea esp, [esp-4*4]
	; Push arguments
	push esp
	push ecx
	push eax
	call dbt_cpuid
	mov eax, [esp+4*3 + 0]
	mov ebx, [esp+4*3 + 4]
	mov ecx, [esp+4*3 + 8]
	mov edx, [esp+4*3 + 12]
	lea esp, [esp+4*7]
	ret
dbt_cpuid_internal ENDP

EXTERN sys_unimplemented_imp:NEAR
sys_unimplemented PROC
	push eax
	call sys_unimplemented_imp
	lea esp, [esp+4]
	jmp syscall_done
sys_unimplemented ENDP

EXTERN sys_fork_imp: NEAR
sys_fork PROC
	; inject context pointer as the first argument
	lea eax, [esp + 4]
	mov [esp], eax
	call sys_fork_imp
	lea esp, [esp+4]
	jmp syscall_done
sys_fork ENDP

EXTERN sys_vfork_imp: NEAR
sys_vfork PROC
	; inject context pointer as the first argument
	lea eax, [esp + 4]
	mov [esp], eax
	call sys_vfork_imp
	lea esp, [esp+4]
	jmp syscall_done
sys_vfork ENDP

EXTERN sys_clone_imp: NEAR
sys_clone PROC
	; inject context pointer as the first argument
	lea eax, [esp + 4]
	mov [esp], eax
	call sys_clone_imp
	lea esp, [esp+4]
	jmp syscall_done
sys_clone ENDP

EXTERN syscall_table: DWORD
syscall_handler PROC
	; save context
	push ecx
	push edx
	; test validity
	cmp eax, 359
	jae out_of_range

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
	lea esp, [esp + 32]
	; restore context
	pop edx
	pop ecx
	jmp dbt_find_indirect_internal

out_of_range:
	call sys_unimplemented
	pop edx
	pop ecx
	jmp dbt_find_indirect_internal
syscall_handler ENDP

END
