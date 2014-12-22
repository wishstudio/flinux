.model flat, C
.code

SIZE_OF_80387_REGISTERS EQU 80
MAXIMUM_SUPPORTED_EXTENSION EQU 512

FLOATING_SAVE_AREA	STRUCT
ControlWord			DWORD		?
StatusWord			DWORD		?
TagWord				DWORD		?
ErrorOffset			DWORD		?
ErrorSelector		DWORD		?
DataOffset			DWORD		?
DataSelector		DWORD		?
RegisterArea		BYTE SIZE_OF_80387_REGISTERS DUP(?)
Spare0				DWORD		?
FLOATING_SAVE_AREA	ENDS

CONTEXT				STRUCT
ContextFlags		DWORD		?
_Dr0				DWORD		?
_Dr1				DWORD		?
_Dr2				DWORD		?
_Dr3				DWORD		?
_Dr6				DWORD		?
_Dr7				DWORD		?
FloatSave			FLOATING_SAVE_AREA	<>
SegGs				DWORD		?
SegFs				DWORD		?
SegEs				DWORD		?
SegDs				DWORD		?
_Edi				DWORD		?
_Esi				DWORD		?
_Ebx				DWORD		?
_Edx				DWORD		?
_Ecx				DWORD		?
_Eax				DWORD		?
_Ebp				DWORD		?
_Eip				DWORD		?
SegCs				DWORD		?
EFlags				DWORD		?
_Esp				DWORD		?
SegSs				DWORD		?
ExtendedRegisters	BYTE MAXIMUM_SUPPORTED_EXTENSION DUP(?)
CONTEXT				ENDS

restore_context PROC ctx

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
	mov eax, [eax]._Eax
	assume eax:nothing
	retn

restore_context ENDP

PUBLIC mm_check_read_begin, mm_check_read_end, mm_check_read_fail
mm_check_read PROC check_addr, check_size
	mov edx, check_addr
	mov ecx, check_size

mm_check_read_begin LABEL PTR
	mov al, byte ptr [edx]
	; test first page which may be unaligned
	
	mov eax, edx
	shr eax, 12
	; eax - start page
	lea ecx, [edx + ecx - 1]
	shr ecx, 12
	; ecx - end page
	sub ecx, eax
	; ecx - remaining pages
	je SUCC

	and dx, 0f000h
L:
	add edx, 01000h
	mov al, byte ptr [edx]
	loop L
mm_check_read_end LABEL PTR

SUCC:
	xor eax, eax
	inc eax
	ret

mm_check_read_fail LABEL PTR
	xor eax, eax
	ret
mm_check_read ENDP

PUBLIC mm_check_read_string_begin, mm_check_read_string_end, mm_check_read_string_fail
mm_check_read_string PROC check_addr
	mov edx, check_addr

mm_check_read_string_begin LABEL PTR
L:
	mov al, byte ptr [edx]
	test al, al
	jz SUCC
	inc edx
mm_check_read_string_end LABEL PTR

SUCC:
	xor eax, eax
	inc eax
	ret

mm_check_read_string_fail LABEL PTR
	xor eax, eax
	ret
mm_check_read_string ENDP

PUBLIC mm_check_write_begin, mm_check_write_end, mm_check_write_fail
mm_check_write PROC check_addr, check_size
	mov edx, check_addr
	mov ecx, check_size
	
mm_check_write_begin LABEL PTR
	mov al, byte ptr [edx]
	mov byte ptr [edx], al
	; test first page which may be unaligned
	
	mov eax, edx
	shr eax, 12
	; eax - start page
	lea ecx, [edx + ecx - 1]
	shr ecx, 12
	; ecx - end page
	sub ecx, eax
	; ecx - remaining pages
	je SUCC

	and dx, 0f000h
L:
	add edx, 01000h
	mov al, byte ptr [edx]
	mov byte ptr [edx], al
	loop L
mm_check_write_end LABEL PTR

SUCC:
	xor eax, eax
	inc eax
	ret

mm_check_write_fail LABEL PTR
	xor eax, eax
	ret
mm_check_write ENDP

EXTERN sys_unimplemented_show:NEAR
sys_unimplemented PROC
	push eax
	jmp sys_unimplemented_show
sys_unimplemented ENDP

OPTION PROLOGUE: NONE
OPTION EPILOGUE: NONE
EXTERN syscall_table: DWORD
syscall_handler PROC
	; save context
	push ecx
	push edx
	; push arguments
	push ebp
	push edi
	push esi
	push edx
	push ecx
	push ebx
	; call syscall
	call [syscall_table + eax * 4]
	add esp, 24
	; restore context
	pop edx
	pop ecx
	ret
syscall_handler ENDP

END
