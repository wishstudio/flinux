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

goto_entrypoint PROC stack, entrypoint

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
	retn

goto_entrypoint ENDP

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

end
