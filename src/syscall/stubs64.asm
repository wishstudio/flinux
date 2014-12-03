.code
M128A			STRUCT
_Low			QWORD	?
_High			QWORD	?
M128A			ENDS

CONTEXT			STRUCT
P1Home			QWORD	?
P2Home			QWORD	?
P3Home			QWORD	?
P4Home			QWORD	?
P5Home			QWORD	?
P6Home			QWORD	?
ContextFlags	DWORD	?
MxCsr			DWORD	?
SegCs			WORD	?
SegDs			WORD	?
SegEs			WORD	?
SegFs			WORD	?
SegGs			WORD	?
SegSs			WORD	?
EFlags			DWORD	?
_Dr0			QWORD	?
_Dr1			QWORD	?
_Dr2			QWORD	?
_Dr3			QWORD	?
_Dr6			QWORD	?
_Dr7			QWORD	?
_Rax			QWORD	?
_Rcx			QWORD	?
_Rdx			QWORD	?
_Rbx			QWORD	?
_Rsp			QWORD	?
_Rbp			QWORD	?
_Rsi			QWORD	?
_Rdi			QWORD	?
_R8				QWORD	?
_R9				QWORD	?
_R10			QWORD	?
_R11			QWORD	?
_R12			QWORD	?
_R13			QWORD	?
_R14			QWORD	?
_R15			QWORD	?
_Rip			QWORD	?
; UNION XMM_SAVE_AREA32
Header			M128A	2	DUP(<>)
Legacy			M128A	8	DUP(<>)
_Xmm0			M128A	<>
_Xmm1			M128A	<>
_Xmm2			M128A	<>
_Xmm3			M128A	<>
_Xmm4			M128A	<>
_Xmm5			M128A	<>
_Xmm6			M128A	<>
_Xmm7			M128A	<>
_Xmm8			M128A	<>
_Xmm9			M128A	<>
_Xmm10			M128A	<>
_Xmm11			M128A	<>
_Xmm12			M128A	<>
_Xmm13			M128A	<>
_Xmm14			M128A	<>
_Xmm15			M128A	<>
; END OF UNION XMM_SAVE_AREA32

VectorRegister	M128A	26	DUP(<>)
VectorControl	QWORD	?
DebugControl	QWORD	?
LastBranchToRip	QWORD	?
LastBranchFromRip	QWORD	?
LastExceptionToRip	QWORD	?
LastExceptionFromRip	QWORD	?
CONTEXT			ENDS

goto_entrypoint PROC ; stack: QWORD, entrypoint: QWORD

	mov rax, rdx ; entrypoint
	mov rsp, rcx ; stack
	push rax
	xor rax, rax
	xor rbx, rbx
	xor rcx, rcx
	xor rdx, rdx
	xor rsi, rsi
	xor rdi, rdi
	xor rbp, rbp
	xor r8, r8
	xor r9, r9
	xor r10, r10
	xor r11, r11
	xor r12, r12
	xor r13, r13
	xor r14, r14
	xor r15, r15
	ret

goto_entrypoint ENDP

restore_context PROC ; ctx: QWORD

	mov rax, rcx ; ctx
	mov rcx, [rax + CONTEXT._Rcx]
	mov rdx, [rax + CONTEXT._Rdx]
	mov rbx, [rax + CONTEXT._Rbx]
	mov rsi, [rax + CONTEXT._Rsi]
	mov rdi, [rax + CONTEXT._Rdi]
	mov rsp, [rax + CONTEXT._Rsp]
	mov rbp, [rax + CONTEXT._Rbp]
	mov r8, [rax + CONTEXT._R8]
	mov r9, [rax + CONTEXT._R9]
	mov r10, [rax + CONTEXT._R10]
	mov r11, [rax + CONTEXT._R11]
	mov r12, [rax + CONTEXT._R12]
	mov r13, [rax + CONTEXT._R13]
	mov r14, [rax + CONTEXT._R14]
	mov r15, [rax + CONTEXT._R15]
	push [rax + CONTEXT._Rip]
	mov rax, [rax + CONTEXT._Rax]
	ret

restore_context ENDP

PUBLIC mm_check_read_begin, mm_check_read_end, mm_check_read_fail
mm_check_read PROC ; check_addr: QWORD, check_size: QWORD
	xchg rcx, rdx
	; rcx = check_size
	; rdx = check_addr

mm_check_read_begin LABEL PTR
	mov al, byte ptr [rdx]
	; test first page which may be unaligned
	
	mov rax, rdx
	shr rax, 12
	; rax - start page
	lea rcx, [rdx + rcx - 1]
	shr rcx, 12
	; rcx - end page
	sub rcx, rax
	; rcx - remaining pages
	je SUCC

	and dx, 0f000h
L:
	add rdx, 01000h
	mov al, byte ptr [rdx]
	loop L
mm_check_read_end LABEL PTR

SUCC:
	xor rax, rax
	inc eax
	ret

mm_check_read_fail LABEL PTR
	xor rax, rax
	ret
mm_check_read ENDP

PUBLIC mm_check_read_string_begin, mm_check_read_string_end, mm_check_read_string_fail
mm_check_read_string PROC ; check_addr: QWORD
	mov rdx, rcx ; check_addr

mm_check_read_string_begin LABEL PTR
L:
	mov al, byte ptr [rdx]
	test al, al
	jz SUCC
	inc rdx
mm_check_read_string_end LABEL PTR

SUCC:
	xor rax, rax
	inc eax
	ret

mm_check_read_string_fail LABEL PTR
	xor rax, rax
	ret
mm_check_read_string ENDP

PUBLIC mm_check_write_begin, mm_check_write_end, mm_check_write_fail
mm_check_write PROC ; check_addr: QWORD, check_size: QWORD
	xchg rcx, rdx
	; rcx = check_size
	; rdx = check_addr
	
mm_check_write_begin LABEL PTR
	mov byte ptr [rdx], al
	; test first page which may be unaligned
	
	mov rax, rdx
	shr rax, 12
	; rax - start page
	lea rcx, [rdx + rcx - 1]
	shr rcx, 12
	; rcx - end page
	sub rcx, rax
	; rcx - remaining pages
	je SUCC

	and dx, 0f000h
L:
	add rdx, 01000h
	mov byte ptr [rdx], al
	loop L
mm_check_write_end LABEL PTR

SUCC:
	xor rax, rax
	inc eax
	ret

mm_check_write_fail LABEL PTR
	xor rax, rax
	ret
mm_check_write ENDP

END
