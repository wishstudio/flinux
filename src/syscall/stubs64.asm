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

goto_entrypoint PROC stack: QWORD, entrypoint: QWORD

	mov rax, entrypoint
	mov rsp, stack
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

restore_context PROC ctx: QWORD

	mov rax, ctx
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

end
