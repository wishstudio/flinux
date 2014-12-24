.model flat, C
.code

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

END
