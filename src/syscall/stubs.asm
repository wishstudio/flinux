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

.model flat, C
.code

PUBLIC mm_check_read_begin, mm_check_read_end, mm_check_read_fail
mm_check_read PROC check_addr, check_size
	mov edx, check_addr
	mov ecx, check_size
	jecxz SUCC

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
	jecxz SUCC
	
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

fpu_fxsave PROC save_area
	mov eax, save_area
	fxsave [eax]
	ret
fpu_fxsave ENDP

fpu_fxrstor PROC save_area
	mov eax, save_area
	fxrstor [eax]
	ret
fpu_fxrstor ENDP

OPTION PROLOGUE: NONE
OPTION EPILOGUE: NONE
; this function will be translated by dbt before run
signal_restorer PROC
	mov eax, 119 ; sigreturn
	int 080h
signal_restorer ENDP

END
