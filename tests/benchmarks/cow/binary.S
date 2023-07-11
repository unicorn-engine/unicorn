USE64
DEFAULT REL

SECTION .text
loop:
	xor rcx, rcx
write:
	mov [rbx+rcx*8], rsi
	inc rcx
	mov rdi, rax
	sub rdi, rcx
	jnz write
	jmp loop
