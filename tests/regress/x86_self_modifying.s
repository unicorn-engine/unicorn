.intel_syntax noprefix

.global _start
_start:
    mov ebp, esp
    sub ebp, 0x4000
    mov edx, ebp

    lea esi, [self_modifying]
    mov edi, ebp
    mov ecx, 0x2d
    call memcpy
    add ebp, 0x2d
    xor ebx, ebx
    call edx

    mov eax, 1
    int 0x80

memcpy:
    cmp ecx, 0
    je _end
    dec ecx
    mov al, byte ptr [esi+ecx]
    mov byte ptr [edi+ecx], al
    jmp memcpy

_end:
    ret

self_modifying:
    inc ebx
    call $+5
    pop esi
    dec byte ptr [esi+11]
    xor edx, edx
    sub esi, 6
_loop_start:
    cmp edx, 5
    jz _loop_end

    mov edi, ebp
    mov ecx, 0x2d
    lea eax, [memcpy]
    call eax
    inc edx
    add ebp, 0x2d
    mov byte ptr [ebp], 0xc3
    jmp _loop_start

_loop_end:
