; setjmp/longjmp for Windows ARM64 (MSVC armasm64)
;
; Based on musl libc aarch64 setjmp/longjmp implementation.
; https://git.musl-libc.org/cgit/musl/tree/src/setjmp/aarch64/setjmp.s
; https://git.musl-libc.org/cgit/musl/tree/src/setjmp/aarch64/longjmp.s
;
; Custom implementations are needed because the CRT longjmp calls
; RtlUnwind for stack unwinding, which crashes when JIT-generated code
; frames (with no SEH unwind metadata) are on the stack.
; See setjmp-wrapper-win32-arm64.md for details.
;
; jmp_buf layout (AAPCS64 callee-saved registers):
;   Offset 0x00: X19, X20
;   Offset 0x10: X21, X22
;   Offset 0x20: X23, X24
;   Offset 0x30: X25, X26
;   Offset 0x40: X27, X28
;   Offset 0x50: X29 (FP), X30 (LR)
;   Offset 0x68: SP
;   Offset 0x70: D8, D9
;   Offset 0x80: D10, D11
;   Offset 0x90: D12, D13
;   Offset 0xA0: D14, D15

    AREA |.text|, CODE, READONLY

    EXPORT _setjmp_wrapper
    EXPORT _longjmp_wrapper

; int _setjmp_wrapper(jmp_buf env)
; x0 = pointer to jmp_buf
; Returns 0 on initial call, non-zero on longjmp return
_setjmp_wrapper PROC
    stp     x19, x20, [x0, #0x00]
    stp     x21, x22, [x0, #0x10]
    stp     x23, x24, [x0, #0x20]
    stp     x25, x26, [x0, #0x30]
    stp     x27, x28, [x0, #0x40]
    stp     x29, x30, [x0, #0x50]
    mov     x2, sp
    str     x2, [x0, #0x68]
    stp     d8, d9, [x0, #0x70]
    stp     d10, d11, [x0, #0x80]
    stp     d12, d13, [x0, #0x90]
    stp     d14, d15, [x0, #0xA0]
    mov     w0, #0
    ret
    ENDP

; void _longjmp_wrapper(jmp_buf env, int val)
; x0 = pointer to jmp_buf
; x1 = return value (0 is converted to 1)
; Does not return - jumps to saved context
_longjmp_wrapper PROC
    ldp     x19, x20, [x0, #0x00]
    ldp     x21, x22, [x0, #0x10]
    ldp     x23, x24, [x0, #0x20]
    ldp     x25, x26, [x0, #0x30]
    ldp     x27, x28, [x0, #0x40]
    ldp     x29, x30, [x0, #0x50]
    ldr     x2, [x0, #0x68]
    mov     sp, x2
    ldp     d8, d9, [x0, #0x70]
    ldp     d10, d11, [x0, #0x80]
    ldp     d12, d13, [x0, #0x90]
    ldp     d14, d15, [x0, #0xA0]
    cmp     w1, #0
    csinc   w0, w1, wzr, ne
    br      x30
    ENDP

    END
