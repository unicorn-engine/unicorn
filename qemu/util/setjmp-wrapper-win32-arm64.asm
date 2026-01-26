; setjmp/longjmp wrapper for Windows ARM64 (MSVC/armasm64)
;
; This is a native assembly implementation that doesn't create a stack frame,
; avoiding the stack corruption issues that occur with a C wrapper.
;
; On ARM64 Windows, wrapping setjmp in a C function doesn't work because:
; 1. The C wrapper creates its own stack frame
; 2. setjmp saves the state inside the wrapper
; 3. After setjmp returns, the wrapper's stack frame is released
; 4. Other code runs and reuses that stack space
; 5. When longjmp is called, it tries to return to corrupted stack
;
; This assembly implementation:
; 1. Saves all callee-saved registers directly to jmp_buf
; 2. Sets Frame=0 to disable stack unwinding
; 3. Returns 0 directly without calling CRT
; 4. longjmp restores registers and returns to original caller
;
; jmp_buf layout for ARM64 Windows (per MSVC _JUMP_BUFFER):
;   Offset 0x00: Frame (set to 0 to disable unwinding)
;   Offset 0x08: Reserved
;   Offset 0x10: X19
;   Offset 0x18: X20
;   Offset 0x20: X21
;   Offset 0x28: X22
;   Offset 0x30: X23
;   Offset 0x38: X24
;   Offset 0x40: X25
;   Offset 0x48: X26
;   Offset 0x50: X27
;   Offset 0x58: X28
;   Offset 0x60: Fp (X29)
;   Offset 0x68: Lr (X30)
;   Offset 0x70: Sp
;   Offset 0x78: Fpcr (4 bytes) + Fpsr (4 bytes) = 8 bytes combined
;   Offset 0x80: D8-D15 (8 doubles = 64 bytes)
;
; Total size: 0xC0 = 192 bytes, which exactly matches jmp_buf size.

    AREA |.text|, CODE, READONLY

    EXPORT _setjmp_wrapper
    EXPORT _longjmp_wrapper

; int _setjmp_wrapper(jmp_buf env)
; x0 = pointer to jmp_buf
; Returns 0 on initial call, non-zero on longjmp return
_setjmp_wrapper PROC
    ; Set Frame and Reserved to 0 (disables stack unwinding)
    str     xzr, [x0, #0]
    str     xzr, [x0, #8]

    ; Save callee-saved general purpose registers x19-x28
    stp     x19, x20, [x0, #0x10]
    stp     x21, x22, [x0, #0x20]
    stp     x23, x24, [x0, #0x30]
    stp     x25, x26, [x0, #0x40]
    stp     x27, x28, [x0, #0x50]

    ; Save frame pointer (x29) and link register (x30)
    stp     x29, x30, [x0, #0x60]

    ; Save stack pointer
    mov     x1, sp
    str     x1, [x0, #0x70]

    ; Save FPCR and FPSR (combined into one 64-bit value)
    mrs     x1, fpcr
    mrs     x2, fpsr
    orr     x1, x1, x2, lsl #32
    str     x1, [x0, #0x78]

    ; Save callee-saved SIMD registers d8-d15 (64 bytes total at offset 0x80)
    stp     d8, d9, [x0, #0x80]
    stp     d10, d11, [x0, #0x90]
    stp     d12, d13, [x0, #0xA0]
    stp     d14, d15, [x0, #0xB0]

    ; Return 0 (initial setjmp call)
    mov     w0, #0
    ret
    ENDP

; void _longjmp_wrapper(jmp_buf env, int val)
; x0 = pointer to jmp_buf
; x1 = return value (0 is converted to 1)
; Does not return - jumps to saved context
_longjmp_wrapper PROC
    ; Ensure return value is at least 1
    cmp     w1, #0
    csinc   w2, w1, wzr, ne     ; w2 = (w1 != 0) ? w1 : 1

    ; Restore callee-saved SIMD registers d8-d15
    ldp     d8, d9, [x0, #0x80]
    ldp     d10, d11, [x0, #0x90]
    ldp     d12, d13, [x0, #0xA0]
    ldp     d14, d15, [x0, #0xB0]

    ; Restore FPCR and FPSR
    ldr     x3, [x0, #0x78]
    msr     fpcr, x3
    lsr     x3, x3, #32
    msr     fpsr, x3

    ; Restore stack pointer
    ldr     x3, [x0, #0x70]
    mov     sp, x3

    ; Restore frame pointer (x29) and link register (x30)
    ldp     x29, x30, [x0, #0x60]

    ; Restore callee-saved general purpose registers x19-x28
    ldp     x19, x20, [x0, #0x10]
    ldp     x21, x22, [x0, #0x20]
    ldp     x23, x24, [x0, #0x30]
    ldp     x25, x26, [x0, #0x40]
    ldp     x27, x28, [x0, #0x50]

    ; Return with the specified value
    mov     w0, w2
    ret
    ENDP

    END
