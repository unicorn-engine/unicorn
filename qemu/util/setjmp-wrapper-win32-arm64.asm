; ARM64 (armasm64) replacement for setjmp/longjmp, the counterpart of
; setjmp-wrapper-win32.asm (x64).
;
; Why do we need this?
; Short answer: Windows default implementation of setjmp/longjmp is incompatible with generated code.
; A longer answer: https://blog.lazym.io/2020/09/21/Unicorn-Devblog-setjmp-longjmp-on-Windows/.
;
; On x64 it is enough to call _setjmp with a NULL frame pointer: longjmp then
; skips the stack unwinding. On ARM64 that trick does not work. The CRT's
; longjmp always performs an RtlUnwindEx based unwind (a NULL frame turns it
; into an "exit unwind" through every frame on the stack). The frames that
; belong to TCG generated code have no unwind information, so the unwinder
; walks off into garbage and the process dies with an access violation.
; QEMU upstream hit the same problem and documents it in os-win32.h:
; "On windows-arm64, setjmp is available in only one variant, and longjmp
;  always does stack unwinding. This crash with generated code."
;
; So, like QEMU with mingw-w64 (__mingw_setjmp/__mingw_longjmp), we provide a
; private pair of routines that just save and restore the callee-saved state
; and never unwind. The buffer passed in is a regular MSVC jmp_buf (_JBLEN = 24
; 64-bit words); the layout below matches _JUMP_BUFFER from <setjmp.h>:
;
;   off  0  Frame      (kept at 0, we never unwind)
;   off  8  Reserved
;   off 16  X19..X28   (10 x 8 bytes)
;   off 96  Fp (x29)
;   off 104 Lr (x30)
;   off 112 Sp
;   off 120 Fpcr (32 bit)
;   off 124 Fpsr (32 bit)
;   off 128 D8..D15    (8 x 8 bytes)
;
; Only ever pair _setjmp_wrapper with _longjmp_wrapper, never with the CRT's
; longjmp (see sigsetjmp/siglongjmp in qemu/include/sysemu/os-win32.h).

        AREA    |.text|, CODE, READONLY, ALIGN=2

        EXPORT  _setjmp_wrapper
        EXPORT  _longjmp_wrapper

; int _setjmp_wrapper(jmp_buf env)
; Returns 0 on the direct call, the longjmp value on the second return.
_setjmp_wrapper PROC
        stp     xzr, xzr, [x0, #0]          ; Frame = 0, Reserved = 0
        stp     x19, x20, [x0, #16]
        stp     x21, x22, [x0, #32]
        stp     x23, x24, [x0, #48]
        stp     x25, x26, [x0, #64]
        stp     x27, x28, [x0, #80]
        stp     x29, x30, [x0, #96]
        mov     x1, sp
        str     x1, [x0, #112]
        mrs     x1, FPCR
        mrs     x2, FPSR
        str     w1, [x0, #120]
        str     w2, [x0, #124]
        stp     d8, d9, [x0, #128]
        stp     d10, d11, [x0, #144]
        stp     d12, d13, [x0, #160]
        stp     d14, d15, [x0, #176]
        mov     w0, wzr
        ret
        ENDP

; void _longjmp_wrapper(jmp_buf env, int val)   -- does not return
; Restores the state saved by _setjmp_wrapper and resumes right after it,
; making that call return val (or 1 if val is 0), exactly like longjmp but
; without any stack unwinding.
_longjmp_wrapper PROC
        ldp     x19, x20, [x0, #16]
        ldp     x21, x22, [x0, #32]
        ldp     x23, x24, [x0, #48]
        ldp     x25, x26, [x0, #64]
        ldp     x27, x28, [x0, #80]
        ldp     x29, x30, [x0, #96]
        ldr     x2, [x0, #112]
        mov     sp, x2
        ldr     w2, [x0, #120]
        msr     FPCR, x2
        ldr     w2, [x0, #124]
        msr     FPSR, x2
        ldp     d8, d9, [x0, #128]
        ldp     d10, d11, [x0, #144]
        ldp     d12, d13, [x0, #160]
        ldp     d14, d15, [x0, #176]
        cmp     w1, #0
        cinc    w0, w1, eq                  ; w0 = (val == 0) ? 1 : val
        ret
        ENDP

        END
