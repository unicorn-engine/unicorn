; Non-unwinding setjmp/longjmp for MSVC x64 (unicorn).
;
; Why do we need this?
; Short answer: Windows' setjmp/longjmp is incompatible with generated code.
; Longer answer: https://blog.lazym.io/2020/09/21/Unicorn-Devblog-setjmp-longjmp-on-Windows/.
;
; On x64 the CRT longjmp only skips the RtlUnwindEx stack unwind when the
; jmp_buf Frame field is 0, which is what the old _setjmp_wrapper (xor rdx,rdx;
; jmp _setjmp) arranged.  That is not enough any more:
;   * On Windows-on-ARM64 an x64 process loads the ARM64X vcruntime140.dll from
;     System32, whose ARM64EC longjmp always unwinds, Frame or no Frame.
;     Unwinding through TCG generated code (no unwind info) dies with
;     STATUS_BAD_FUNCTION_TABLE (0xC00000FF).
;   * It also ties us to an undocumented CRT internal.
; So, like the ARM64 build (setjmp-wrapper-win32-arm64.asm), provide a private
; pair that only saves/restores the callee-saved register state, in the
; standard x64 _JUMP_BUFFER layout (see <setjmp.h>), and never unwinds.  It is
; the same thing the CRT does on its own no-unwind path.
;
; QEMU/unicorn never has __try/__finally blocks between the sigsetjmp in
; cpu_exec and the siglongjmp in cpu_loop_exit, so skipping the unwind is safe.

; _JUMP_BUFFER field offsets (x64 <setjmp.h>)
JB_FRAME    EQU 0
JB_RBX      EQU 8
JB_RSP      EQU 16
JB_RBP      EQU 24
JB_RSI      EQU 32
JB_RDI      EQU 40
JB_R12      EQU 48
JB_R13      EQU 56
JB_R14      EQU 64
JB_R15      EQU 72
JB_RIP      EQU 80
JB_MXCSR    EQU 88
JB_FPCSR    EQU 92
JB_XMM6     EQU 96
JB_XMM7     EQU 112
JB_XMM8     EQU 128
JB_XMM9     EQU 144
JB_XMM10    EQU 160
JB_XMM11    EQU 176
JB_XMM12    EQU 192
JB_XMM13    EQU 208
JB_XMM14    EQU 224
JB_XMM15    EQU 240

PUBLIC _setjmp_wrapper
PUBLIC _longjmp_wrapper

_TEXT SEGMENT

; int _setjmp_wrapper(jmp_buf env)      ; rcx = env
_setjmp_wrapper PROC
    mov     qword ptr [rcx+JB_FRAME], 0     ; never unwind
    mov     [rcx+JB_RBX], rbx
    lea     rax, [rsp+8]                    ; caller's rsp after our return
    mov     [rcx+JB_RSP], rax
    mov     [rcx+JB_RBP], rbp
    mov     [rcx+JB_RSI], rsi
    mov     [rcx+JB_RDI], rdi
    mov     [rcx+JB_R12], r12
    mov     [rcx+JB_R13], r13
    mov     [rcx+JB_R14], r14
    mov     [rcx+JB_R15], r15
    mov     rax, [rsp]                      ; return address
    mov     [rcx+JB_RIP], rax
    stmxcsr dword ptr [rcx+JB_MXCSR]
    fnstcw  word ptr [rcx+JB_FPCSR]
    movdqu  xmmword ptr [rcx+JB_XMM6], xmm6
    movdqu  xmmword ptr [rcx+JB_XMM7], xmm7
    movdqu  xmmword ptr [rcx+JB_XMM8], xmm8
    movdqu  xmmword ptr [rcx+JB_XMM9], xmm9
    movdqu  xmmword ptr [rcx+JB_XMM10], xmm10
    movdqu  xmmword ptr [rcx+JB_XMM11], xmm11
    movdqu  xmmword ptr [rcx+JB_XMM12], xmm12
    movdqu  xmmword ptr [rcx+JB_XMM13], xmm13
    movdqu  xmmword ptr [rcx+JB_XMM14], xmm14
    movdqu  xmmword ptr [rcx+JB_XMM15], xmm15
    xor     eax, eax
    ret
_setjmp_wrapper ENDP

; void _longjmp_wrapper(jmp_buf env, int val)   ; rcx = env, edx = val
_longjmp_wrapper PROC
    mov     eax, edx
    test    eax, eax
    jnz     have_val
    mov     eax, 1                          ; setjmp must not return 0 here
have_val:
    mov     rbx, [rcx+JB_RBX]
    mov     rbp, [rcx+JB_RBP]
    mov     rsi, [rcx+JB_RSI]
    mov     rdi, [rcx+JB_RDI]
    mov     r12, [rcx+JB_R12]
    mov     r13, [rcx+JB_R13]
    mov     r14, [rcx+JB_R14]
    mov     r15, [rcx+JB_R15]
    ldmxcsr dword ptr [rcx+JB_MXCSR]
    fnclex
    fldcw   word ptr [rcx+JB_FPCSR]
    movdqu  xmm6, xmmword ptr [rcx+JB_XMM6]
    movdqu  xmm7, xmmword ptr [rcx+JB_XMM7]
    movdqu  xmm8, xmmword ptr [rcx+JB_XMM8]
    movdqu  xmm9, xmmword ptr [rcx+JB_XMM9]
    movdqu  xmm10, xmmword ptr [rcx+JB_XMM10]
    movdqu  xmm11, xmmword ptr [rcx+JB_XMM11]
    movdqu  xmm12, xmmword ptr [rcx+JB_XMM12]
    movdqu  xmm13, xmmword ptr [rcx+JB_XMM13]
    movdqu  xmm14, xmmword ptr [rcx+JB_XMM14]
    movdqu  xmm15, xmmword ptr [rcx+JB_XMM15]
    mov     rdx, [rcx+JB_RIP]
    mov     rsp, [rcx+JB_RSP]
    jmp     rdx
_longjmp_wrapper ENDP

_TEXT ENDS

END
