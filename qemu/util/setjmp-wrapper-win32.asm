EXTERN _setjmp: proc
PUBLIC _setjmp_wrapper

_TEXT SEGMENT

_setjmp_wrapper PROC

; Why do we need this wrapper?
; Short answer: Windows default implementation of setjmp/longjmp is incompatible with generated code.
; A longer answer: https://blog.lazym.io/2020/09/21/Unicorn-Devblog-setjmp-longjmp-on-Windows/.

; From qemu os-win32 comments:
; > On w64, setjmp is implemented by _setjmp which needs a second parameter.
; > If this parameter is NULL, longjump does no stack unwinding.
; > That is what we need for QEMU. Passing the value of register rsp (default)
; > lets longjmp try a stack unwinding which will crash with generated code.
; It's true indeed, but MSVC doesn't has a setjmp signature which receives two arguements.
; Therefore, we add a wrapper to keep the second argument zero.
xor rdx, rdx
jmp _setjmp

_setjmp_wrapper ENDP

_TEXT ENDS

END