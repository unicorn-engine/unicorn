EXTERN _setjmp: proc
PUBLIC _setjmp_wrapper

_TEXT SEGMENT

_setjmp_wrapper PROC

; Why do we need this wrapper?
; Short answer: Windows default implementation of setjmp/longjmp is incompatible with generated code.
; A longer answer: https://blog.lazym.io/2020/09/21/Unicorn-Devblog-setjmp-longjmp-on-Windows/.

xor rdx, rdx
jmp _setjmp

_setjmp_wrapper ENDP

_TEXT ENDS

END