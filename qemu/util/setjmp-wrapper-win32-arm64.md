# Why setjmp/longjmp wrappers are needed on Windows ARM64

## Background

Unicorn's QEMU TCG uses `setjmp`/`longjmp` to exit from JIT-generated code back
to the CPU execution loop (e.g. on HLT, exceptions, or memory faults). On
Windows ARM64, both the CRT `setjmp` and `longjmp` are unsuitable for this
because they interact with Windows Structured Exception Handling (SEH) stack
unwinding, which cannot traverse JIT-generated code frames that lack unwind
metadata.

## Why `_setjmp_wrapper` is needed

The CRT `_setjmp` on ARM64 saves frame information into `jmp_buf` that
`longjmp` later uses to drive `RtlUnwind`. The wrapper uses a simple
musl-libc-style layout that only saves callee-saved registers (x19-x28, x29,
x30, sp, d8-d15) without any SEH frame data.

Without it: **linker error** — `os-win32.h` declares
`extern int _setjmp_wrapper(jmp_buf)` and the `setjmp` macro expands to it, so
all three callsites (`cpu-exec.c`, `translate-all.c`, `translate.c`) reference
this symbol.

## Why `_longjmp_wrapper` is needed

Even with a correct `jmp_buf` (Frame=0), the CRT `longjmp` still calls
`__longjmp_internal` → `RtlUnwind` → `RtlUnwindEx`, which attempts to walk the
stack. When JIT-generated code is on the stack (no SEH unwind info), this fails
with exception `0xC00000FF`.

The wrapper bypasses the CRT entirely — it restores callee-saved registers
directly from the `jmp_buf` with `ldp`/`ldr` instructions and `ret`s to the
saved return address.

Without it: **runtime crash** — confirmed via debugger:

```
ntdll!RtlRaiseStatus          (exception 0xC00000FF)
ntdll!RtlUnwindEx              ← stack unwinding fails here
ntdll!RtlUnwind
VCRUNTIME140!__longjmp_internal
VCRUNTIME140!longjmp
unicorn!cpu_loop_exit_x86_64
unicorn!helper_hlt_x86_64
0x000001b480000184             ← JIT code (no unwind info)
```

46 of 54 x86 tests crash with exit code `0xC00000FF`.

## Why x64 doesn't need a longjmp wrapper

On x64, `_setjmp` accepts a second parameter (frame pointer). Passing `NULL`
disables stack unwinding in `longjmp`. ARM64's CRT has no equivalent mechanism,
so both wrappers are required.
