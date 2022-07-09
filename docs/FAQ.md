## Why is my execution so slow?

Typically, it’s due to

- Instrumenting every instruction executed.
- Instrumenting every memory access.

Optimize your program with less instrumentation, e.g. by using `UC_HOOK_BLOCK` instead of `UC_HOOK_CODE`

## Why do I get a wrong PC after emulation stops?

PC is only guaranteed to be correct if you install `UC_HOOK_CODE`. This is due to the fact that updating PC is a big performance overhead during emulation.

## I get an “Unhandled CPU Exception”, why?

Unicorn is a pure CPU emulator and usually it’s due to no handler registered for instructions like `syscall` and `SVC`. If you expect system emulation, you probably would like [qiling framework](https://github.com/qilingframework/qiling).

## I would like to instrument a specific instruction but get a `UC_ERR_HOOK`, why?

Currently, only a small subset of the instructions can be instrumented.

On x86, all available instructions are: `in` `out` `syscall` `sysenter` `cpuid`.

## Emulating some instructions gives an error, what should I do?

1. Some instructions are not enabled by default on some architectures. For example, you have to setup CSR on RISC-V or VFP on ARM before emulating floating-point instructions. Refer to the corresponding manual to check if you leave out possible switches in special registers.
2. If you are on ARM, please check whether you are emulating a THUMB instruction. If so, please use `UC_MODE_THUMB` and make sure the starting address is odd. 
3. If either is not the case, it might be some newer instruction sets that qemu5 doesn’t support.
4. Note some instruction sets are not implemented by QEMU.

If you are still using Unicorn1, please upgrade to Unicorn2 for better support.

## I can't recover from unmapped read/write even I return `true` in the hook, why?

This is a minor change in memory hooks behavior between Unicorn1 and Unicorn2. To gracefully recover from memory read/write error, you have to map the invalid memory before you return true.

It is due to the fact that, if users return `true` without memory mapping set up correctly, we don't know what to do next. In Unicorn1, the behavior is __undefined__ in this case but in Unicorn2 we would like to force users to set up memory mapping in the hook to continue execution.

See the [sample](https://github.com/unicorn-engine/unicorn/blob/c05fbb7e63aed0b60fc2888e08beceb17bce8ac4/samples/sample_x86.c#L1379-L1393) for details.

## My MIPS emulation gets weird read/write error and CPU exceptions.

Note you might have an address that falls in MIPS `kseg` segments. In that case, MMU is bypassed and you have to make sure the corresponding physical memory is mapped. See [#217](https://github.com/unicorn-engine/unicorn/issues/217), [#1371](https://github.com/unicorn-engine/unicorn/issues/1371), [#1550](https://github.com/unicorn-engine/unicorn/issues/1371).

## KeyboardInterrupt is not raised during `uc.emu_start`

This is intended as python [signal module](https://docs.python.org/3.10/library/signal.html) states:

> A long-running calculation implemented purely in C (such as regular expression matching on a large body of text) may run uninterrupted for an arbitrary amount of time, regardless of any signals received. The Python signal handlers will be called when the calculation finishes.

A workaround is to start emulation in another thread.

## Editing an instruction doesn't take effect/Hooks added during emulation are not called.

Unicorn is a fork of QEMU and inherits most QEMU internal mechanisms, one of which is called TB chaining. In short, every block (in most cases, a `basic block`) is translated, executed and __cached__. Therefore, any operation on cached addresses won't immediately take effect without a call to `uc_ctl_remove_cache`. Check a more detailed discussion here: [#1561](https://github.com/unicorn-engine/unicorn/issues/1561)

Note, this doesn't mean you have to care about Self Modifying Code because the read/write happens within emulation (TB execution) and QEMU would handle such special cases. For technical details, refer to the [QEMU paper](https://www.usenix.org/legacy/event/usenix05/tech/freenix/full_papers/bellard/bellard.pdf).

TLDR: To ensure any modification to an address will take effect:

1. Call `uc_ctl_remove_cache` on the target address.
2. Call `uc_reg_write` to write current PC to the PC register, if the modification happens during emulation. It restarts emulation (but doesn't quit `uc_emu_start`) on current address to re-translate the block.

## How to emulate interrupts (or ticks) with Unicorn?

As stated, Unicorn is a pure CPU emulator. For such emulation, you have two choices:

- Use the `timeout` parameter of `uc_emu_start`
- Use the `count` parameter of `uc_emu_start`

After emulation stops, you may check anything you feel interested and resume emulation accordingly.

Note that for cortex-m `exec_return`, Unicorn has a magic software exception with interrupt number 8. You may register a hook to handle that.

## Why not keep up the upstream qemu?

To provide end users with simple API, Unicorn does lots of dirty hacks within qemu code which prevents it from sync painlessly.

## Is there anyway to disable softmmu to speed up execution?

Yes, it’s possible but that is not Unicorn’s goal and there is no simple switch in qemu to disable softmmu.

## I'd like to make contributions, where do I start?

See [milestones](https://github.com/unicorn-engine/unicorn/milestones) and [coding convention](https://github.com/unicorn-engine/unicorn/wiki/Coding-Convention
).

Be sure to send pull requests for our **dev** branch only.

## Which qemu version is Unicorn based on?

Prior to 2.0.0, Unicorn is based on qemu 2.2.1. After that, Unicorn is based on qemu 5.0.1. 