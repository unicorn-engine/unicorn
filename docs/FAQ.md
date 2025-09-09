## Why is my execution so slow?

Typically, it’s due to

- Instrumenting every instruction executed.
- Instrumenting every memory access.

Optimize your program with less instrumentation, e.g. by using `UC_HOOK_BLOCK` instead of `UC_HOOK_CODE`

## Why do I get a wrong PC after emulation stops?

<details>
  <summary>For version < 2.1.4 </summary>
  
Updating PC is a very large overhead (10x slower in the worst case, see FAQ above) for emulation so the PC sync guarantee is explained below in several cases:

- A `UC_HOOK_CODE` hook is installed. In this case, the PC is sync-ed _everywhere_ within the effective range of the hook. However, on some architectures, the PC might by sync-ed all the time if the hook is installed in any range. Note using `count` in `uc_emu_start` implies installing a `UC_HOOK_CODE` hook.
- A `UC_HOOK_MEM_READ` or `UC_HOOK_MEM_WRITE` hook is installed. In this case, the PC is sync-ed exactly before any read/write events within the effective range of the hook.
- Emulation (`uc_emu_start`) terminates without any exception. In this case, the PC will point to the next instruction.
- No hook mentioned above is installed and emulation terminates with exceptions. In this case, the PC is sync-ed at the basic block boundary, in other words, the first instruction of the basic block where the exception happens.

Below is an example:

```
mov x0, #1 <--- the PC will be here
mov x1, #2
ldr x0, [x1] <--- exception here
```

If `ldr x0, [x1]` fails with memory exceptions, the PC will be left at the beginning of the basic block, in this case `mov x0, #1`.

However, if a `UC_HOOK_MEM_READ` hook is installed, the PC will be sync-ed:

```
mov x0, #1 
mov x1, #2
ldr x0, [x1] <--- exception here and PC sync-ed here
```
  
</details>

<details>
  <summary>For version >= 2.1.4 </summary>

We should always have valid PC all the time. Please report an issue for your case.

</details>

## I get an “Unhandled CPU Exception”, why?

Unicorn is a pure CPU emulator and usually it’s due to no handler registered for instructions like `syscall` and `SVC`. If you expect syscall and userland emulation, you probably would like [qiling framework](https://github.com/qilingframework/qiling).

## I would like to instrument a specific instruction but get a `UC_ERR_HOOK`, why?

Currently, only a small subset of the instructions can be instrumented.

On x86, all available instructions are: `in` `out` `syscall` `sysenter` `cpuid`.

## Emulating some instructions gives an error like "Invalid Instruction", what should I do?

1. Some instructions are not enabled by default on some architectures. For example, you have to setup CSR on RISC-V or VFP on ARM before emulating floating-point instructions. Refer to the corresponding manual to check if you leave out possible switches in special registers.
2. Different CPU models support different sets of instructions. This is especially observed on ARM CPUs. For example, for `THUMB2` big-endian instructions, consider setting CPU model to `cortex-r5` or `arm_max`. See [#1725](https://github.com/unicorn-engine/unicorn/issues/1725) and [#1724](https://github.com/unicorn-engine/unicorn/issues/1724).
3. If you are on ARM, please check whether you are emulating a THUMB instruction. If so, please use `UC_MODE_THUMB` and make sure the starting address is odd. 
4. If it's not the cases above, it might be some newer instruction sets that qemu5 doesn’t support.
5. Note some instruction sets are not implemented by the latest QEMU.

If you are still using Unicorn1, please upgrade to Unicorn2 for better support.

## Memory hooks get called multiple times for a single instruction

There are several possibilities, e.g.:

- The instruction might access memory multiple times like `rep stos` in x86.
- The address to access is bad-aligned and thus the MMU emulation will split the access into several aligned memory access. In worst cases on some arch, it leads to byte by byte access.

## I can't recover from unmapped read/write even I return `true` in the hook, why?

This is a minor change in memory hooks behavior between Unicorn1 and Unicorn2. To gracefully recover from memory read/write error, you have to map the invalid memory before you return true.

It is due to the fact that, if users return `true` without memory mapping set up correctly, we don't know what to do next. In Unicorn1, the behavior is __undefined__ in this case but in Unicorn2 we would like to force users to set up memory mapping in the hook to continue execution.

See the [sample](https://github.com/unicorn-engine/unicorn/blob/c05fbb7e63aed0b60fc2888e08beceb17bce8ac4/samples/sample_x86.c#L1379-L1393) for details.

## My emulation gets weird read/write error and CPU exceptions.

For MIPS, you might have an address that falls in MIPS `kseg` segments. In that case, MMU is bypassed and you have to make sure the corresponding physical memory is mapped. See [#217](https://github.com/unicorn-engine/unicorn/issues/217), [#1371](https://github.com/unicorn-engine/unicorn/issues/1371), [#1550](https://github.com/unicorn-engine/unicorn/issues/1371).

For ARM, you might have an address that falls in some non-executable segments. For example, for m-class ARM cpu, some memory area is not executable according to [the ARM document](https://developer.arm.com/documentation/ddi0403/d/System-Level-Architecture/System-Address-Map/The-system-address-map?lang=en). 

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

Starting from 2.0.2, Unicorn will emulate the MMU depending on the emulated architecture without further hacks. That said, Unicorn offers the full ability of the target MMU implementation. While this enables more possibilities of Uncorn, it has a few drawbacks:

- As previous question points out already, some memory regions are not writable/executable.
- You have to always check architecture-specific registers to confirm MMU status.
- `uc_mem_map` will always deal with physical addresses while `uc_emu_start` accepts virtual addresses.

Therefore, if you still prefer the previous `paddr = vaddr` simple mapping, we have a simple experimental MMU implementation that can be switched on by: `uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL)`. With this mode, you could also add a `UC_HOOK_TLB_FILL` hook to manage the TLB. When a virtual address is not cached, the hook will be called. Besides, users are allowed to flush the tlb with `uc_ctl_flush_tlb`.

In theory, `UC_TLB_VIRTUAL` will achieve better performance as it skips all MMU details, though not benchmarked.

## Something is wrong - I would like to dig deeper

Unicorn uses at several places logging by the qemu implementation.
This might provide a first glance what could be wrong.

The logs contains optionally the filename and the line number including
additional messages to indicate what is happening.
However, the qemu logs are partially commented-out and incomplete, but give it a try.
You might want to dig deeper - and add your own log messages where you expect or try to find the bug.

To enable logs, you must recompile Unicorn with `-DUNICORN_LOGGING=yes` to cmake.

Logs are written in different log levels, which might result into a very verbose logging if enabled.
To control the log level information, two environment variables could be used.

`UNICORN_LOG_LEVEL` and `UNICORN_LOG_DETAIL_LEVEL`.

These environment variables are parsed into `uint32_t` values once, (due to performance reasons)
so set these environment variables before you execute any line of Unicorn.
Allowed are hexa-decimal, decimal and octal values, which fits into a buffer of 10 chars. (see stroul for details).

To define how detailed and what should be logged, use the following environment variables:

- `UNICORN_LOG_LEVEL`=\<32bit mask\>
  - The qemu bit mask what should be logged.
  - Use the value of `UINT32_MAX` to log everything.
  - If no bit is set in the mask, there will be no logging.
- `UNICORN_LOG_DETAIL_LEVEL`=\<level\>
  - The level defines how the filename and line is constructed.
    - 0: no filename and no line is used.
    - 1: full filename including the leading path is used with line information.
    - 2: just the filename with line information. It might be a little confusing,
    as the file name can be used in several places.
  - If unsure or unwanted, leave this variable undefined or set it to 0.

As an example to set up the environment for python correctly, see the example below.

```python
import os
os.environ['UNICORN_LOG_LEVEL'] = "0xFFFFFFFF" # verbose - print anything 
os.environ['UNICORN_LOG_DETAIL_LEVEL'] = "1" # full filename with line info
```

Please note that file names are statically compiled in and can reveal the paths
of the file system used during compilation.

## Does Unicorn support ARM PAC (Pointer Authentication)?

Yes! However, Unicorn by default disables it and enabling it involves a few coding and document reading.

TLDR:

Taken from [#1789](https://github.com/unicorn-engine/unicorn/issues/1789).

```C
    uc_arm64_cp_reg reg;

    // SCR_EL3
    reg.op0 = 0b11;
    reg.op1 = 0b110;
    reg.crn = 0b0001;
    reg.crm = 0b0001;
    reg.op2 = 0b000;

    err = uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg);
    assert(err == UC_ERR_OK);

    // NS && RW && API
    reg.val |= (1 | (1<<10) | (1<<17));

    err = uc_reg_write(uc, UC_ARM64_REG_CP_REG, &reg);
    assert(err == UC_ERR_OK);

    // SCTLR_EL1
    reg.op0 = 0b11;
    reg.op1 = 0b000;
    reg.crn = 0b0001;
    reg.crm = 0b0000;
    reg.op2 = 0b000;

    err = uc_reg_read(uc, UC_ARM64_REG_CP_REG, &reg);
    assert(err == UC_ERR_OK);

    // EnIA && EnIB
    reg.val |= (1<<31) | (1<<30);

    err = uc_reg_write(uc, UC_ARM64_REG_CP_REG, &reg);
    assert(err == UC_ERR_OK);
    
    // HCR_EL2
    reg.op0 = 0b11;
    reg.op1 = 0b100;
    reg.crn = 0b0001;
    reg.crm = 0b0001;
    reg.op2 = 0b000;

    // HCR.API
    reg.val |= (1ULL<<41);

    err = uc_reg_write(uc, UC_ARM64_REG_CP_REG, &reg);
    assert(err == UC_ERR_OK);
```

For further explanation, refer to related ARM documents. Here is an incomplete list:

- [System register control of pointer authentication](https://developer.arm.com/documentation/ddi0487/latest/)
- [EnIA & EnIB](https://developer.arm.com/documentation/ddi0595/2021-12/AArch64-Registers/SCTLR-EL1--System-Control-Register--EL1-?lang=en#fieldset_0-31_31-1)
- [HCR.API](https://developer.arm.com/documentation/ddi0601/2020-12/AArch64-Registers/HCR-EL2--Hypervisor-Configuration-Register?lang=en#fieldset_0-41_41-1)
Note you could find the definitions of these registers at the end of corresponding documents.

## I debug my application but soon get an access violation inside unicorn.

This is intended for Windows. See discussion in [#1841](https://github.com/unicorn-engine/unicorn/issues/1841).

## My code does not do what I would expect - is this a bug?

Please create a github issue and provide as many details as possible.

- [ ] Simplified version of your script / source
  - Make sure that "no" external dependencies are needed.
  - E.g. remove additional use of capstone or CTF tools.
- [ ] Used Unicorn git-hash commit
  - Make sure to exclude any changes of you made in unicorn.
  - Alternativily provide the repo link to your commit.
- [ ] Detailed explaination what is expected
  - Try to verify if the instructions can be processed by qemu.
  - Dumping the registers of unicorn and qemu helps a lot.
- [ ] Detailed explaination what is observed
  - Describe what's going on (and what you might think about it).
- [ ] Output from your executed script
  - You might have additional log messages which could be helpful.
- [ ] Output from the qemu-logs
  - Try to gather more informations by enabling the qemu logging.
- [ ] More details
  - Attach more details to help reproduce the bug.
  - Like attaching a repo link to the CTF challenge containing the binary or source code.

## I'd like to make contributions, where do I start?

See [milestones](https://github.com/unicorn-engine/unicorn/milestones) and [coding convention](https://github.com/unicorn-engine/unicorn/wiki/Coding-Convention
).

Be sure to send pull requests for our **dev** branch only.

## Which qemu version is Unicorn based on?

Prior to 2.0.0, Unicorn is based on qemu 2.2.1. After that, Unicorn is based on qemu 5.0.1.
