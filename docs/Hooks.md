## Introduction

In general, all the hooks can be bound to a region of the emulated memory, so that they will only fire when that region is reached (or accessed). The hooks are also stored in a list, so the more hooks that you add, the more processing that is needed by the system to dispatch them. This can make your emulation slow down if you have a lot of hooks present.

Some hooks can return a value, which if non-0 will abort execution.


## UC_HOOK_BLOCK

*What is it?*

Let's first deal with the `UC_HOOK_BLOCK` case. These hooks are called whenever the code execution starts within a 'basic block' in the emulated code. A 'basic block' is a sequence of instructions without any conditional branch or special processing instructions (or other events like the end of mapped memory) - a sequence that can be entirely emulated in (effectively) a linear path. The UC_HOOK_BLOCK is called with the address of the start of the block that's being executed and the size of that block (in bytes).

Because the block hooks are only called on entry to a section of code which must be executed, you can guarantee the execution passes through all the instructions in the block. If some instructions are conditional, the effect of the instruction might be null - e.g. `ADDEQ r0, r0, r1` in ARM is a conditional add that only happens if the Z flag is set. The basic block might contain any number of these conditional instructions as the execution still passes through the instructions.

*Why might you use it?*

If you want a gross understanding of the code path, knowing where the system executed, you might use a block hook. Your hook might write diagnostics about where the code was at that time and the state of registers. This would give you a very clear picture of how the execution was passing through the system. Loops, for example, might result in the same block hook being fired repeatedly, as the code passes through the same code, ending in the conditional jump back to the start of the loop.

If you were disassembling the code, you could perform the disassembly on each block for its entire range, rather than using a code hook.


## UC_HOOK_CODE

*What is it?*

The `UC_HOOK_CODE` is more fine-grained than the `UC_HOOK_BLOCK`. This occurs on every instruction that is executed, before it is executed. So whilst `UC_HOOK_BLOCK` is "I'm about to run this section of code", `UC_HOOK_CODE` is "I'm about to run this instruction". There being a lot of code hooks means that your hook will be called a lot. The hook is called (like the block hook) with the address of the code being executed, and its size. The size will only ever cover one instruction, however.

*Why might you use it?*

If you want to breakpoint the code at a particular place, this hook is a perfect way to do that. Calling `uc_emu_stop` will cause the emulation to stop at this point.

You might also use it to trace the execution with a disassembly, in a similar way to the block hooks, above. Because you're executing at the instruction level, this means that you can read the registers as they are before the code is executed, which may be useful for your disassembly.

If you want to inject behaviour you might use this hook to modify the registers - including modifying the program counter, to jump to a different place.


## UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_READ_MEM_AFTER

*What is it?*

The `UC_HOOK_MEM_READ` and `UC_HOOK_MEM_WRITE` hooks are called whilst the emulator is executing instructions. When the code being emulated tries to read or write memory within the range, the hooks will be called.

For `UC_HOOK_MEM_READ`, the hook is called with the address that is being read, and the size of the access. A 'value' is passed, but this operation occurs before the value has been read, so its content is indeterminate.

For `UC_HOOK_MEM_WRITE`, the hook is called with the address that is being written, the size of the access and the value that was written to it.

For `UC_HOOK_MEM_READ_AFTER`, the hook is called *after* the read has occurred. It is the same as `UC_HOOK_MEM_READ` except that the value has been populated.

These hooks are not used if you directly access the memory using the Unicorn `mem_*` functions.

*Why might you use it?*

If you were providing watchpoints that track accesses to memory, you might use any of these 3 hooks. You could report all the registers and the program counter at the time of access - even reporting a stack backtrace if you knew the calling standard.

You might use these `UC_HOOK_MEM_READ` and `UC_HOOK_MEM_WRITE` operations to fake memory mapped IO. If you had a memory mapped device that you wanted to expose to the system, you could use a `UC_HOOK_MEM_READ` hook to write a suitable value into memory for the memory mapped register being accessed. The execution of the instruction would then pick up the new value that you had written.

Similarly, the `UC_HOOK_MEM_WRITE` could update your internal state with the register that had been written to the address.

You might implement memory protection in a different manner than the standard Unicorn form. For example, you might check that processor mode and decide whether the memory is actually accessible or not to the code that is performing that access. This isn't usually an operation of the CPU (although some CPUs and MMUs do have this ability), but for diagnosing whether a given section of code should be *able* to access other memory this could be useful.


## UC_HOOK_MEM_FETCH

*What is it?*

The `UC_HOOK_MEM_FETCH` hook is not used.

*Why might you use it?*

You wouldn't. It's deprecated and will never be called.


## UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED

*What is it?*

All 3 of these hooks are called when there is an access to a region for which there is no memory mapping.

The `UC_HOOK_MEM_READ_UNMAPPED` hooks is called when the code tries to read an unmapped memory region.

The `UC_HOOK_MEM_WRITE_UNMAPPED` hooks is called when the code tries to write to an unmapped memory region.

The `UC_HOOK_MEM_FETCH_UNMAPPED` hooks is called when the emulator needs to read an unmapped memory region to fetch code to execute.

In all cases, you can either map the page in with the `uc_mem_map*` function or return non-0 to abort execution.

*Why might you use it?*

You might use these for dynamic memory mapping, only mapping in the memory when it is needed - which could be useful for a virtual-memory type system.

You might use it for trapping bad accesses at the time that they happen (although the usual abort that you would get will also give you this information).



## UC_HOOK_MEM_READ_PROT, UC_HOOK_MEM_WRITE_PROT, UC_HOOK_MEM_FETCH_PROT

*What is it?*

All 3 of these hooks are called when there is an access to a region for which there is a memory mapping but the memory was mapped with one of the `UC_PROT_*` restrictions.

The `UC_HOOK_MEM_READ_PROT` hooks is called when the code tries to read a region that isn't allowed to be read.

The `UC_HOOK_MEM_WRITE_PROT` hooks is called when the code tries to write to a region that isn't allowed to be written.

The `UC_HOOK_MEM_FETCH_PROT` hooks is called when the emulator needs to read an instruction from a region that isn't allowed to execute.

In all cases you can either map the page in with the `uc_mem_protect*` function or return non-0 to abort execution.

*Why might you use it?*

You might change the protection level of the region to allow the memory to be accessed, or you might return non-0 to abort execution.