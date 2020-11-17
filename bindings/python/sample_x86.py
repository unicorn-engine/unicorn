#!/usr/bin/env python
# Sample code for X86 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import pickle

X86_CODE32 = b"\x41\x4a\x66\x0f\xef\xc1" # INC ecx; DEC edx; PXOR xmm0, xmm1
X86_CODE32_LOOP = b"\x41\x4a\xeb\xfe" # INC ecx; DEC edx; JMP self-loop
X86_CODE32_JUMP = b"\xeb\x02\x90\x90\x90\x90\x90\x90" # jmp 4; nop; nop; nop; nop; nop; nop
X86_CODE32_JMP_INVALID = b"\xe9\xe9\xee\xee\xee\x41\x4a" # JMP outside; INC ecx; DEC edx
X86_CODE32_MEM_READ = b"\x8B\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx
X86_CODE32_MEM_WRITE = b"\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
X86_CODE64 = b"\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59"
X86_CODE32_INOUT = b"\x41\xE4\x3F\x4a\xE6\x46\x43" # INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx
X86_CODE64_SYSCALL = b'\x0f\x05' # SYSCALL
X86_CODE16 = b'\x00\x00' # add   byte ptr [bx + si], al

# memory address where emulation starts
ADDRESS = 0x1000000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)
    print(">>> --- EFLAGS is 0x%x" %eflags)

def hook_code64(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    rip = uc.reg_read(UC_X86_REG_RIP)
    print(">>> RIP is 0x%x" %rip);


# callback for tracing invalid memory access (READ or WRITE)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
        # map this memory in with 2MB in size
        uc.mem_map(0xaaaa0000, 2 * 1024*1024)
        # return True to indicate we want to continue emulation
        return True
    else:
        # return False to indicate we want to stop emulation
        return False


# callback for tracing memory access (READ or WRITE)
def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
    else:   # READ
        print(">>> Memory is being READ at 0x%x, data size = %u" \
                %(address, size))


# callback for IN instruction
def hook_in(uc, port, size, user_data):
    eip = uc.reg_read(UC_X86_REG_EIP)
    print("--- reading from port 0x%x, size: %u, address: 0x%x" %(port, size, eip))
    if size == 1:
        # read 1 byte to AL
        return 0xf1
    if size == 2:
        # read 2 byte to AX
        return 0xf2
    if size == 4:
        # read 4 byte to EAX
        return 0xf4
    # we should never reach here
    return 0


# callback for OUT instruction
def hook_out(uc, port, size, value, user_data):
    eip = uc.reg_read(UC_X86_REG_EIP)
    print("--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x" %(port, size, value, eip))

    # confirm that value is indeed the value of AL/AX/EAX
    v = 0
    if size == 1:
        # read 1 byte in AL
        v = uc.reg_read(UC_X86_REG_AL)
    if size == 2:
        # read 2 bytes in AX
        v = uc.reg_read(UC_X86_REG_AX)
    if size == 4:
        # read 4 bytes in EAX
        v = uc.reg_read(UC_X86_REG_EAX)

    print("--- register value = 0x%x" %v)


# Test X86 32 bit
def test_i386():
    print("Emulate i386 code")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)
        mu.reg_write(UC_X86_REG_XMM0, 0x000102030405060708090a0b0c0d0e0f)
        mu.reg_write(UC_X86_REG_XMM1, 0x00102030405060708090a0b0c0d0e0f0)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        r_xmm0 = mu.reg_read(UC_X86_REG_XMM0)
        print(">>> ECX = 0x%x" %r_ecx)
        print(">>> EDX = 0x%x" %r_edx)
        print(">>> XMM0 = 0x%.32x" %r_xmm0)

        # read from memory
        tmp = mu.mem_read(ADDRESS, 4)
        print(">>> Read 4 bytes from [0x%x] = 0x" %(ADDRESS), end="")
        for i in reversed(tmp):
            print("%x" %(i), end="")
        print("")

    except UcError as e:
        print("ERROR: %s" % e)


def test_i386_map_ptr():
    print("Emulate i386 code - use uc_mem_map_ptr()")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32), 2 * UC_SECOND_SCALE)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        print(">>> ECX = 0x%x" %r_ecx)
        print(">>> EDX = 0x%x" %r_edx)

        # read from memory
        tmp = mu.mem_read(ADDRESS, 4)
        print(">>> Read 4 bytes from [0x%x] = 0x" %(ADDRESS), end="")
        for i in reversed(tmp):
            print("%x" %(i), end="")
        print("")

    except UcError as e:
        print("ERROR: %s" % e)


def test_i386_invalid_mem_read():
    print("Emulate i386 code that read from invalid memory")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_MEM_READ)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        try:
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_MEM_READ))
        except UcError as e:
            print("Failed on uc_emu_start() with error returned 6: %s" % e)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        print(">>> ECX = 0x%x" %r_ecx)
        print(">>> EDX = 0x%x" %r_edx)

    except UcError as e:
        print("ERROR: %s" % e)

def test_i386_jump():
    print("Emulate i386 code with jump")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_JUMP)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block, begin=ADDRESS, end=ADDRESS)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

        try:
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_JUMP))
        except UcError as e:
            print("ERROR: %s" % e)

        print(">>> Emulation done. Below is the CPU context")

    except UcError as e:
        print("ERROR: %s" % e)


def test_i386_invalid_mem_write():
    print("Emulate i386 code that write to invalid memory")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_MEM_WRITE)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # intercept invalid memory events
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

        try:
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_MEM_WRITE))
        except UcError as e:
            print("ERROR: %s" % e)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        print(">>> ECX = 0x%x" %r_ecx)
        print(">>> EDX = 0x%x" %r_edx)

        # read from memory
        print(">>> Read 4 bytes from [0x%x] = 0x" %(0xaaaaaaaa), end="")
        tmp = mu.mem_read(0xaaaaaaaa, 4)
        for i in reversed(tmp):
            if i != 0:
                print("%x" %i, end="")
        print("")

        try:
            tmp = mu.mem_read(0xffffffaa, 4)
            print(">>> Read 4 bytes from [0x%x] = 0x" %(0xffffffaa), end="")
            for i in reversed(tmp):
                print("%x" %i, end="")
            print("")

        except UcError as e:
            print(">>> Failed to read 4 bytes from [0xffffffaa]")

    except UcError as e:
        print("ERROR: %s" % e)

def test_i386_jump_invalid():
    print("Emulate i386 code that jumps to invalid memory")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_JMP_INVALID)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        try:
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_JMP_INVALID))
        except UcError as e:
            print("Failed on uc_emu_start() with error returned 8: %s" %e)

        print(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        print(">>> ECX = 0x%x" %r_ecx)
        print(">>> EDX = 0x%x" %r_edx)

    except UcError as e:
        print("ERROR %s" % e)

def test_i386_loop():
    print("Emulate i386 code that loop forever")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_LOOP)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_LOOP), timeout=2*UC_SECOND_SCALE)

        print(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        print(">>> ECX = 0x%x" %r_ecx)
        print(">>> EDX = 0x%x" %r_edx)

    except UcError as e:
        print("ERROR: %s" % e)


# Test X86 32 bit with IN/OUT instruction
def test_i386_inout():
    print("Emulate i386 code with IN/OUT instructions")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_INOUT)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_EAX, 0x1234)
        mu.reg_write(UC_X86_REG_ECX, 0x6789)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # handle IN & OUT instruction
        mu.hook_add(UC_HOOK_INSN, hook_in, None, 1, 0, UC_X86_INS_IN)
        mu.hook_add(UC_HOOK_INSN, hook_out, None, 1, 0, UC_X86_INS_OUT)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_INOUT))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_eax = mu.reg_read(UC_X86_REG_EAX)
        print(">>> EAX = 0x%x" %r_eax)
        print(">>> ECX = 0x%x" %r_ecx)
    except UcError as e:
        print("ERROR: %s" % e)


def test_i386_context_save():
    print("Save/restore CPU context in opaque blob")
    address = 0
    code = b'\x40'  # inc eax
    try:
        # Initialize emulator
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 8KB memory for this emulation
        mu.mem_map(address, 8 * 1024, UC_PROT_ALL)

        # write machine code to be emulated to memory
        mu.mem_write(address, code)

        # set eax to 1
        mu.reg_write(UC_X86_REG_EAX, 1)

        print(">>> Running emulation for the first time")
        mu.emu_start(address, address+1)

        print(">>> Emulation done. Below is the CPU context")
        print(">>> EAX = 0x%x" %(mu.reg_read(UC_X86_REG_EAX)))
        print(">>> Saving CPU context")
        saved_context = mu.context_save()

        print(">>> Pickling CPU context")
        pickled_saved_context = pickle.dumps(saved_context)

        print(">>> Running emulation for the second time")
        mu.emu_start(address, address+1)
        print(">>> Emulation done. Below is the CPU context")
        print(">>> EAX = 0x%x" %(mu.reg_read(UC_X86_REG_EAX)))

        print(">>> Unpickling CPU context")
        saved_context = pickle.loads(pickled_saved_context)

        print(">>> CPU context restored. Below is the CPU context")
        mu.context_restore(saved_context)
        print(">>> EAX = 0x%x" %(mu.reg_read(UC_X86_REG_EAX)))

    except UcError as e:
        print("ERROR: %s" % e)

def test_x86_64():
    print("Emulate x86_64 code")
    try:
        # Initialize emulator in X86-64bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE64)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_RAX, 0x71f3029efd49d41d)
        mu.reg_write(UC_X86_REG_RBX, 0xd87b45277f133ddb)
        mu.reg_write(UC_X86_REG_RCX, 0xab40d1ffd8afc461)
        mu.reg_write(UC_X86_REG_RDX, 0x919317b4a733f01)
        mu.reg_write(UC_X86_REG_RSI, 0x4c24e753a17ea358)
        mu.reg_write(UC_X86_REG_RDI, 0xe509a57d2571ce96)
        mu.reg_write(UC_X86_REG_R8, 0xea5b108cc2b9ab1f)
        mu.reg_write(UC_X86_REG_R9, 0x19ec097c8eb618c1)
        mu.reg_write(UC_X86_REG_R10, 0xec45774f00c5f682)
        mu.reg_write(UC_X86_REG_R11, 0xe17e9dbec8c074aa)
        mu.reg_write(UC_X86_REG_R12, 0x80f86a8dc0f6d457)
        mu.reg_write(UC_X86_REG_R13, 0x48288ca5671c5492)
        mu.reg_write(UC_X86_REG_R14, 0x595f72f6e4017f6e)
        mu.reg_write(UC_X86_REG_R15, 0x1efd97aea331cccc)

        # setup stack
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + 0x200000)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions in range [ADDRESS, ADDRESS+20]
        mu.hook_add(UC_HOOK_CODE, hook_code64, None, ADDRESS, ADDRESS+20)

        # tracing all memory READ & WRITE access
        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)
        # actually you can also use READ_WRITE to trace all memory access
        #mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

        try:
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE64))
        except UcError as e:
            print("ERROR: %s" % e)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        rax = mu.reg_read(UC_X86_REG_RAX)
        rbx = mu.reg_read(UC_X86_REG_RBX)
        rcx = mu.reg_read(UC_X86_REG_RCX)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        rdi = mu.reg_read(UC_X86_REG_RDI)
        r8 = mu.reg_read(UC_X86_REG_R8)
        r9 = mu.reg_read(UC_X86_REG_R9)
        r10 = mu.reg_read(UC_X86_REG_R10)
        r11 = mu.reg_read(UC_X86_REG_R11)
        r12 = mu.reg_read(UC_X86_REG_R12)
        r13 = mu.reg_read(UC_X86_REG_R13)
        r14 = mu.reg_read(UC_X86_REG_R14)
        r15 = mu.reg_read(UC_X86_REG_R15)

        print(">>> RAX = 0x%x" %rax)
        print(">>> RBX = 0x%x" %rbx)
        print(">>> RCX = 0x%x" %rcx)
        print(">>> RDX = 0x%x" %rdx)
        print(">>> RSI = 0x%x" %rsi)
        print(">>> RDI = 0x%x" %rdi)
        print(">>> R8 = 0x%x" %r8)
        print(">>> R9 = 0x%x" %r9)
        print(">>> R10 = 0x%x" %r10)
        print(">>> R11 = 0x%x" %r11)
        print(">>> R12 = 0x%x" %r12)
        print(">>> R13 = 0x%x" %r13)
        print(">>> R14 = 0x%x" %r14)
        print(">>> R15 = 0x%x" %r15)


    except UcError as e:
        print("ERROR: %s" % e)


def test_x86_64_syscall():
    print("Emulate x86_64 code with 'syscall' instruction")
    try:
        # Initialize emulator in X86-64bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE64_SYSCALL)

        def hook_syscall(mu, user_data):
            rax = mu.reg_read(UC_X86_REG_RAX)
            if rax == 0x100:
                mu.reg_write(UC_X86_REG_RAX, 0x200)
            else:
                print('ERROR: was not expecting rax=%d in syscall' % rax)

        # hook interrupts for syscall
        mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

        # syscall handler is expecting rax=0x100
        mu.reg_write(UC_X86_REG_RAX, 0x100)

        try:
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE64_SYSCALL))
        except UcError as e:
            print("ERROR: %s" % e)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        rax = mu.reg_read(UC_X86_REG_RAX)
        print(">>> RAX = 0x%x" % rax)

    except UcError as e:
        print("ERROR: %s" % e)


def test_x86_16():
    print("Emulate x86 16-bit code")
    try:
        # Initialize emulator in X86-16bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_16)

        # map 8KB memory for this emulation
        mu.mem_map(0, 8 * 1024)

        # set CPU registers
        mu.reg_write(UC_X86_REG_EAX, 7)
        mu.reg_write(UC_X86_REG_EBX, 5)
        mu.reg_write(UC_X86_REG_ESI, 6)

        # write machine code to be emulated to memory
        mu.mem_write(0, X86_CODE16)

        # emulate machine code in infinite time
        mu.emu_start(0, len(X86_CODE16))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        tmp = mu.mem_read(11, 1)
        print(">>> Read 1 bytes from [0x%x] = 0x%x" %(11, tmp[0]))

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_x86_16()
    test_i386()
    print("=" * 35)
    test_i386_map_ptr()
    print("=" * 35)
    test_i386_inout()
    print("=" * 35)
    test_i386_context_save()
    print("=" * 35)
    test_i386_jump()
    print("=" * 35)
    test_i386_loop()
    print("=" * 35)
    test_i386_invalid_mem_read()
    print("=" * 35)
    test_i386_invalid_mem_write()
    print("=" * 35)
    test_i386_jump_invalid()
    test_x86_64()
    print("=" * 35)
    test_x86_64_syscall()
