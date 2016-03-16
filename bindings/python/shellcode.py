#!/usr/bin/env python
# Sample code for X86 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *


X86_CODE32 = b"\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff\xff\xff\x68\x65\x6c\x6c\x6f"

X86_CODE32_SELF = b"\xeb\x1c\x5a\x89\xd6\x8b\x02\x66\x3d\xca\x7d\x75\x06\x66\x05\x03\x03\x89\x02\xfe\xc2\x3d\x41\x41\x41\x41\x75\xe9\xff\xe6\xe8\xdf\xff\xff\xff\x31\xd2\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xca\x7d\x41\x41\x41\x41\x41\x41\x41\x41"

X86_CODE64 = "\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"

# memory address where emulation starts
ADDRESS = 0x1000000


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    # read this instruction code from memory
    tmp = uc.mem_read(address, size)
    print(">>> Instruction code at [0x%x] =" %(address), end="")
    for i in tmp:
        print(" %02x" %i, end="")
    print("")


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing Linux interrupt
def hook_intr(uc, intno, user_data):
    # only handle Linux syscall
    if intno != 0x80:
        print("got interrupt %x ???" %intno);
        uc.emu_stop()
        return

    eax = uc.reg_read(UC_X86_REG_EAX)
    eip = uc.reg_read(UC_X86_REG_EIP)
    if eax == 1:    # sys_exit
        print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" %(eip, intno, eax))
        uc.emu_stop()
    elif eax == 4:    # sys_write
        # ECX = buffer address
        ecx = uc.reg_read(UC_X86_REG_ECX)
        # EDX = buffer size
        edx = uc.reg_read(UC_X86_REG_EDX)

        try:
            buf = uc.mem_read(ecx, edx)
            print(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = " \
                        %(eip, intno, ecx, edx), end="")
            for i in buf:
                print("%c" %i, end="")
            print("")
        except UcError as e:
            print(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = <unknown>\n" \
                        %(eip, intno, ecx, edx))
    else:
        print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" %(eip, intno, eax))


def hook_syscall(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    print(">>> got SYSCALL with RAX = 0x%x" %(rax))
    mu.emu_stop()


# Test X86 32 bit
def test_i386(mode, code):
    print("Emulate x86 code")
    try:
        # Initialize emulator
        mu = Uc(UC_ARCH_X86, mode)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # handle interrupt ourself
        mu.hook_add(UC_HOOK_INTR, hook_intr)

        # handle SYSCALL
        mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(code))

        # now print out some registers
        print(">>> Emulation done")

    except UcError as e:
        print("ERROR: %s" % e)



if __name__ == '__main__':
    test_i386(UC_MODE_32, X86_CODE32_SELF)
    print("=" * 20)
    test_i386(UC_MODE_32, X86_CODE32)
    print("=" * 20)
    test_i386(UC_MODE_64, X86_CODE64)  # FIXME

