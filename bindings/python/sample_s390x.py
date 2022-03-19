#!/usr/bin/env python

from unicorn import *
from unicorn.s390x_const import *

# lr %r2, %r3
S390X_CODE = b"\x18\x23"

# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test RISCV
def test_s390x():
    print("Emulate S390X code")
    try:
        # Initialize emulator in big endian mode
        mu = Uc(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, S390X_CODE)

        # initialize machine registers
        mu.reg_write(UC_S390X_REG_R3, 0x7890)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(S390X_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r2 = mu.reg_read(UC_S390X_REG_R2)
        r3 = mu.reg_read(UC_S390X_REG_R3)
        print(">>> R2 = 0x%x" % r2)
        print(">>> R3 = 0x%x" % r3)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_s390x()

