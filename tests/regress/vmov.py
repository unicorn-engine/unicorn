#!/usr/bin/env python
# Moshe Kravchik

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *



# code to be emulated
THUMB_CODE_FAIL = "\xC0\xEF\x10\x00" #                 VMOV.I32        D16, #0 ; Vector Move
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))

def test_thumb(code):
    print("Emulate THUMB code")
    try:
        # Initialize emulator in thumb mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize machine registers
        for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
            val = mu.reg_write(i, i - UC_ARM_REG_R0)
        mu.reg_write(UC_ARM_REG_SP, 0x1234)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        sp = mu.reg_read(UC_ARM_REG_SP)
        print(">>> Before emulation SP = 0x%x" %sp)
        for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
            val = mu.reg_read(i)
            print(">>> %s = 0x%x" % ("R" + str(i-UC_ARM_REG_R0),val))

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(code))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        sp = mu.reg_read(UC_ARM_REG_SP)
        print(">>> SP = 0x%x" %sp)
        val = mu.reg_read(UC_ARM_REG_PC)
        print(">>> PC = 0x%x" %val)
        for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
            val = mu.reg_read(i)
            print(">>> %s = 0x%x" % ("R" + str(i-UC_ARM_REG_R0),val))

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_thumb(THUMB_CODE_FAIL)

