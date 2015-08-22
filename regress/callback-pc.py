#!/usr/bin/env python

# reg_write() can't modify PC from within trace callbacks

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *

BASE_ADDRESS = 0x10000000

# sub sp, #0xc
THUMB_CODE = "\x83\xb0" * 5 

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u" % (address, size))
    mu = user_data
    print(">>> Setting PC to 0xffffffff")
    mu.reg_write(ARM_REG_PC, 0xffffffff)

# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))
    mu = user_data
    print(">>> Setting PC to 0xffffffff")
    mu.reg_write(ARM_REG_PC, 0xffffffff)

# set up emulation
def instruction_trace_test():
    try:
        # initialize emulator in ARM's Thumb mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # map some memory
        mu.mem_map(BASE_ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(BASE_ADDRESS, THUMB_CODE)

        # setup stack
        mu.reg_write(ARM_REG_SP, BASE_ADDRESS + 2 * 1024 * 1024)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, user_data=mu)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block, user_data=mu)

        # emulate machine code in infinite time
        mu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(THUMB_CODE))

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == '__main__':
    instruction_trace_test()
