#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.m68k_const import *


# code to be emulated
M68K_CODE  = b"\x76\xed" # movq #-19, %d3
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test ARM
def test_m68k():
    print("Emulate M68K code")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, M68K_CODE)

        # initialize machine registers
        mu.reg_write(UC_M68K_REG_D3, 0x1234)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(M68K_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        a0 = mu.reg_read(UC_M68K_REG_A0)
        a1 = mu.reg_read(UC_M68K_REG_A1)
        a2 = mu.reg_read(UC_M68K_REG_A2)
        a3 = mu.reg_read(UC_M68K_REG_A3)
        a4 = mu.reg_read(UC_M68K_REG_A4)
        a5 = mu.reg_read(UC_M68K_REG_A5)
        a6 = mu.reg_read(UC_M68K_REG_A6)
        a7 = mu.reg_read(UC_M68K_REG_A7)
        d0 = mu.reg_read(UC_M68K_REG_D0)
        d1 = mu.reg_read(UC_M68K_REG_D1)
        d2 = mu.reg_read(UC_M68K_REG_D2)
        d3 = mu.reg_read(UC_M68K_REG_D3)
        d4 = mu.reg_read(UC_M68K_REG_D4)
        d5 = mu.reg_read(UC_M68K_REG_D5)
        d6 = mu.reg_read(UC_M68K_REG_D6)
        d7 = mu.reg_read(UC_M68K_REG_D7)
        pc = mu.reg_read(UC_M68K_REG_PC)
        sr = mu.reg_read(UC_M68K_REG_SR)
        print(">>> A0 = 0x%x\t\t>>> D0 = 0x%x" % (a0, d0))
        print(">>> A1 = 0x%x\t\t>>> D1 = 0x%x" % (a1, d1))
        print(">>> A2 = 0x%x\t\t>>> D2 = 0x%x" % (a2, d2))
        print(">>> A3 = 0x%x\t\t>>> D3 = 0x%x" % (a3, d3))
        print(">>> A4 = 0x%x\t\t>>> D4 = 0x%x" % (a4, d4))
        print(">>> A5 = 0x%x\t\t>>> D5 = 0x%x" % (a5, d5))
        print(">>> A6 = 0x%x\t\t>>> D6 = 0x%x" % (a6, d6))
        print(">>> A7 = 0x%x\t\t>>> D7 = 0x%x" % (a7, d7))
        print(">>> PC = 0x%x" % pc)
        print(">>> SR = 0x%x" % sr)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_m68k()
