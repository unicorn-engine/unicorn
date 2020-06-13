#!/usr/bin/env python
# Sample code for MIPS of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.ppc_const import *
from keystone import *
import struct
import sys

ks = Ks(KS_ARCH_PPC,KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)

def asm(instruction):
    code = ks.asm(instruction)[0]
    if sys.version_info[0] >= 3:
        return bytes(code)
    else:
        return str(bytearray(code))


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

# callback for cpu interruption
def hook_intr(uc, intno, user_data):
    print("INTR : %d" % intno)

# code to be emulated
PPC_CODE_EB  = asm("lwz %r1,0(%r1)")
# memory address where emulation starts
ADDRESS      = 0x10000
DATA = 0x800000


def main():
    # Initialize emulator in POWERPC
    mu = Uc(UC_ARCH_PPC, UC_MODE_BIG_ENDIAN | UC_MODE_32)
    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    # tracing all basic blocks with customized callback
    mu.hook_add(UC_HOOK_BLOCK, hook_block)
    # tracing all instructions with customized callback
    mu.hook_add(UC_HOOK_CODE, hook_code)
    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, PPC_CODE_EB)

    mu.mem_map(DATA,4096)
    mu.mem_write(DATA,struct.pack(">I",4))

    mu.reg_write(UC_PPC_REG_GPR_1,DATA)

    # mu.hook_add(UC_HOOK_INTR,hook_intr)

    try:
        mu.emu_start(ADDRESS, ADDRESS + len(PPC_CODE_EB))
    except UcError as e:
        print("ERROR: %s" % e)

    print("GPR1:%08.8x" % mu.reg_read(UC_PPC_REG_GPR_1))

if __name__=='__main__':
    main()
