#!/usr/bin/python

from unicorn import *
from unicorn.x86_const import *

binary1 = b'\x40\x01\xc1\x31\xf6' # inc eax; add ecx, eax; xor esi, esi

mu = Uc(UC_ARCH_X86, UC_MODE_32)

mu.mem_map(0, 2 * 1024 * 1024)

# write machine code to be emulated to memory
mu.mem_write(0, binary1)

# emu for maximum 1 instruction.
mu.emu_start(0, 10, 0, 1)

print("EAX = %u" %mu.reg_read(X86_REG_EAX))

pos = mu.reg_read(X86_REG_EIP)

print("EIP = %x" %pos)

