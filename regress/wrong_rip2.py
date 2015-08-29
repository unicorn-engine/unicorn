#!/usr/bin/python

from unicorn import *
from unicorn.x86_const import *

binary1 = b'\xb8\x02\x00\x00\x00'    # mov eax, 2
binary2 = b'\xb8\x01\x00\x00\x00'    # mov eax, 1

mu = Uc(UC_ARCH_X86, UC_MODE_64)

mu.mem_map(0, 2 * 1024 * 1024)

# write machine code to be emulated to memory
mu.mem_write(0, binary1 + binary2)

# emu for maximum 1 instruction.
mu.emu_start(0, 10, 0, 1)

print("RAX = %u" %mu.reg_read(UC_X86_REG_RAX))

pos = mu.reg_read(UC_X86_REG_RIP)

print("RIP = %x" %pos)

mu.emu_start(5, 10, 0, 1)

pos = mu.reg_read(UC_X86_REG_RIP)

print("RIP = %x" %pos)

print("RAX = %u" %mu.reg_read(UC_X86_REG_RAX))

