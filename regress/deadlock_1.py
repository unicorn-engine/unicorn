#!/usr/bin/python
# From issue #1 of Ryan Hileman

from unicorn import *

CODE = b"\x90\x91\x92"

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x100000, 4 * 1024)
mu.mem_write(0x100000, CODE)
mu.emu_start(0x100000, 0x1000 + len(CODE))
