#!/usr/bin/python

from unicorn import *
uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(0x0000, 0x2000)
uc.mem_map(0x2000, 0x4000)
uc.mem_write(0x1000, 0x1004 * ' ')
print 'Not reached on x86_64 Linux.'
