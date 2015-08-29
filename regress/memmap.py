#!/usr/bin/python
# By Ryan Hileman, issue #9

# this prints out 2 lines and the contents must be the same

from unicorn import *
uc = Uc(UC_ARCH_X86, UC_MODE_64)

uc.mem_map(0x8048000, 0x2000)
uc.mem_write(0x8048000, 'test')
print 1, str(uc.mem_read(0x8048000, 4)).encode('hex')

uc.mem_map(0x804a000, 0x8000)
print 2, str(uc.mem_read(0x8048000, 4)).encode('hex')
