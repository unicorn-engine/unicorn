#!/usr/bin/python
from unicorn import *
from unicorn.mips_const import *

def hook_intr(uc, intno, _):
    print 'interrupt', intno

CODE = 0x400000
asm = '0000a48f'.decode('hex')

uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
uc.hook_add(UC_HOOK_INTR, hook_intr)
uc.mem_map(CODE, 0x1000)
uc.mem_write(CODE, asm)

print 'unaligned access (exc 12)'
uc.reg_write(UC_MIPS_REG_SP, 0x01)
uc.emu_start(CODE, CODE + len(asm), 300)
print

print 'dunno (exc 26)'
uc.reg_write(UC_MIPS_REG_SP, 0xFFFFFFF0)
uc.emu_start(CODE, CODE + len(asm), 200)
print

print 'unassigned access (exc 28)'
uc.reg_write(UC_MIPS_REG_SP, 0x80000000)
uc.emu_start(CODE, CODE + len(asm), 100)
print
