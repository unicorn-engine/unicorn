#!/usr/bin/python
from capstone import *
from unicorn import *
from unicorn.mips_const import *

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

def disas(code, addr):
    for i in md.disasm(code, addr):
        print '0x%x: %s %s' % (i.address, str(i.bytes).encode('hex'), i.op_str)

def hook_code(uc, addr, size, _):
    mem = str(uc.mem_read(addr, size))
    disas(mem, addr)

CODE = 0x400000
asm = '0000a4126a00822800000000'.decode('hex')

print 'Input instructions:'
disas(asm, CODE)
print

print 'Hooked instructions:'

uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
uc.hook_add(UC_HOOK_CODE, hook_code)
uc.mem_map(CODE, 0x1000)
uc.mem_write(CODE, asm)
uc.emu_start(CODE, CODE + len(asm))
