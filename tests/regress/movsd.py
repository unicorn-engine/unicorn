#!/usr/bin/python
# By Ryan Hileman, issue #3

from capstone import *
from unicorn import *
from unicorn.x86_const import *

import regress
code = 'f20f1005aa120000'.decode('hex')

def dis(mem, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return '\n'.join([
        '%s %s' % (i.mnemonic, i.op_str)
        for i in md.disasm(str(mem), addr)
    ])

def hook_code(uc, addr, size, user_data):
    mem = uc.mem_read(addr, size)
    print 'instruction size:', size
    print 'instruction:', str(mem).encode('hex'), dis(mem, addr)
    print 'reference:  ', code.encode('hex'), dis(code, addr)

class Movsd(regress.RegressTest):

    def runTest(self):
        addr = 0x400000
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.mem_map(addr, 8 * 1024 * 1024)
        mu.mem_write(addr, code)
        mu.emu_start(addr, addr + len(code))

if __name__ == '__main__':
    regress.main()
