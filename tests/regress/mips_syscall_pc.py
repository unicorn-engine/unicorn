#!/usr/bin/python

from unicorn import *
from unicorn.mips_const import *

import regress

def intr_hook(uc, intno, data):
    print 'interrupt=%d, v0=%d, pc=0x%08x' % (intno, uc.reg_read(UC_MIPS_REG_V0), uc.reg_read(UC_MIPS_REG_PC))

class MipsSyscall(regress.RegressTest):
    def test(self):
        addr = 0x40000
        code = '0c000000'.decode('hex') # syscall

        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        uc.mem_map(addr, 0x1000)
        uc.mem_write(addr, code)
        uc.reg_write(UC_MIPS_REG_V0, 100)
        uc.hook_add(UC_HOOK_INTR, intr_hook)

        uc.emu_start(addr, addr+len(code))
        self.assertEqual(0x40004, uc.reg_read(UC_MIPS_REG_PC))


if __name__ == '__main__':
    regress.main()
