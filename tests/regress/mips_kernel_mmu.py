#!/usr/bin/python

from unicorn import *
from unicorn.mips_const import *

import regress

class MipsSyscall(regress.RegressTest):
    def test(self):
        addr = 0x80000000
        code = '34213456'.decode('hex') # ori $at, $at, 0x3456

        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
        uc.mem_map(addr, 0x1000)
        uc.mem_write(addr, code)
        uc.reg_write(UC_MIPS_REG_AT, 0)

        uc.emu_start(addr, addr + len(code))

        self.assertEqual(uc.reg_read(UC_MIPS_REG_AT), 0x3456)


if __name__ == '__main__':
    regress.main()
