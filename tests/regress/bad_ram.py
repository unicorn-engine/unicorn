#!/usr/bin/python

from unicorn import *
from unicorn.x86_const import *

import regress


class Hang(regress.RegressTest):

    def runTest(self):
        CODE_ADDR = 0x400000
        RSP_ADDR =  0x200000
        binary1 = "\xCA\x24\x5D" # retf 0x5d24
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(CODE_ADDR, 0x5000)
        mu.mem_map(RSP_ADDR, 0x5000)

        # write machine code to be emulated to memory
        mu.mem_write(CODE_ADDR, binary1)

        mu.reg_write(UC_X86_REG_RSP, RSP_ADDR)

        # emu for maximum 1 sec.
        mu.emu_start(CODE_ADDR, 0x400000 + 0x5000, 0)


if __name__ == '__main__':
    regress.main()
