#!/usr/bin/python

from unicorn import *
from unicorn.x86_const import *

import regress

CODE_ADDR = 0x0
binary1 = b'\xb8\x02\x00\x00\x00'
binary2 = b'\xb8\x01\x00\x00\x00'

class CrashTB(regress.RegressTest):

    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(CODE_ADDR, binary1)

        # emu for maximum 1 sec.
        mu.emu_start(CODE_ADDR, len(binary1), UC_SECOND_SCALE)

        self.assertEqual(0x2, mu.reg_read(UC_X86_REG_RAX))

        # write machine code to be emulated to memory
        mu.mem_write(CODE_ADDR, binary2)

        # emu for maximum 1 sec.
        mu.emu_start(CODE_ADDR, len(binary2), UC_SECOND_SCALE)

        self.assertEqual(0x1, mu.reg_read(UC_X86_REG_RAX))

if __name__ == '__main__':
    regress.main()

