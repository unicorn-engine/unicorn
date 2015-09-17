#!/usr/bin/python
# By Ryan Hileman, issue #91

# Invalid instruction = test failed

from unicorn import *
from unicorn.x86_const import *

import regress

class Pshufb(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0x2000, 0x1000)
        # pshufb xmm0, xmm1
        uc.mem_write(0x2000, '660f3800c1'.decode('hex'))
        uc.emu_start(0x2000, 0x2005)

if __name__ == '__main__':
    regress.main()
