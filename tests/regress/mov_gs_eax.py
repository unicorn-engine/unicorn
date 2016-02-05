#!/usr/bin/python

from unicorn import *
from unicorn.x86_const import *

import regress

class VldrPcInsn(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x1000, 0x1000)
        # mov gs, eax; mov eax, 1
        code = '8ee8b801000000'.decode('hex')
        uc.mem_write(0x1000, code)

        uc.reg_write(UC_X86_REG_EAX, 0xFFFFFFFF)
        # this should throw an error
        # the eax test is just to prove the second instruction doesn't execute
        try:
            uc.emu_start(0x1000, len(code))
        except UcError:
            return
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 1)

if __name__ == '__main__':
    regress.main()
