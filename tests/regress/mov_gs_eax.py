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

        with self.assertRaises(UcError) as ex_ctx:
            uc.emu_start(0x1000, 0x1000 + len(code))

        self.assertEquals(ex_ctx.exception.errno, UC_ERR_EXCEPTION)

if __name__ == '__main__':
    regress.main()
