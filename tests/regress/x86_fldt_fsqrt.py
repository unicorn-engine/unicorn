#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
from struct import pack

import regress

CODE_ADDR = 0x1000000
CODE = (
    '\xb8\x00\x00\x00\x02' # mov eax, 0x2000000
    '\xdb\x28'             # fldt [eax]
    '\xd9\xfa'             # fsqrt
)

DATA_ADDR = 0x2000000
DATA = '\0\0\0\0\0\0\0\0\0\1'

class FldtFsqrt(regress.RegressTest):
    def test_fldt_fsqrt(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        uc.mem_map(CODE_ADDR, 0x1000)
        uc.mem_write(CODE_ADDR, CODE)

        uc.mem_map(DATA_ADDR, 0x1000)
        uc.mem_write(DATA_ADDR, DATA)

        uc.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), 10000, 10)

if __name__ == '__main__':
    regress.main()
