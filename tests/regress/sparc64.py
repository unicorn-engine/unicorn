#!/usr/bin/python

import regress

from unicorn import *
from unicorn.sparc_const import *


PAGE_SIZE = 1 * 1024 * 1024

uc = Uc(UC_ARCH_SPARC, UC_MODE_SPARC64|UC_MODE_BIG_ENDIAN)

regress.logger.info('writing sp = 100')
uc.reg_write(UC_SPARC_REG_SP, 100)

CODE = (
    b"\xb0\x06\x20\x01"         # 0: b0 06 20 01     inc  %i0
    b"\xb2\x06\x60\x01"         # 4: b2 06 60 01     inc  %i1
)

uc.mem_map(0, PAGE_SIZE)
uc.mem_write(0, CODE)
uc.emu_start(0, len(CODE), 0, 2)

regress.logger.info('sp = 0x%x', uc.reg_read(UC_SPARC_REG_SP))
regress.logger.info('i0 = 0x%x', uc.reg_read(UC_SPARC_REG_I0))
regress.logger.info('i1 = 0x%x', uc.reg_read(UC_SPARC_REG_I1))
