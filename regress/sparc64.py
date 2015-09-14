#!/usr/bin/python

from unicorn import *
from unicorn.sparc_const import *

uc = Uc(UC_ARCH_SPARC, UC_MODE_64)
uc.reg_write(UC_SPARC_REG_SP, 100)
uc.reg_write(UC_SPARC_REG_FP, 100)
print 'writing sp = 100, fp = 100'
print 'sp =', uc.reg_read(UC_SPARC_REG_SP)
print 'fp =', uc.reg_read(UC_SPARC_REG_FP)
