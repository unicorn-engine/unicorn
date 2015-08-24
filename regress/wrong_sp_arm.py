#!/usr/bin/python
# By Ryan Hileman, issue #16

from unicorn import *
from unicorn.arm_const import *
uc = Uc(UC_ARCH_ARM, UC_MODE_32)
uc.reg_write(ARM_REG_SP, 4)
print 'Writing 4 to SP'
print 'SP =', uc.reg_read(ARM_REG_SP)
