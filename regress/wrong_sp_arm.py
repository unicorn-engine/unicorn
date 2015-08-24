#!/usr/bin/python
# By Ryan Hileman, issue #16

from unicorn import *
from unicorn.arm_const import *

try:
    uc = Uc(UC_ARCH_ARM, UC_MODE_32)
    uc.reg_write(ARM_REG_SP, 4)
    print 'Writing 4 to SP'
    print 'SP =', uc.reg_read(ARM_REG_SP)
except UcError as e:
    print("ERROR: %s" % e)

try:
    print "==========="
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.reg_write(ARM_REG_SP, 4)
    print 'Writing 4 to SP'
    print 'SP =', uc.reg_read(ARM_REG_SP)
except UcError as e:
    print("ERROR: %s" % e)
