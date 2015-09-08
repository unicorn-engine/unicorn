#!/usr/bin/python

from unicorn import *
from unicorn.arm64_const import *

try:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.reg_write(UC_ARM64_REG_SP, 4)
    print 'Writing 4 to SP'
    print 'SP =', uc.reg_read(UC_ARM64_REG_SP)
except UcError as e:
    print("ERROR: %s" % e)
