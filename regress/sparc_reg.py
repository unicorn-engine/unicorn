#!/usr/bin/python

from unicorn import *
from unicorn.sparc_const import *

uc = Uc(UC_ARCH_SPARC, UC_MODE_32)
uc.reg_write(UC_SPARC_REG_SP, 100)
uc.reg_write(UC_SPARC_REG_FP, 100)
uc.reg_write(UC_SPARC_REG_G0, 200)
uc.reg_write(UC_SPARC_REG_O0, 201)
uc.reg_write(UC_SPARC_REG_L0, 202)
uc.reg_write(UC_SPARC_REG_L7, 203)
uc.reg_write(UC_SPARC_REG_I0, 204)

print 'writing sp = 100, fp = 100'
print 'sp =', uc.reg_read(UC_SPARC_REG_SP)
print 'fp =', uc.reg_read(UC_SPARC_REG_FP)
print 'g0 =', uc.reg_read(UC_SPARC_REG_G0)
print 'o0 =', uc.reg_read(UC_SPARC_REG_O0)
print 'l0 =', uc.reg_read(UC_SPARC_REG_L0)
print 'l7 =', uc.reg_read(UC_SPARC_REG_L7)
print 'i0 =', uc.reg_read(UC_SPARC_REG_I0)

assert uc.reg_read(UC_SPARC_REG_SP) == 100
assert uc.reg_read(UC_SPARC_REG_FP) == 100
assert uc.reg_read(UC_SPARC_REG_G0) == 200
assert uc.reg_read(UC_SPARC_REG_O0) == 201
assert uc.reg_read(UC_SPARC_REG_L0) == 202
assert uc.reg_read(UC_SPARC_REG_L7) == 203
assert uc.reg_read(UC_SPARC_REG_I0) == 204