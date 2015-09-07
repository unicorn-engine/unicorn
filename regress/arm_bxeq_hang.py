#!/usr/bin/python

from unicorn import *
from unicorn.arm_const import *

uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
uc.mem_map(0x1000, 0x1000)
uc.mem_write(0x1000, '1eff2f010000a0e1'.decode('hex'))
def hook_block(uc, addr, *args):
    print 'enter block 0x%04x' % addr

uc.reg_write(UC_ARM_REG_LR, 0x1004)
uc.hook_add(UC_HOOK_BLOCK, hook_block)
print 'block should only run once'
uc.emu_start(0x1000, 0x1004, timeout=250)
