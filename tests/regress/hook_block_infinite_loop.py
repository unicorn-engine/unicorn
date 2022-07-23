#!/usr/bin/python

'''https://github.com/unicorn-engine/unicorn/issues/1661'''

from __future__ import print_function
import regress

from unicorn import *
from unicorn.arm64_const import *

# MOV x0, #1234
# MOV x1, #2345
# MOV x2, #4331
# LDR x9, =0x2000
# BLR x9
# MOV x8, x2
code_1 = '409A80D2212581D2621D82D2090084D220013FD6E80302AA'
addr_1 = 0x1000

# MOV x2, #9999
# RET
code_2 = 'E2E184D2C0035FD6'
addr_2 = 0x2000


def hook_code(uc_, address, size, user_data):
    print('Called hook_code')
    pass


def hook_block(uc_, address, size, user_data):
    print('Called hook_block')
    uc_.reg_write(UC_ARM64_REG_X2, 1337)
    uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))


class HookBlockInfiniteLoop(regress.RegressTest):
    def runTest(self):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(addr_1, 0x1000)
        uc.mem_map(addr_2, 0x2000)
        uc.mem_write(addr_1, bytes.fromhex(code_1))
        uc.mem_write(addr_2, bytes.fromhex(code_2))
        # Uncommenting line below would also fix it on Unicorn 2.0.0
        # uc.hook_del(uc.hook_add(UC_HOOK_CODE, hook_code))
        uc.hook_add(UC_HOOK_BLOCK, hook_block, user_data=None, begin=addr_2, end=addr_2 + 4)
        uc.emu_start(addr_1, until=addr_1 + len(code_1) // 2)

        print('x2 = 1337 (EXPECTED)')
        print('x2 = %d (ACTUAL)' % uc.reg_read(UC_ARM64_REG_X2))

        self.assertEqual(1337, uc.reg_read(UC_ARM64_REG_X2), "Unexpected X2")


if __name__ == '__main__':
    regress.main()
