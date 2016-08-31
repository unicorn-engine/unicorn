#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
from struct import pack

import os
import regress

# The file we're loading is a full assembled ELF.
# Source for it, along with assembly instructions, are in x86_self_modifying.s

CODE_ADDR = 0x08048000
STACK_ADDR = 0x2000000
CODE = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'x86_self_modifying.elf')).read()
CODE_SIZE = len(CODE) + (0x1000 - len(CODE)%0x1000)
STACK_SIZE = 0x8000

ENTRY_POINT = 0x8048074

def hook_intr(uc, intno, data):
    uc.emu_stop()

class SelfModifying(regress.RegressTest):
    def test_self_modifying(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        uc.mem_map(CODE_ADDR, CODE_SIZE, 5)
        uc.mem_map(STACK_ADDR, STACK_SIZE, 7)
        uc.mem_write(CODE_ADDR, CODE)
        uc.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE)

        uc.hook_add(UC_HOOK_INTR, hook_intr)

        uc.emu_start(ENTRY_POINT, -1)

        retcode = uc.reg_read(UC_X86_REG_EBX)
        self.assertEqual(retcode, 65)

if __name__ == '__main__':
    regress.main()
