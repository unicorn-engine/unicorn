#!/usr/bin/python
from unicorn import *
from unicorn.x86_const import *
import regress

PAGE_SIZE = 4 * 1024

CODE = b'\xf3\xaa'  # rep stosb


def hook_code(uc, addr, size, user_data):
    print("hook called at %x" %addr)

class REP(regress.RegressTest):

    def test_rep(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        mu.mem_map(0, PAGE_SIZE)
        mu.mem_write(0, CODE)
        mu.reg_write(UC_X86_REG_ECX, 3)
        mu.reg_write(UC_X86_REG_EDI, 0x100)
        mu.hook_add(UC_HOOK_CODE, hook_code)

        mu.emu_start(0, len(CODE))
        self.assertEqual(0, mu.reg_read(UC_X86_REG_ECX))


if __name__ == '__main__':
    regress.main()
