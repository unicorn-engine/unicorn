import regress
from unicorn import *
from unicorn.x86_const import *

PAGE_SIZE = 0x1000

CODE = b'\xf3\xaa'  # rep stosb
BASE = 0x00000000


class TestRep(regress.RegressTest):

    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        mu.mem_map(BASE, PAGE_SIZE)
        mu.mem_write(BASE, CODE)

        mu.reg_write(UC_X86_REG_ECX, 8)
        mu.reg_write(UC_X86_REG_ESI, 0x10)
        mu.reg_write(UC_X86_REG_EDI, 0x20)

        def __hook_code(uc, addr, size, ud):
            regress.logger.debug('iterations remaining: %d', uc.reg_read(UC_X86_REG_ECX))

        mu.hook_add(UC_HOOK_CODE, __hook_code)

        mu.emu_start(BASE, len(CODE))

        self.assertEqual(0, mu.reg_read(UC_X86_REG_ECX))


if __name__ == '__main__':
    regress.main()
