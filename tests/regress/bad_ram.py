import regress
from unicorn import *
from unicorn.x86_const import *


class BadRam(regress.RegressTest):
    def runTest(self):
        PAGE_SIZE = 0x5000
        CODE_ADDR = 0x400000
        RSP_ADDR = 0x200000

        CODE = b"\xCA\x24\x5D"  # retf 0x5d24

        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(CODE_ADDR, PAGE_SIZE)
        mu.mem_map(RSP_ADDR, PAGE_SIZE)

        mu.mem_write(CODE_ADDR, CODE)
        mu.reg_write(UC_X86_REG_RSP, RSP_ADDR)

        # make sure we bump into an exception
        with self.assertRaises(UcError) as raisedEx:
            mu.emu_start(CODE_ADDR, CODE_ADDR + PAGE_SIZE)

        # make sure it is an exception with the errno we expect
        self.assertEqual(raisedEx.exception.errno, UC_ERR_READ_UNMAPPED)


if __name__ == '__main__':
    regress.main()
