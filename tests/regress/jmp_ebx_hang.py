""" See https://github.com/unicorn-engine/unicorn/issues/82 """

import regress
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x10101000
CODE = b'\xff\xe3'  # jmp ebx


class JumEbxHang(regress.RegressTest):
    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        mu.mem_map(CODE_ADDR, 1024 * 4)
        mu.mem_write(CODE_ADDR, CODE)
        # If EBX is zero then an exception is raised, as expected
        mu.reg_write(UC_X86_REG_EBX, 0x0)

        regress.logger.debug(">>> jmp ebx (ebx = 0)")
        with self.assertRaises(UcError) as m:
            mu.emu_start(CODE_ADDR, CODE_ADDR + 2, count=1)

        self.assertEqual(m.exception.errno, UC_ERR_FETCH_UNMAPPED)

        regress.logger.debug(">>> jmp ebx (ebx = 0xaa96a47f)")
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(CODE_ADDR, 1024 * 4)
        # If we write this address to EBX then the emulator hangs on emu_start
        mu.reg_write(UC_X86_REG_EBX, 0xaa96a47f)
        mu.mem_write(CODE_ADDR, CODE)

        with self.assertRaises(UcError) as m:
            mu.emu_start(CODE_ADDR, CODE_ADDR + 2, count=1)

        self.assertEqual(m.exception.errno, UC_ERR_FETCH_UNMAPPED)


if __name__ == '__main__':
    regress.main()
