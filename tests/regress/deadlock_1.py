#!/usr/bin/python
# From issue #1 of Ryan Hileman

from unicorn import *
import regress

CODE = b"\x90\x91\x92"

class DeadLock(regress.RegressTest):

    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x100000, 4 * 1024)
        mu.mem_write(0x100000, CODE)

        with self.assertRaises(UcError):
            mu.emu_start(0x100000, 0x1000 + len(CODE))

if __name__ == '__main__':
    regress.main()
