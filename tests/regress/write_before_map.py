import regress
from unicorn import *
from unicorn.x86_const import *

X86_CODE64 = b"\x90"  # NOP


class WriteBeforeMap(regress.RegressTest):
    def runTest(self):
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # memory address where emulation starts
        ADDRESS = 0x1000000

        # write machine code to be emulated to memory
        with self.assertRaises(UcError) as raisedEx:
            mu.mem_write(ADDRESS, X86_CODE64)

        self.assertEqual(UC_ERR_WRITE_UNMAPPED, raisedEx.exception.errno)


if __name__ == '__main__':
    regress.main()
