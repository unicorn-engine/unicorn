import regress
from unicorn import *
from unicorn.arm64_const import *


class Arm64RegReadWriteW0ThroughW30(regress.RegressTest):
    """
    Testing the functionality to read/write 32-bit registers in AArch64
    See issue #716 
    """

    def runTest(self):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        expected = 0x1234567890abcdef

        uc.reg_write(UC_ARM64_REG_X0, expected)
        self.assertEqual(uc.reg_read(UC_ARM64_REG_X0), expected)
        self.assertEqual(uc.reg_read(UC_ARM64_REG_W0), expected & 0xffffffff)

        # ----------------------------------------------------------

        expected = 0xa1b2c3d4e5f6a7b8

        uc.reg_write(UC_ARM64_REG_X30, expected)
        self.assertEqual(uc.reg_read(UC_ARM64_REG_W30), expected & 0xffffffff)

        expected_lo = 0xaabbccdd

        uc.reg_write(UC_ARM64_REG_W30, expected_lo)
        self.assertEqual(uc.reg_read(UC_ARM64_REG_X30), (expected & ~0xffffffff) | expected_lo)
        self.assertEqual(uc.reg_read(UC_ARM64_REG_W30), expected_lo)


if __name__ == '__main__':
    regress.main()
