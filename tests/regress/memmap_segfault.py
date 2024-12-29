import regress
from unicorn import *


class MmapSeg1(regress.RegressTest):
    def runTest(self):
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        u.mem_map(0x2000, 0x1000)
        u.mem_read(0x2000, 1)

        for i in range(50):
            u = Uc(UC_ARCH_X86, UC_MODE_32)
            u.mem_map(i * 0x1000, 0x1000)
            u.mem_read(i * 0x1000, 1)

        for i in range(20):
            with self.assertRaises(UcError):
                u = Uc(UC_ARCH_X86, UC_MODE_32)
                u.mem_map(i * 0x1000, 5)
                u.mem_read(i * 0x1000, 1)


class MmapSeg2(regress.RegressTest):
    def runTest(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x0000, 0x2000)
        uc.mem_map(0x2000, 0x4000)
        uc.mem_write(0x1000, b' ' * 0x1004)


if __name__ == '__main__':
    regress.main()
