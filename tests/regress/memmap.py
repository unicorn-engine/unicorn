# By Ryan Hileman, issue #9

# this prints out 2 lines and the contents must be the same

import regress
from unicorn import *


class MemMap(regress.RegressTest):

    def test_mmap_write(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        uc.mem_map(0x8048000, 0x2000)
        uc.mem_write(0x8048000, b'test')
        s1 = uc.mem_read(0x8048000, 4)

        self.assertEqual(b'test', s1)

        uc.mem_map(0x804a000, 0x8000)
        s2 = uc.mem_read(0x8048000, 4)

        self.assertEqual(s1, s2)

    def test_mmap_invalid(self):
        u = Uc(UC_ARCH_X86, UC_MODE_32)

        with self.assertRaises(UcError):
            u.mem_map(0x2000, 0)

        with self.assertRaises(UcError):
            u.mem_map(0x4000, 1)

    def test_mmap_weird(self):
        u = Uc(UC_ARCH_X86, UC_MODE_32)

        for i in range(20):
            with self.assertRaises(UcError):
                u.mem_map(i * 0x1000, 5)
                u.mem_read(i * 0x1000 + 6, 1)


if __name__ == '__main__':
    regress.main()
