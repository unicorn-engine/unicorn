#!/usr/bin/env python

import unicorn
from unicorn import *

import regress

class MmapSeg(regress.RegressTest):

    def test_seg1(self):
        u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        u.mem_map(0x2000, 0x1000)
        u.mem_read(0x2000, 1)

        for i in range(50):
            u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
            u.mem_map(i*0x1000, 0x1000)
            u.mem_read(i*0x1000, 1)

        for i in range(20):
            with self.assertRaises(UcError):
                u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
                u.mem_map(i*0x1000, 5)
                u.mem_read(i*0x1000, 1)

    def test_seg2(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x0000, 0x2000)
        uc.mem_map(0x2000, 0x4000)
        uc.mem_write(0x1000, 0x1004 * ' ')
        self.assertTrue(1,
            'If not reached, then we have BUG (crash on x86_64 Linux).')

if __name__ == '__main__':
    regress.main()
