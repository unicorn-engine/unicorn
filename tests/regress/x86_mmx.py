"""MMX register access must address physical x87 storage, independent of TOP."""
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_MODE_32, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_MM0, UC_X86_REG_FP0, UC_X86_REG_FPSW

import regress


class X86MMX(regress.RegressTest):
    MODES = (UC_MODE_16, UC_MODE_32, UC_MODE_64)
    VALUES = (0, 1, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000,
              0x0123456789ABCDEF, 0xFEDCBA9876543210,
              0xAAAAAAAAAAAAAAAA, 0x5555555555555555)

    def test_register_access(self):
        for mode in self.MODES:
            for top in (0, 3, 7):
                with self.subTest(mode=mode, top=top):
                    uc = Uc(UC_ARCH_X86, mode)
                    uc.reg_write(UC_X86_REG_FPSW, top << 11)
                    for i in range(8):
                        uc.reg_write(UC_X86_REG_FP0 + i, (0xBAD, 0x3FFF))
                    for i, value in enumerate(self.VALUES):
                        uc.reg_write(UC_X86_REG_MM0 + i, value)
                        self.assertEqual(uc.reg_read(UC_X86_REG_MM0 + i), value)
                        self.assertEqual(uc.reg_read(UC_X86_REG_FP0 + i),
                                         (value, 0x3FFF))
                    self.assertEqual(uc.reg_read(UC_X86_REG_FPSW) >> 11 & 7, top)
                    uc.reg_write_batch([(UC_X86_REG_MM0 + i, value)
                                        for i, value in enumerate(reversed(self.VALUES))])
                    self.assertEqual(tuple(uc.reg_read_batch(range(UC_X86_REG_MM0,
                                                                 UC_X86_REG_MM0 + 8))),
                                     tuple(reversed(self.VALUES)))
                    ctx = uc.context_save()
                    for i, value in enumerate(self.VALUES):
                        self.assertEqual(ctx.reg_read(UC_X86_REG_MM0 + i),
                                         self.VALUES[7 - i])
                        ctx.reg_write(UC_X86_REG_MM0 + i, value)
                    uc.context_restore(ctx)
                    for i, value in enumerate(self.VALUES):
                        self.assertEqual(uc.reg_read(UC_X86_REG_MM0 + i), value)

    def test_instruction_access(self):
        for mode in self.MODES:
            for i in range(8):
                with self.subTest(mode=mode, register=i):
                    uc = Uc(UC_ARCH_X86, mode)
                    uc.mem_map(0x1000, 0x1000)
                    # paddb mmN, mmN: double each packed byte.
                    code = bytes((0x0F, 0xFC, 0xC0 | (i << 3) | i))
                    uc.mem_write(0x1000, code)
                    uc.reg_write(UC_X86_REG_MM0 + i, 0x0102030405060708)
                    uc.emu_start(0x1000, 0x1000 + len(code))
                    self.assertEqual(uc.reg_read(UC_X86_REG_MM0 + i),
                                     0x020406080A0C0E10)


if __name__ == '__main__':
    regress.main()
