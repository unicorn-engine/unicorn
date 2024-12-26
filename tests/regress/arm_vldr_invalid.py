import regress
from unicorn import *


class VldrPcInsn(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, b'\xed\x9f\x8a\x3d')  # vldr s16, [pc, #244]

        with self.assertRaises(UcError) as ex:
            uc.emu_start(0x1000, 0x1004)

        self.assertEqual(UC_ERR_INSN_INVALID, ex.exception.errno)


if __name__ == '__main__':
    regress.main()
