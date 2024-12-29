# By Ryan Hileman, issue #91

import regress
from unicorn import *
from unicorn.x86_const import *


class Pshufb(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.ctl_set_cpu_model(UC_CPU_X86_HASWELL)

        uc.mem_map(0x2000, 0x1000)

        uc.mem_write(0x2000, b'\x66\x0f\x38\x00\xc1')  # pshufb xmm0, xmm1

        # Invalid instruction -> test failed
        uc.emu_start(0x2000, 0x2005)


if __name__ == '__main__':
    regress.main()
