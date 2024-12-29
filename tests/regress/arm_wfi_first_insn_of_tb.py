import regress
from unicorn import *

CODE = (
    b'\x00\x00\x8a\xe0'     #       ADD R0, R10, R0
    b'\xff\xff\xff\xea'     #       B L0
    b'\x00\x00\x8a\xe0'     #  L0:  ADD R0, R10, R0     <-- we stop here, the first instruction of the next TB
)

BASE = 0x1000


class TestARMFirstInsn(regress.RegressTest):
    def runTest(self):
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        mu.mem_map(BASE, 0x1000)
        mu.mem_write(BASE, CODE)

        mu.emu_start(BASE, BASE + len(CODE) - 4)


if __name__ == '__main__':
    regress.main()
