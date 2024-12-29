import regress
from unicorn import *

CODE = (
    b'\xb8\x00\x00\x00\x02'  #  mov eax, 0x2000000
    b'\xdb\x28'              #  fldt [eax]
    b'\xd9\xfa'              #  fsqrt
)

BASE = 0x1000000

DATA_ADDR = 0x2000000
DATA = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


class FldtFsqrt(regress.RegressTest):
    def test_fldt_fsqrt(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        uc.mem_map(BASE, 0x1000)
        uc.mem_write(BASE, CODE)

        uc.mem_map(DATA_ADDR, 0x1000)
        uc.mem_write(DATA_ADDR, DATA)

        uc.emu_start(BASE, BASE + len(CODE), 10000, 10)


if __name__ == '__main__':
    regress.main()
