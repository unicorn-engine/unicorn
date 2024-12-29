import regress
from unicorn import *
from unicorn.x86_const import *

CODE = (
    b'\x8b\x83\xd4\x05\x00\x00'  # mov    eax, DWORD PTR [ebx+0x5d4]
    b'\x8b\x93\x80\x05\x00\x00'  # mov    edx, DWORD PTR [ebx+0x580]
)

BASE = 0x47bb000
PATT1 = b"\xaf\xaf\xaf\xaf"
PATT2 = b"\xbf\xbf\xbf\xbf"


class TestReadMem(regress.RegressTest):
    def runTest(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        uc.mem_map(BASE, 0x1000)

        uc.mem_write(BASE, CODE)
        uc.mem_write(BASE + 0x5d4, PATT1)
        uc.mem_write(BASE + 0x580, PATT2)

        uc.reg_write(UC_X86_REG_EBX, BASE)

        uc.emu_start(BASE, BASE + len(CODE))

        self.assertEqual(PATT1, uc.mem_read(BASE + 0x5d4, 4))
        self.assertEqual(PATT2, uc.mem_read(BASE + 0x580, 4))


if __name__ == '__main__':
    regress.main()
