import regress
from unicorn import *
from unicorn.x86_const import *

CODE = (
    b'\x8e\xe8'              #  mov     gs, eax
    b'\xb8\x01\x00\x00\x00'  #  mov     eax, 1
)

BASE = 0x1000


class MovGsEax(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        uc.mem_map(BASE, 0x1000)

        uc.mem_write(BASE, CODE)
        uc.reg_write(UC_X86_REG_EAX, 0xFFFFFFFF)

        with self.assertRaises(UcError) as ex_ctx:
            uc.emu_start(BASE, BASE + len(CODE))

        self.assertEqual(UC_ERR_EXCEPTION, ex_ctx.exception.errno)


if __name__ == '__main__':
    regress.main()
