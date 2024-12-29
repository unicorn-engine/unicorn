import regress
from unicorn import *
from unicorn.x86_const import *

CODE = (
    b'\x9b\xd9\x3c\x24'     #  fstcw  WORD PTR [esp]
    b'\x59'                 #  pop    ecx
)

BASE = 0x00000000
STACK = 0x00000f00


def hook_mem_write(uc, access, address, size, value, user_data):
    regress.logger.debug("mem WRITE to: %#x, size = %u, value = %#x", address, size, value)
    return True


class FpuWrite(regress.RegressTest):

    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        mu.mem_map(BASE, 0x1000)
        mu.mem_write(BASE, CODE)
        mu.reg_write(UC_X86_REG_ESP, STACK)

        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        mu.emu_start(BASE, BASE + len(CODE), count=2)

        self.assertSequenceEqual(b'\x00' * 2, mu.mem_read(STACK, 2))


if __name__ == '__main__':
    regress.main()
