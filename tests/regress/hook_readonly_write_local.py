import regress
from unicorn import *
from unicorn.x86_const import *

PAGE_SIZE = 0x1000
ACCESS_ADDR = 0x1000

CODE = (
    b'\xA1\x00\x10\x00\x00'  # mov eax, [0x1000]
    b'\xA1\x00\x10\x00\x00'  # mov eax, [0x1000]
)

BASE = 0x00000000


def hook_mem_read(uc, access, address, size, value, data):
    regress.logger.debug("Reading at %#x", address)
    # BUG: unicorn will segfault when calling "uc.mem_write" to write to a location that was mapped only as UC_PROT_READ
    uc.mem_write(address, CODE)


class REP(regress.RegressTest):
    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        mu.mem_map(BASE, PAGE_SIZE)
        mu.mem_write(BASE, CODE)
        mu.mem_map(ACCESS_ADDR, PAGE_SIZE, UC_PROT_READ)
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, begin=ACCESS_ADDR, end=ACCESS_ADDR + PAGE_SIZE)

        mu.emu_start(BASE, BASE + len(CODE))

        self.assertEqual(0x001000a1, mu.reg_read(UC_X86_REG_EAX))


if __name__ == '__main__':
    regress.main()
