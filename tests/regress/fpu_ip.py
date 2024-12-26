import regress
import sys
import unittest
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

CODE = (
    b'\xc7\x04\x24\x7f\x03\x00\x00'     #  mov      DWORD PTR [rsp],0x37f
    b'\xd9\x2c\x24'                     #  fldcw    WORD PTR [rsp]
    b'\xd9\xd0'                         #  fnop
    b'\xd9\x74\x24\x08'                 #  fnstenv  [rsp+0x8]
    b'\x59'                             #  pop      rcx
)

BASE = 0x00000000
STACK = 0x00000f00


def hook_code(uc, addr, size, user_data):
    cs = user_data
    data = uc.mem_read(addr, size)
    mnem, ops = next((insn.mnemonic, insn.op_str) for insn in cs.disasm(data, addr))

    regress.logger.debug("0x%x: %-12s %-24s", addr, mnem, ops)


class FpuIP(regress.RegressTest):

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def test_32(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        cs = Cs(CS_ARCH_X86, CS_MODE_32)

        mu.mem_map(BASE, 0x1000)
        mu.mem_write(BASE, CODE)
        mu.reg_write(UC_X86_REG_ESP, STACK)
        mu.hook_add(UC_HOOK_CODE, hook_code, cs)

        mu.emu_start(BASE, BASE + len(CODE), count=5)

        self.assertSequenceEqual(b'\x7f\x03\x00\x00\x00\x00\x00\x00', mu.mem_read(STACK + 8, 8))
        self.assertSequenceEqual(b'\x55\x55\x00\x00\x00\x00\x00\x00', mu.mem_read(STACK + 16, 8))

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def test_64(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        cs = Cs(CS_ARCH_X86, CS_MODE_64)

        mu.mem_map(BASE, 0x1000)
        mu.mem_write(BASE, CODE)
        mu.reg_write(UC_X86_REG_RSP, STACK)
        mu.hook_add(UC_HOOK_CODE, hook_code, cs)

        mu.emu_start(BASE, BASE + len(CODE), count=5)

        self.assertSequenceEqual(b'\x7f\x03\x00\x00\x00\x00\x00\x00', mu.mem_read(STACK + 8, 8))
        self.assertSequenceEqual(b'\x55\x55\x00\x00\x00\x00\x00\x00', mu.mem_read(STACK + 16, 8))


if __name__ == '__main__':
    regress.main()
