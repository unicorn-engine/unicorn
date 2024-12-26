import regress
import sys
import unittest
from capstone import *
from unicorn import *

CODE = (
    b'\x00\x00\xa4\x12'  # beq $a0, $s5, 0x4008a0
    b'\x6a\x00\x82\x28'  # slti $v0, $a0, 0x6a
    b'\x00\x00\x00\x00'  # nop
)

BASE = 0x400000


class MipsBranchDelay(regress.RegressTest):

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def runTest(self):
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

        def disas(code, addr):
            for insn in md.disasm(code, addr):
                regress.logger.debug('%#x: %-8s %s', insn.address, insn.mnemonic, insn.op_str)

        def hook_code(uc, addr, size, _):
            disas(uc.mem_read(addr, size), addr)

        regress.logger.debug('Input instructions:')
        disas(CODE, BASE)

        regress.logger.debug('Hooked instructions:')

        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.mem_map(BASE, 0x1000)
        uc.mem_write(BASE, CODE)

        self.assertEqual(None, uc.emu_start(BASE, BASE + len(CODE)))


if __name__ == '__main__':
    regress.main()
