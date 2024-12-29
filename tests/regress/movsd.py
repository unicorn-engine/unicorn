# By Ryan Hileman, issue #3

import regress
import sys
import unittest
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import *

CODE = b'\xf2\x0f\x10\x05\xaa\x12\x00\x00'


def dis(md, mem, addr):
    return '\n'.join(('%-16s %s' % (insn.mnemonic, insn.op_str) for insn in md.disasm(mem, addr)))


def hook_code(uc, addr, size, md):
    mem = uc.mem_read(addr, size)

    regress.logger.debug('instruction size: %d', size)
    regress.logger.debug('instruction: %s %s', mem, dis(md, mem, addr))
    regress.logger.debug('reference:  %s %s', CODE, dis(md, CODE, addr))


class Movsd(regress.RegressTest):

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def runTest(self):
        addr = 0x400000
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        mu.hook_add(UC_HOOK_CODE, hook_code, md)
        mu.mem_map(addr, 8 * 1024 * 1024)
        mu.mem_write(addr, CODE)
        mu.emu_start(addr, addr + len(CODE))


if __name__ == '__main__':
    regress.main()
