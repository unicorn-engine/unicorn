#!/usr/bin/python
from capstone import *
from unicorn import *

import regress

class MipsBranchDelay(regress.RegressTest):

    def runTest(self):
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

        def disas(code, addr):
            for i in md.disasm(code, addr):
                print '0x%x: %s %-6s %s' % (i.address, str(i.bytes).encode('hex'), i.mnemonic, i.op_str)

        def hook_code(uc, addr, size, _):
            mem = str(uc.mem_read(addr, size))
            disas(mem, addr)

        CODE = 0x400000
        asm = '0000a4126a00822800000000'.decode('hex') # beq $a0, $s5, 0x4008a0; slti   $v0, $a0, 0x6a; nop

        print 'Input instructions:'
        disas(asm, CODE)
        print

        print 'Hooked instructions:'

        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.mem_map(CODE, 0x1000)
        uc.mem_write(CODE, asm)
        self.assertEqual(None, uc.emu_start(CODE, CODE + len(asm)))

if __name__ == '__main__':
    regress.main()
