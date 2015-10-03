#!/usr/bin/python

from unicorn import *
from unicorn.mips_const import *

import regress

def code_hook(uc, addr, size, user_data):
    print 'code hook: pc=%08x sp=%08x' % (addr, uc.reg_read(UC_MIPS_REG_SP))

def run(step=False):
    addr = 0x4010dc

    code = (
        'f8ff0124' # addiu $at, $zero, -8
        '24e8a103' # and $sp, $sp, $at
        '09f82003' # jalr $t9
        'e8ffbd23' # addi $sp, $sp, -0x18
        'b8ffbd27' # addiu $sp, $sp, -0x48
        '00000000' # nop
    ).decode('hex')

    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
    if step:
        uc.hook_add(UC_HOOK_CODE, code_hook)

    uc.reg_write(UC_MIPS_REG_SP, 0x60800000)
    uc.reg_write(UC_MIPS_REG_T9, addr + len(code) - 8)

    print 'sp =', hex(uc.reg_read(UC_MIPS_REG_SP))
    print 'at =', hex(uc.reg_read(UC_MIPS_REG_AT))
    print '<run> (single step: %s)' % (str(step))

    uc.mem_map(addr & ~(0x1000 - 1), 0x2000)
    uc.mem_write(addr, code)
    uc.emu_start(addr, addr + len(code))

    print 'sp =', hex(uc.reg_read(UC_MIPS_REG_SP))
    print 'at =', hex(uc.reg_read(UC_MIPS_REG_AT))
    print
    return uc.reg_read(UC_MIPS_REG_SP)


class MipsSingleStep(regress.RegressTest):
    def test(self):
        sp1 = run(step=False)
        sp2 = run(step=True)
        self.assertEqual(sp1, sp2)

if __name__ == '__main__':
    regress.main()
