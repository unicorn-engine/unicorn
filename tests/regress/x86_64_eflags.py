#!/usr/bin/python
import regress
import unicorn as U

class WrongEFLAGS(regress.RegressTest):
    def test_eflags(self):
        # xor r14,r14
        CODE = 'M1\xf6'

        uc = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
        uc.reg_write(U.x86_const.UC_X86_REG_RIP, 0x6000b0)
        uc.reg_write(U.x86_const.UC_X86_REG_EFLAGS, 0x200)

        uc.mem_map(0x600000, 0x1000)
        uc.mem_write(0x6000b0, CODE)
        uc.emu_start(0x6000b0, 0, count=1)


        # Here's the original execution trace for this on actual hardware.
        #
        # (gdb) x/i $pc
        # => 0x6000b0:    xor    %r14,%r14
        # (gdb) p/x $eflags
        # $1 = 0x200
        # (gdb) p $eflags
        # $2 = [ IF ]
        # (gdb) si
        # 0x00000000006000b3 in ?? ()
        # (gdb) p/x $eflags
        # $3 = 0x246
        # (gdb) p $eflags
        # $4 = [ PF ZF IF ]

        self.assertEqual(0x6000b3, uc.reg_read(U.x86_const.UC_X86_REG_RIP))
        self.assertEqual(0x246, uc.reg_read(U.x86_const.UC_X86_REG_EFLAGS))

if __name__ == '__main__':
    regress.main()
