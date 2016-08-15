#!/usr/bin/python
import regress
import unicorn as U

class WrongEFLAGS2(regress.RegressTest):
    def test_eflags(self):
        # imul eax, ebx
        CODE = '\x0f\xaf\xc3'

        uc = U.Uc(U.UC_ARCH_X86, U.UC_MODE_32)
        uc.reg_write(U.x86_const.UC_X86_REG_EAX, 16)
        uc.reg_write(U.x86_const.UC_X86_REG_EBX, 1)
        uc.reg_write(U.x86_const.UC_X86_REG_EFLAGS, 0x292)

        uc.mem_map(0x600000, 0x1000)
        uc.mem_write(0x6000b0, CODE)
        uc.emu_start(0x6000b0, 0, count=1)


        # Here's the original execution trace for this on actual hardware.
        #
        # (gdb) x/i $eip
        # => 0x804aae5:   imul   eax,DWORD PTR [ebp-0x8]
        # (gdb) p/x $eax
        # $2 = 0x10
        # (gdb) x/wx $ebp-8
        # 0xbaaaad4c:     0x00000001
        # (gdb) p/x $eflags
        # $3 = 0x292
        # (gdb) si
        # 0x0804aae9 in ?? ()
        # (gdb) p/x $eflags
        # $4 = 0x202

        self.assertEqual(0x202, uc.reg_read(U.x86_const.UC_X86_REG_EFLAGS))

if __name__ == '__main__':
    regress.main()
