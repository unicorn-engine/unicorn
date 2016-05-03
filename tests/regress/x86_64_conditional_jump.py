#!/usr/bin/python
import regress
import unicorn as U

class WrongConditionalPath(regress.RegressTest):
    def test_eflags(self):
        # 0:    4d 31 f6                 xor    r14, r14
        # 3:    45 85 f6                 test   r14d, r14d
        # 6:    75 fe                    jne    0x6
        # 8:    f4                       hlt
        CODE = 'M1\xf6E\x85\xf6u\xfe\xf4'

        uc = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
        uc.reg_write(U.x86_const.UC_X86_REG_RIP, 0x6000b0)
        uc.reg_write(U.x86_const.UC_X86_REG_EFLAGS, 0x246)

        uc.mem_map(0x600000, 0x1000)
        uc.mem_write(0x6000b0, CODE)

        uc.emu_start(0x6000b0 + 6, 0, count=1)

        # Here's the original execution trace for this on qemu-user.
        #
        # $ SC='xor r14,r14; test r14d, r14d; jne $; hlt'
        # $ asm --context amd64 --format elf $SC > example
        # $ qemu-x86_64-static -d cpu,in_asm -singlestep ./test \
        #   | grep -E 'RFL|^0x'
        # 0x00000000006000b0:  xor    %r14,%r14
        # RIP=00000000006000b0 RFL=00000202 [-------] CPL=3 II=0 A20=1 SMM=0 HLT=0
        # 0x00000000006000b3:  test   %r14d,%r14d
        # RIP=00000000006000b3 RFL=00000246 [---Z-P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
        # 0x00000000006000b6:  jne    0x6000b6
        # RIP=00000000006000b6 RFL=00000246 [---Z-P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
        # 0x00000000006000b8:  hlt    
        # RIP=00000000006000b8 RFL=00000246 [---Z-P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
        self.assertEqual(0x6000b0 + 8, uc.reg_read(U.x86_const.UC_X86_REG_RIP))

if __name__ == '__main__':
    regress.main()
