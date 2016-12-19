from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
import regress

# code to be emulated
'''
ins = {
    0x00008cd4: """
                push    {r11}
                add     r11, sp, #0
                mov     r3, pc
                mov     r0, r3
                sub     sp, r11, #0
                pop     {r11}
                bx      lr
                """,
    0x00008cf0: """
                push    {r11}
                add     r11, sp, #0
                push   {r6}
                add    r6, pc, $1
                bx r6
                .code   16
                mov    r3, pc
                add    r3, $0x4
                push   {r3}
                pop    {pc}
                .code  32
                pop    {r6}
                mov     r0, r3
                sub     sp, r11, #0
                pop     {r11}
                bx      lr
                """,
    0x00008d20: """
                push    {r11}
                add r11, sp, #0
                mov r3, lr
                mov r0, r3
                sub sp, r11, #0
                pop {r11}
                bx  lr
                """,
    0x00008d68: "bl      0x8cd4\n"
                "mov     r4, r0\n"
                "bl      0x8cf0\n"
                "mov     r3, r0\n"
                "add     r4, r4, r3\n"
                "bl      0x8d20\n"
                "mov     r3, r0\n"
                "add     r2, r4, r3",
}
'''

class BxTwiceTest(regress.RegressTest):
    def runTest(self):
        ADDRESS = 0x8000
        MAIN_ADDRESS = 0x8d68
        STACK_ADDR = ADDRESS + 0x1000

        code = {
            0x8cf0: '\x04\xb0-\xe5\x00\xb0\x8d\xe2\x04`-\xe5\x01`\x8f\xe2\x16\xff/\xe1{F\x03\xf1\x04\x03\x08\xb4\x00\xbd\x00\x00\x04`\x9d\xe4\x03\x00\xa0\xe1\x00\xd0K\xe2\x04\xb0\x9d\xe4\x1e\xff/\xe1',
            0x8d20: '\x04\xb0-\xe5\x00\xb0\x8d\xe2\x0e0\xa0\xe1\x03\x00\xa0\xe1\x00\xd0K\xe2\x04\xb0\x9d\xe4\x1e\xff/\xe1',
            0x8cd4: '\x04\xb0-\xe5\x00\xb0\x8d\xe2\x0f0\xa0\xe1\x03\x00\xa0\xe1\x00\xd0K\xe2\x04\xb0\x9d\xe4\x1e\xff/\xe1',
            0x8d68: '\xd9\xff\xff\xeb\x00@\xa0\xe1\xde\xff\xff\xeb\x000\xa0\xe1\x03@\x84\xe0\xe7\xff\xff\xeb\x000\xa0\xe1\x03 \x84\xe0'
        }

        try:
            mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            # map 2MB memory for this emulation
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)

            # write machine code to be emulated to memory
            for addr, c in code.items():
                print("Writing chunk to 0x{:x}".format(addr))
                mu.mem_write(addr, c)

            # initialize machine registers
            mu.reg_write(UC_ARM_REG_SP, STACK_ADDR)

            print("Starting emulation")

            # emulate code in infinite time & unlimited instructions
            mu.emu_start(MAIN_ADDRESS, MAIN_ADDRESS + len(code[MAIN_ADDRESS]))

            print("Emulation done")

            r2 = mu.reg_read(UC_ARM_REG_R2)
            print(">>> r2: 0x{:08x}".format(r2))

        except UcError as e:
            self.fail("ERROR: %s" % e)
