import regress
from unicorn import *
from unicorn.arm_const import *

MAIN_ADDRESS = 0x8d68
ADDRESS = MAIN_ADDRESS & ~(0x1000 - 1)
STACK_ADDR = ADDRESS + 0x1000


class BxTwiceTest(regress.RegressTest):
    def runTest(self):
        # code to be emulated
        code = {
            0x8cd4: (
                b'\x04\xb0\x2d\xe5'  # 8cd4     push     {r11}
                b'\x00\xb0\x8d\xe2'  # 8cd8     add      r11, sp, #0
                b'\x0f\x30\xa0\xe1'  # 8cdc     mov      r3, pc
                b'\x03\x00\xa0\xe1'  # 8ce0     mov      r0, r3
                b'\x00\xd0\x4b\xe2'  # 8ce4     sub      sp, r11, #0
                b'\x04\xb0\x9d\xe4'  # 8ce8     pop      {r11}
                b'\x1e\xff\x2f\xe1'  # 8cec     bx       lr
            ),
            0x8cf0: (
                b'\x04\xb0\x2d\xe5'  # 8cf0     push     {r11}
                b'\x00\xb0\x8d\xe2'  # 8cf4     add      r11, sp, #0
                b'\x04\x60\x2d\xe5'  # 8cf8     push     {r6}
                b'\x01\x60\x8f\xe2'  # 8cfc     add      r6, pc, $1
                b'\x16\xff\x2f\xe1'  # 8d00     bx       r6
                                     #           .thumb
                b'\x7b\x46'          # 8d04     mov      r3, pc
                b'\x03\xf1\x08\x03'  # 8d06     add      r3, $0x8        # elicn: used to be $0x4 but it kept failing
                b'\x08\xb4'          # 8d0a     push     {r3}
                b'\x00\xbd'          # 8d0c     pop      {pc}
                b'\x00\x00'          # 8d0e     (alignment)
                                     #           .arm
                b'\x04\x60\x9d\xe4'  # 8d10     pop      {r6}
                b'\x03\x00\xa0\xe1'  # 8d14     mov      r0, r3
                b'\x00\xd0\x4b\xe2'  # 8d18     sub      sp, r11, #0
                b'\x04\xb0\x9d\xe4'  # 8d1c     pop      {r11}
                b'\x1e\xff\x2f\xe1'  # 8d20     bx       lr
            ),
            0x8d24: (  # elicn: used to be 0x8d20 but it caused this block to overlap with the previous one
                b'\x04\xb0\x2d\xe5'  # 8d24     push     {r11}
                b'\x00\xb0\x8d\xe2'  # 8d28     add      r11, sp, #0
                b'\x0e\x30\xa0\xe1'  # 8d2c     mov      r3, lr
                b'\x03\x00\xa0\xe1'  # 8d20     mov      r0, r3
                b'\x00\xd0\x4b\xe2'  # 8d34     sub      sp, r11, #0
                b'\x04\xb0\x9d\xe4'  # 8d38     pop      {r11}
                b'\x1e\xff\x2f\xe1'  # 8d3c     bx       lr
            ),
            0x8d68: (
                b'\xd9\xff\xff\xeb'  # 8d68     bl       0x8cd4      <-- MAIN_ADDRESS
                b'\x00\x40\xa0\xe1'  # 8d6c     mov      r4, r0
                b'\xde\xff\xff\xeb'  # 8d70     bl       0x8cf0
                b'\x00\x30\xa0\xe1'  # 8d74     mov      r3, r0
                b'\x03\x40\x84\xe0'  # 8d78     add      r4, r4, r3
                b'\xe8\xff\xff\xeb'  # 8d7c     bl       0x8d24
                b'\x00\x30\xa0\xe1'  # 8d80     mov      r3, r0
                b'\x03\x20\x84\xe0'  # 8d84     add      r2, r4, r3
            )
        }

        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        mu.mem_map(ADDRESS, 0x1000)

        # write machine code to be emulated to memory
        for addr, c in code.items():
            regress.logger.debug("Writing %d bytes to %#x", len(c), addr)
            mu.mem_write(addr, c)

        # initialize machine registers
        mu.reg_write(UC_ARM_REG_PC, MAIN_ADDRESS)
        mu.reg_write(UC_ARM_REG_SP, STACK_ADDR)

        regress.logger.debug("Starting emulation")

        # trace code only if we are debugging it
        if regress.logger.isEnabledFor(regress.logging.DEBUG):
            def __hook_code(uc, addr, size, _):
                cpsr, r0, r3, r4, r6 = uc.reg_read_batch((
                    UC_ARM_REG_CPSR,
                    UC_ARM_REG_R0,
                    UC_ARM_REG_R3,
                    UC_ARM_REG_R4,
                    UC_ARM_REG_R6
                ))

                is_thumb = (cpsr >> 5) & 0b1

                opcode = uc.mem_read(addr, size).hex()

                regress.logger.debug(
                    "%-2s PC = %#06x | opcode = %-8s    [R0 = %#06x, R3 = %#06x, R4 = %#07x, R6 = %#06x]",
                    "T" if is_thumb else "", addr, opcode, r0, r3, r4, r6
                )

            mu.hook_add(UC_HOOK_CODE, __hook_code)

        mu.emu_start(MAIN_ADDRESS, MAIN_ADDRESS + len(code[MAIN_ADDRESS]))

        regress.logger.debug("Emulation done")

        self.assertEqual(0x8ce4 + 0x8d10 + 0x8d80, mu.reg_read(UC_ARM_REG_R2))


if __name__ == '__main__':
    regress.main()
