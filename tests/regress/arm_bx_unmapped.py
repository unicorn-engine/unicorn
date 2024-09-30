from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
import regress


class BxTwiceTest(regress.RegressTest):
    def runTest(self):
        ADDRESS = 0x8000
        MAIN_ADDRESS = 0x8d68
        STACK_ADDR = ADDRESS + 0x1000

        # code to be emulated
        code = {
            0x8cf0: (
                b'\x04\xb0\x2d\xe5'     #  push     {r11}
                b'\x00\xb0\x8d\xe2'     #  add      r11, sp, #0
                b'\x04\x60\x2d\xe5'     #  push     {r6}
                b'\x01\x60\x8f\xe2'     #  add      r6, pc, $1
                b'\x16\xff\x2f\xe1'     #  bx       r6
                                        #  .code 16
                b'\x7b\x46'             #  mov      r3, pc
                b'\x03\xf1\x04\x03'     #  add      r3, $0x4
                b'\x08\xb4'             #  push     {r3}
                b'\x00\xbd'             #  pop      {pc}
                b'\x00\x00'             #  (alignment)
                                        #  .code 32
                b'\x04\x60\x9d\xe4'     #  pop      {r6}
                b'\x03\x00\xa0\xe1'     #  mov      r0, r3
                b'\x00\xd0\x4b\xe2'     #  sub      sp, r11, #0
                b'\x04\xb0\x9d\xe4'     #  pop      {r11}
                b'\x1e\xff\x2f\xe1'     #  bx       lr
            ),
            0x8d20: (
                b'\x04\xb0\x2d\xe5'     #  push     {r11}
                b'\x00\xb0\x8d\xe2'     #  add      r11, sp, #0
                b'\x0e\x30\xa0\xe1'     #  mov      r3, lr
                b'\x03\x00\xa0\xe1'     #  mov      r0, r3
                b'\x00\xd0\x4b\xe2'     #  sub      sp, r11, #0
                b'\x04\xb0\x9d\xe4'     #  pop      {r11}
                b'\x1e\xff\x2f\xe1'     #  bx       lr
            ),
            0x8cd4: (
                b'\x04\xb0\x2d\xe5'     #  push     {r11}
                b'\x00\xb0\x8d\xe2'     #  add      r11, sp, #0
                b'\x0f\x30\xa0\xe1'     #  mov      r3, pc
                b'\x03\x00\xa0\xe1'     #  mov      r0, r3
                b'\x00\xd0\x4b\xe2'     #  sub      sp, r11, #0
                b'\x04\xb0\x9d\xe4'     #  pop      {r11}
                b'\x1e\xff\x2f\xe1'     #  bx       lr
            ),
            0x8d68: (
                b'\xd9\xff\xff\xeb'     #  bl       0x8cd4
                b'\x00\x40\xa0\xe1'     #  mov      r4, r0
                b'\xde\xff\xff\xeb'     #  bl       0x8cf0
                b'\x00\x30\xa0\xe1'     #  mov      r3, r0
                b'\x03\x40\x84\xe0'     #  add      r4, r4, r3
                b'\xe7\xff\xff\xeb'     #  bl       0x8d20
                b'\x00\x30\xa0\xe1'     #  mov      r3, r0
                b'\x03\x20\x84\xe0'     #  add      r2, r4, r3
            )
        }

        try:
            mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            # map 2MB memory for this emulation
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)

            # write machine code to be emulated to memory
            for addr, c in code.items():
                regress.logger.info("Writing chunk to 0x%x", addr)
                mu.mem_write(addr, c)

            # initialize machine registers
            mu.reg_write(UC_ARM_REG_SP, STACK_ADDR)

            regress.logger.info("Starting emulation")

            # emulate code in infinite time & unlimited instructions
            mu.emu_start(MAIN_ADDRESS, MAIN_ADDRESS + len(code[MAIN_ADDRESS]))

            regress.logger.info("Emulation done")

            r2 = mu.reg_read(UC_ARM_REG_R2)
            regress.logger.info(">>> r2: 0x%08x", r2)

        except UcError as e:
            self.fail("ERROR: %s" % e)
