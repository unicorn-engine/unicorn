# Moshe Kravchik

import binascii
import regress
from unicorn import *
from unicorn.arm_const import *

# enable VFP
ENABLE_VFP_CODE = (
    b"\x4f\xf4\x70\x03"  # 00000016    mov.w       r3, #0xf00000
    b"\x01\xee\x50\x3f"  # 0000001a    mcr         p15, #0x0, r3, c1, c0, #0x2
    b"\xbf\xf3\x6f\x8f"  # 0000bfb6    isb         sy
    b"\x4f\xf0\x80\x43"  # 0000bfba    mov.w       r3, #0x40000000
    b"\xe8\xee\x10\x3a"  # 0000bfbe    vmsr        fpexc, r3
)

VLD_CODE = b"\x21\xf9\x0f\x6a"  # 0000002a    vld1.8  {d6, d7}, [r1]
VST_CODE = b"\x00\xf9\x0f\x6a"  # 0000002e    vst1.8  {d6, d7}, [r0]

# memory address where emulation starts
ADDRESS = 0x10000
SCRATCH_ADDRESS = 0x1000


class SIMDNotReadArm(regress.RegressTest):

    def runTest(self):
        code = ENABLE_VFP_CODE + VLD_CODE + VST_CODE
        regress.logger.debug("Emulate THUMB code")

        # Initialize emulator in thumb mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # map 10K scratch memory for this emulation
        mu.mem_map(SCRATCH_ADDRESS, 10 * 1024)

        # write dummy data to be emulated to memory
        mu.mem_write(SCRATCH_ADDRESS, b"\x01" * 64)

        # initialize machine registers
        for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
            mu.reg_write(i, i - UC_ARM_REG_R0)

        mu.reg_write(UC_ARM_REG_R1, SCRATCH_ADDRESS)
        mu.reg_write(UC_ARM_REG_R0, SCRATCH_ADDRESS + 0x100)

        mu.reg_write(UC_ARM_REG_SP, 0x1234)
        mu.reg_write(UC_ARM_REG_D6, UC_ARM_REG_D6)
        mu.reg_write(UC_ARM_REG_D7, UC_ARM_REG_D7)

        regress.logger.debug(">>> Before emulation")
        regress.logger.debug("\tD6 = %#x", mu.reg_read(UC_ARM_REG_D6))
        regress.logger.debug("\tD7 = %#x", mu.reg_read(UC_ARM_REG_D7))

        for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
            regress.logger.debug("\tR%d = %#x", (i - UC_ARM_REG_R0), mu.reg_read(i))

        addr = SCRATCH_ADDRESS
        data = mu.mem_read(addr, 100)
        regress.logger.debug("Memory at addr %#x: %s", addr, binascii.hexlify(data))

        addr = SCRATCH_ADDRESS + 0x100
        data = mu.mem_read(addr, 100)
        regress.logger.debug("Memory at addr %#x: %s", addr, binascii.hexlify(data))

        self.assertEqual(UC_ARM_REG_D6, mu.reg_read(UC_ARM_REG_D6))
        self.assertEqual(UC_ARM_REG_D7, mu.reg_read(UC_ARM_REG_D7))

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS | 0b1, ADDRESS + len(code))

        # now print out some registers
        regress.logger.debug(">>> After emulation")
        regress.logger.debug(">>> SP = %#x", mu.reg_read(UC_ARM_REG_SP))
        regress.logger.debug(">>> PC = %#x", mu.reg_read(UC_ARM_REG_PC))

        for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
            regress.logger.debug("\tR%d = %#x", (i - UC_ARM_REG_R0), mu.reg_read(i))

        regress.logger.debug("\tD6 = %#x", mu.reg_read(UC_ARM_REG_D6))
        regress.logger.debug("\tD7 = %#x", mu.reg_read(UC_ARM_REG_D7))

        addr = SCRATCH_ADDRESS
        data = mu.mem_read(addr, 100)
        regress.logger.debug("Memory at addr %#x: %s", addr, binascii.hexlify(data))

        addr = SCRATCH_ADDRESS + 0x100
        data = mu.mem_read(addr, 100)
        regress.logger.debug("Memory at addr %#x: %s", addr, binascii.hexlify(data))

        self.assertEqual(mu.reg_read(UC_ARM_REG_D6), 0x0101010101010101)
        self.assertEqual(mu.reg_read(UC_ARM_REG_D7), 0x0101010101010101)


if __name__ == '__main__':
    regress.main()
