#!/usr/bin/env python
# Moshe Kravchik

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
import binascii
import regress


# code to be emulated

#enable VFP
'''
00000016	f44f0370	mov.w	r3, #0xf00000
0000001a	ee013f50	mcr	p15, #0x0, r3, c1, c0, #0x2
0000bfb6	f3bf8f6f	isb	sy
0000bfba	f04f4380	mov.w	r3, #0x40000000
0000bfbe	eee83a10	vmsr	fpexc, r3
'''
ENABLE_VFP_CODE = "\x4f\xf4\x70\x03\x01\xee\x50\x3f\xbf\xf3\x6f\x8f\x4f\xf0\x80\x43\xe8\xee\x10\x3a"
VLD_CODE = "\x21\xf9\x0f\x6a"
#0000002a	f9216a0f	vld1.8	{d6, d7}, [r1]
VST_CODE = "\x00\xf9\x0f\x6a"
#0000002e	f9006a0f	vst1.8	{d6, d7}, [r0]

# memory address where emulation starts
ADDRESS    = 0x10000
SCRATCH_ADDRESS    = 0x1000

class SIMDNotReadArm(regress.RegressTest):
    def runTest(self):
        code = ENABLE_VFP_CODE+VLD_CODE+VST_CODE
        print("Emulate THUMB code")
        try:
            # Initialize emulator in thumb mode
            mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

            # map 2MB memory for this emulation
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)

            # write machine code to be emulated to memory
            mu.mem_write(ADDRESS, code)

            # map 10K scratch memory for this emulation
            mu.mem_map(SCRATCH_ADDRESS, 10 * 1024)

            # write dummy data to be emulated to memory
            mu.mem_write(SCRATCH_ADDRESS, "\x01"*64)

            # initialize machine registers
            for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
                val = mu.reg_write(i, i - UC_ARM_REG_R0)

            mu.reg_write(UC_ARM_REG_R1, SCRATCH_ADDRESS)
            mu.reg_write(UC_ARM_REG_R0, SCRATCH_ADDRESS + 0x100)

            mu.reg_write(UC_ARM_REG_SP, 0x1234)
            mu.reg_write(UC_ARM_REG_D6, UC_ARM_REG_D6)
            mu.reg_write(UC_ARM_REG_D7, UC_ARM_REG_D7)

            print(">>> Before emulation ")
            print("\tD6 = 0x%x" % mu.reg_read(UC_ARM_REG_D6))
            print("\tD7 = 0x%x" % mu.reg_read(UC_ARM_REG_D7))
            for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
                val = mu.reg_read(i)
                print("\t %s = 0x%x" % ("R" + str(i-UC_ARM_REG_R0),val))

            self.assertEqual(UC_ARM_REG_D6, mu.reg_read(UC_ARM_REG_D6))
            self.assertEqual(UC_ARM_REG_D7, mu.reg_read(UC_ARM_REG_D7))

            try:
                content = mu.mem_read(SCRATCH_ADDRESS, 100)
                print("Memory at addr 0x%X %s" % (SCRATCH_ADDRESS, binascii.hexlify(content)))
                content = mu.mem_read(SCRATCH_ADDRESS+0x100, 100)
                print("Memory at addr 0x%X %s" % (SCRATCH_ADDRESS+0x100, binascii.hexlify(content)))
            except Exception, errtxt:
                print (errtxt)


            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(code))

            # now print out some registers
            print(">>> Emulation done. Below is the CPU context")

            sp = mu.reg_read(UC_ARM_REG_SP)
            print(">>> SP = 0x%x" %sp)
            val = mu.reg_read(UC_ARM_REG_PC)
            print(">>> PC = 0x%x" %val)
            for i in range(UC_ARM_REG_R0, UC_ARM_REG_R12):
                val = mu.reg_read(i)
                print(">>> %s = 0x%x" % ("R" + str(i-UC_ARM_REG_R0),val))

            print("\tD6 = 0x%x" % mu.reg_read(UC_ARM_REG_D6))
            print("\tD7 = 0x%x" % mu.reg_read(UC_ARM_REG_D7))

            try:
                content = mu.mem_read(SCRATCH_ADDRESS, 100)
                print("Memory at addr 0x%X %s" % (SCRATCH_ADDRESS, binascii.hexlify(content)))
                content = mu.mem_read(SCRATCH_ADDRESS+0x100, 100)
                print("Memory at addr 0x%X %s" % (SCRATCH_ADDRESS+0x100, binascii.hexlify(content)))
            except Exception, errtxt:
                print (errtxt)

            self.assertEqual(mu.reg_read(UC_ARM_REG_D6), 0x0101010101010101)
            self.assertEqual(mu.reg_read(UC_ARM_REG_D7), 0x0101010101010101)

        except UcError as e:
            print("ERROR: %s" % e)

if __name__ == '__main__':
    regress.main()
