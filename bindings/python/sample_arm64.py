#!/usr/bin/env python
# Sample code for ARM64 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *


# code to be emulated
ARM64_CODE = b"\xab\x05\x00\xb8\xaf\x05\x40\x38" # str x11, [x13]; ldrb x15, [x13]

# MSR code
ARM64_MRS_CODE = b"\x62\xd0\x3b\xd5" # mrs        x2, tpidrro_el0

# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


# Test ARM64
def test_arm64():
    print("Emulate ARM64 code")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM64_CODE)

        # initialize machine registers
        mu.reg_write(UC_ARM64_REG_X11, 0x12345678)
        mu.reg_write(UC_ARM64_REG_X13, 0x10008)
        mu.reg_write(UC_ARM64_REG_X15, 0x33)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing one instruction with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM64_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")
        print(">>> As little endian, X15 should be 0x78:")

        x11 = mu.reg_read(UC_ARM64_REG_X11)
        x13 = mu.reg_read(UC_ARM64_REG_X13)
        x15 = mu.reg_read(UC_ARM64_REG_X15)
        print(">>> X15 = 0x%x" %x15)

    except UcError as e:
        print("ERROR: %s" % e)


def test_arm64_read_sctlr():
    print("Read SCTLR_EL1")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # Read SCTLR_EL1
        # crn = 1;
        # crm = 0;
        # op0 = 3;
        # op1 = 0;
        # op2 = 0;
        val = mu.reg_read(UC_ARM64_REG_CP_REG, (1, 0, 3, 0, 0))
        print(">>> SCTLR_EL1 = 0x%x" % val)

    except UcError as e:
        print("ERROR: %s" % e)

def test_arm64_hook_mrs():
    def _hook_mrs(uc, reg, cp_reg, _):
        print(f">>> Hook MRS instruction: reg = 0x{reg:x}(UC_ARM64_REG_X2) cp_reg = {cp_reg}")
        uc.reg_write(reg, 0x114514)
        print(">>> Write 0x114514 to X")

        # Skip MRS instruction
        return True

    print("Test hook MRS instruction")
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # Map an area for code
        mu.mem_map(0x1000, 0x1000)

        # Write code
        mu.mem_write(0x1000, ARM64_MRS_CODE)

        # Hook MRS instruction
        mu.hook_add(UC_HOOK_INSN, _hook_mrs, None, 1, 0, UC_ARM64_INS_MRS)

        # Start emulation
        mu.emu_start(0x1000, 0x1000 + len(ARM64_MRS_CODE))

        print(f">>> X2 = {mu.reg_read(UC_ARM64_REG_X2):x}")

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == '__main__':
    test_arm64()
    print("=" * 26)
    test_arm64_read_sctlr()
    print("=" * 26)
    test_arm64_hook_mrs()
