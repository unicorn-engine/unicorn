#
# This test demonstrates emulation behavior within and across
#  basic blocks.

import binascii
import struct
import regress
from unicorn import *
from unicorn.x86_const import *

CODE = (
    b"\xb8\x00\x00\x00\x00" # 1000:   mov    eax,0x0
    b"\x40"                 # 1005:   inc    eax
    b"\x40"                 # 1006:   inc    eax
    b"\x68\x10\x10\x00\x00" # 1007:   push   0x1010
    b"\xc3"                 # 100c:   ret
    b"\xcc"                 # 100d:   int3
    b"\xcc"                 # 100e:   int3
    b"\xcc"                 # 100f:   int3
    b"\xb8\x00\x00\x00\x00" # 1010:   mov    eax,0x0
    b"\x40"                 # 1015:   inc    eax
    b"\x40"                 # 1016:   inc    eax
)


def showpc(mu):
    regress.logger.debug("pc: 0x%x", mu.reg_read(UC_X86_REG_EIP))


class RunAcrossBBTest(regress.RegressTest):
    def test_run_all(self):
        try:
            #######################################################################
            # emu SETUP
            #######################################################################
            regress.logger.debug("\n---- test: run_all ----")

            mu = Uc(UC_ARCH_X86, UC_MODE_32)

            def hook_code(uc, address, size, user_data):
                regress.logger.debug(">>> Tracing instruction at 0x%x, instruction size = %u", address, size)

            mu.hook_add(UC_HOOK_CODE, hook_code)

            # base of CODE
            mu.mem_map(0x1000, 0x1000)
            mu.mem_write(0x1000, CODE)

            # stack
            mu.mem_map(0x2000, 0x1000)

            mu.reg_write(UC_X86_REG_EIP, 0x1000)
            mu.reg_write(UC_X86_REG_ESP, 0x2800)
            self.assertEqual(0x1000, mu.reg_read(UC_X86_REG_EIP), "unexpected PC")
            self.assertEqual(0x2800, mu.reg_read(UC_X86_REG_ESP), "unexpected SP")
            showpc(mu)

            mu.emu_start(0x1000, 0x1016)
            # should exec the following four instructions:
            # 1000: b8 00 00 00 00          mov    eax,0x0  <
            # 1005: 40                      inc    eax      <
            # 1006: 40                      inc    eax      <
            # 1007: 68 10 10 00 00          push   0x1010   <
            # 100c: c3                      ret   -----------+
            # 100d: cc                      int3             |
            # 100e: cc                      int3             |
            # 100f: cc                      int3             |
            # 1010: b8 00 00 00 00          mov    eax,0x0 <-+
            # 1015: 40                      inc    eax       <
            # 1016: 40                      inc    eax       <

            self.assertEqual(0x1016, mu.reg_read(UC_X86_REG_EIP), "unexpected PC (2)")
            self.assertEqual(0x2800, mu.reg_read(UC_X86_REG_ESP), "unexpected SP (2)")

            showpc(mu)

        except UcError as e:
            eip = mu.reg_read(UC_X86_REG_EIP)

            if e.errno == UC_ERR_FETCH_UNMAPPED:
                # during initial test dev, bad fetch at 0x1010, but the data is there, and this proves it
                regress.logger.error("!!! about to bail due to bad fetch... here's the data at PC:")
                regress.logger.error(binascii.hexlify(mu.mem_read(eip, 8)))

            self.fail("ERROR: %s @ 0x%x" % (e, eip))

    def test_run_across_bb(self):
        try:
            #######################################################################
            # emu SETUP
            #######################################################################
            regress.logger.debug("\n---- test: run_across_bb ----")

            mu = Uc(UC_ARCH_X86, UC_MODE_32)

            def hook_code(uc, address, size, user_data):
                regress.logger.debug(">>> Tracing instruction at 0x%x, instruction size = %u", address, size)

            mu.hook_add(UC_HOOK_CODE, hook_code)

            # base of CODE
            mu.mem_map(0x1000, 0x1000)
            mu.mem_write(0x1000, CODE)

            # stack
            mu.mem_map(0x2000, 0x1000)

            mu.reg_write(UC_X86_REG_EIP, 0x1000)
            mu.reg_write(UC_X86_REG_ESP, 0x2800)

            self.assertEqual(0x1000, mu.reg_read(UC_X86_REG_EIP), "unexpected PC")
            self.assertEqual(0x2800, mu.reg_read(UC_X86_REG_ESP), "unexpected SP")

            showpc(mu)

            #######################################################################
            # emu_run ONE:
            #   exectue four instructions, until the last instruction in a BB
            #######################################################################

            mu.emu_start(0x1000, 0x100c)
            # should exec the following four instructions:
            # 1000: b8 00 00 00 00          mov    eax,0x0  <
            # 1005: 40                      inc    eax      <
            # 1006: 40                      inc    eax      <
            # 1007: 68 10 10 00 00          push   0x1010   <

            # should be at 0x100c, as requested
            self.assertEqual(0x100c, mu.reg_read(UC_X86_REG_EIP), "unexpected PC (2)")

            # single push, so stack diff is 0x4
            TOP_OF_STACK = 0x2800 - 0x4
            self.assertEqual(TOP_OF_STACK, mu.reg_read(UC_X86_REG_ESP), "unexpected SP (2)")

            # top of stack should be 0x1010
            self.assertEqual(0x1010,
                             struct.unpack("<I", mu.mem_read(TOP_OF_STACK, 0x4))[0],
                             "unexpected stack value")
            showpc(mu)

            #######################################################################
            # emu_run TWO
            #   execute one instruction that jumps to a new BB
            #######################################################################

            mu.emu_start(0x100c, 0x1010)
            # should exec one instruction that jumps to 0x1010:
            # 100c: c3                      ret   -----------+
            # 100d: cc                      int3             |
            # 100e: cc                      int3             |
            # 100f: cc                      int3             |
            # 1010: b8 00 00 00 00          mov    eax,0x0 <-+

            # should be at 0x1010, as requested
            self.assertEqual(0x1010, mu.reg_read(UC_X86_REG_EIP), "unexpected PC (3)")

            # single pop, so stack back at base
            self.assertEqual(0x2800, mu.reg_read(UC_X86_REG_ESP), "unexpected SP (3)")
            showpc(mu)

            #######################################################################
            # emu_run THREE
            #  execute three instructions to verify things work as expected
            #######################################################################

            mu.emu_start(0x1010, 0x1016)
            # should exec the following three instructions:
            # 1010: b8 00 00 00 00          mov    eax,0x0   <
            # 1015: 40                      inc    eax       <
            # 1016: 40                      inc    eax       <
            self.assertEqual(0x1016, mu.reg_read(UC_X86_REG_EIP),
                             "unexpected PC (4): 0x%x vs 0x%x" % (0x1016, mu.reg_read(UC_X86_REG_EIP)))
            showpc(mu)

        except UcError as e:
            eip = mu.reg_read(UC_X86_REG_EIP)

            if e.errno == UC_ERR_FETCH_UNMAPPED:
                # during initial test dev, bad fetch at 0x1010, but the data is there, and this proves it
                regress.logger.error("!!! about to bail due to bad fetch... here's the data at PC:")
                regress.logger.error(binascii.hexlify(mu.mem_read(eip, 8)))

            self.fail("ERROR: %s @ 0x%x" % (e, eip))


if __name__ == '__main__':
    regress.main()
