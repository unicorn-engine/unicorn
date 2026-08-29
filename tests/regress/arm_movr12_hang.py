import regress
from unicorn import *
from unicorn.arm_const import *


class MovHang(regress.RegressTest):

    def runTest(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, b'\x00\xc0\x00\xe3\x00\x00\x00\xef')  # movw r12, #0 ; svc #0

        def hook_block(uc, addr, *args):
            regress.logger.debug('enter block 0x%#06x', addr)
            uc.count += 1

        uc.reg_write(UC_ARM_REG_R12, 0x123)
        self.assertEqual(0x123, uc.reg_read(UC_ARM_REG_R12))

        uc.hook_add(UC_HOOK_BLOCK, hook_block)
        uc.hook_add(UC_HOOK_INTR, lambda uc, intno, data: uc.emu_stop())
        uc.count = 0

        # Translate the block up front so the timeout bounds execution only, not
        # code generation. A pre-built tb does not carry the `until` exit, so the
        # svc stops emulation in-band instead. The timeout is only a hang guard,
        # with headroom for a scheduler stall on a loaded machine.
        uc.ctl_request_cache(0x1000)
        uc.emu_start(0x1000, 0x1008, timeout=10000)

        self.assertEqual(0x0, uc.reg_read(UC_ARM_REG_R12))
        self.assertEqual(uc.count, 1)


if __name__ == '__main__':
    regress.main()
