import regress
from unicorn import *
from unicorn.x86_const import *

NOPSLED = b"\x90" * 5


class TestSetIP(regress.RegressTest):
    def runTest(self):
        # execution history
        history = []

        def __code_hook(uc, addr, size, ud):
            # track execution history
            history.append(addr)

            if len(history) == 5:
                uc.emu_stop()
            else:
                uc.reg_write(UC_X86_REG_RIP, 0x1800)

        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(0x1000, 0x1000)
        mu.mem_write(0x1000, NOPSLED)
        mu.mem_write(0x1800, NOPSLED)

        mu.hook_add(UC_HOOK_CODE, __code_hook)
        mu.emu_start(0x1000, 0x1800 + 1)

        self.assertListEqual([0x1000] + [0x1800] * 4, history)


if __name__ == '__main__':
    regress.main()
