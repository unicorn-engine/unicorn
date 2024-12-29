import regress
from unicorn import *
from unicorn.x86_const import *

CODE = (
    b'\x48\xc7\xc0\x03\x00\x00\x00'     # 0x1000:    mov      rax, 3
    b'\x0f\x05'                         # 0x1007:    syscall
    b'\x48\xc7\xc7\x00\x40\x00\x00'     # 0x1009:    mov      rdi, 0x4000
    b'\x48\x89\x07'                     # 0x1010:    mov      [rdi], rdx
    b'\x48\x8b\x07'                     # 0x1013:    mov      rdx, [rdi]
    b'\x48\x83\xc2\x01'                 # 0x1016:    add      rdx, 1
)

BASE = 0x00001000
SCRATCH = 0x00004000


class SingleStepper:
    def __init__(self, uc, test):
        self.uc = uc
        self.hits = 0
        self.test = test

    def _stop_hook(self, uc, address, *args, **kwargs):
        self.hits += 1

        if self.hits > 1:
            self.test.assertEqual(2, self.hits, "HOOK_CODE invoked too many times")
            uc.emu_stop()

    def step(self):
        self.hits = 0
        h = self.uc.hook_add(UC_HOOK_CODE, self._stop_hook)

        try:
            pc = self.uc.reg_read(UC_X86_REG_RIP)
            self.uc.emu_start(pc, pc + 0x20)
        finally:
            self.uc.hook_del(h)


def showpc(mu):
    regress.logger.debug("pc: %#x", mu.reg_read(UC_X86_REG_RIP))


class HookCodeStopEmuTest(regress.RegressTest):
    def test_hook_code_stop_emu(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # base of CODE
        mu.mem_map(BASE, 0x1000)
        mu.mem_write(BASE, CODE)

        # scratch, used by CODE
        mu.mem_map(SCRATCH, 0x1000)

        mu.reg_write(UC_X86_REG_RDX, 0x1)
        mu.reg_write(UC_X86_REG_RIP, BASE)

        stepper = SingleStepper(mu, self)
        showpc(mu)
        self.assertEqual(BASE + 0x0, mu.reg_read(UC_X86_REG_RIP), "Unexpected starting PC")

        stepper.step()
        showpc(mu)
        self.assertEqual(BASE + 0x7, mu.reg_read(UC_X86_REG_RIP), "Emulator failed to stop after one instruction")

        stepper.step()
        showpc(mu)
        self.assertEqual(BASE + 0x9, mu.reg_read(UC_X86_REG_RIP), "Emulator failed to stop after one instruction")


if __name__ == '__main__':
    regress.main()
