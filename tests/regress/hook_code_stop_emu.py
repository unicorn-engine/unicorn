#!/usr/bin/python

from __future__ import print_function
import binascii
import regress

from unicorn import *
from unicorn.x86_const import *


CODE = binascii.unhexlify(b"".join([
  b"48c7c003000000", # mov rax, 3      mapped: 0x1000
  b"0f05",           # syscall         mapped: 0x1007
  b"48c7c700400000", # mov rdi, 0x4000 mapped: 0x1009
  b"488907",         # mov [rdi], rdx  mapped: 0x1010
  b"488b07",         # mov rdx, [rdi]  mapped: 0x1013
  b"4883c201",       # add rdx, 1      mapped: 0x1016
  ]))


class SingleStepper:
    def __init__(self, emu, test):
        self._emu = emu
        self._hit_count = 0
        self._test = test

    def _stop_hook(self, uc, address, *args, **kwargs):
        if self._hit_count == 0:
            self._hit_count += 1
        else:
            self._test.assertEqual(1, self._hit_count, "HOOK_CODE invoked too many times")
            uc.emu_stop()

    def step(self):
        self._hit_count = 0
        h = self._emu.hook_add(UC_HOOK_CODE, self._stop_hook)
        try:
            pc = self._emu.reg_read(UC_X86_REG_RIP)
            self._emu.emu_start(pc, pc+0x20)
        finally:
            self._emu.hook_del(h)


def showpc(mu):
    pc = mu.reg_read(UC_X86_REG_RIP)
    print("pc: 0x%x" % (pc))


class HookCodeStopEmuTest(regress.RegressTest):
    def test_hook_code_stop_emu(self):
        try:
            mu = Uc(UC_ARCH_X86, UC_MODE_64)

            # base of CODE
            mu.mem_map(0x1000, 0x1000)
            mu.mem_write(0x1000, CODE)

            # scratch, used by CODE
            mu.mem_map(0x4000, 0x1000)

            mu.reg_write(UC_X86_REG_RDX, 0x1)
            mu.reg_write(UC_X86_REG_RIP, 0x1000)

            # 0x1000:  48c7c003000000  mov rax, 3
            # 0x1007:  0f05            syscall
            # 0x1009:  48c7c700400000  mov rdi, 0x4000
            # 0x1010:  488907          mov [rdi], rdx
            # 0x1013:  488b07          mov rdx, [rdi]
            # 0x1016:  4883c201        add rdx, 1
            
            stepper = SingleStepper(mu, self)
            showpc(mu)
            self.assertEqual(0x1000, mu.reg_read(UC_X86_REG_RIP), "Unexpected PC")


            stepper.step()
            showpc(mu)            
            self.assertEqual(0x1007, mu.reg_read(UC_X86_REG_RIP),
                             "Emulator failed to stop after one instruction")

            stepper.step()
            showpc(mu)            
            self.assertEqual(0x1009, mu.reg_read(UC_X86_REG_RIP),
                             "Emulator failed to stop after one instruction")

        except UcError as e:
            self.assertFalse(0, "ERROR: %s" % e)


if __name__ == '__main__':
    regress.main()
