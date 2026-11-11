import pickle

import regress
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *


class ContextRegisters(regress.RegressTest):

    def test_x86_vector_read(self):
        value = 0x112233445566778899aabbccddeeff00
        for pickled in (False, True):
            for batch in (False, True):
                with self.subTest(pickled=pickled, batch=batch):
                    uc = Uc(UC_ARCH_X86, UC_MODE_64)
                    uc.reg_write(UC_X86_REG_XMM0, value)
                    context = uc.context_save()
                    if pickled:
                        context = pickle.loads(pickle.dumps(context))

                    if batch:
                        actual, = context.reg_read_batch((UC_X86_REG_XMM0,))
                    else:
                        actual = context.reg_read(UC_X86_REG_XMM0)
                    self.assertEqual(actual, value)

    def check_registers(self, arch, mode, values):
        for pickled in (False, True):
            for batch in (False, True):
                with self.subTest(pickled=pickled, batch=batch):
                    uc = Uc(arch, mode)
                    context = uc.context_save()
                    if pickled:
                        context = pickle.loads(pickle.dumps(context))

                    if batch:
                        context.reg_write_batch(values)
                    else:
                        for reg, value in values:
                            context.reg_write(reg, value)

                    uc.context_restore(context)
                    for reg, value in values:
                        self.assertEqual(uc.reg_read(reg), value)

                    regs = tuple(reg for reg, _ in values)
                    expected = tuple(value for _, value in values)
                    if batch:
                        actual = context.reg_read_batch(regs)
                    else:
                        actual = tuple(context.reg_read(reg) for reg in regs)
                    self.assertEqual(actual, expected)

    def test_x86_vectors(self):
        self.check_registers(UC_ARCH_X86, UC_MODE_64, (
            (UC_X86_REG_XMM0, 0x112233445566778899aabbccddeeff00),
            (UC_X86_REG_YMM1,
             0x0123456789abcdef112233445566778899aabbccddeeff00fedcba9876543210)
        ))

    def test_arm_vectors(self):
        self.check_registers(UC_ARCH_ARM, UC_MODE_ARM, (
            (UC_ARM_REG_Q0, 0x112233445566778899aabbccddeeff00),
            (UC_ARM_REG_Q15, 0xfedcba98765432100123456789abcdef)
        ))

    def test_arm64_vectors(self):
        self.check_registers(UC_ARCH_ARM64, UC_MODE_ARM, (
            (UC_ARM64_REG_Q0, 0x112233445566778899aabbccddeeff00),
            (UC_ARM64_REG_V31, 0xfedcba98765432100123456789abcdef)
        ))

    def test_x86_floating_point(self):
        self.check_registers(UC_ARCH_X86, UC_MODE_64, (
            (UC_X86_REG_FP0, (0x8000000000000000, 0x3fff)),
            (UC_X86_REG_FP7, (0xc000000000000000, 0x4000))
        ))

    def test_x86_descriptors(self):
        self.check_registers(UC_ARCH_X86, UC_MODE_64, (
            (UC_X86_REG_GDTR, (0, 0x123456789abcdef0, 0xffff, 0)),
            (UC_X86_REG_IDTR, (0, 0xfedcba9876543210, 0x7fff, 0))
        ))

    def test_scalar_registers(self):
        for arch, mode, reg in (
            (UC_ARCH_X86, UC_MODE_64, UC_X86_REG_RAX),
            (UC_ARCH_ARM, UC_MODE_ARM, UC_ARM_REG_R0),
            (UC_ARCH_ARM64, UC_MODE_ARM, UC_ARM64_REG_X0),
            (UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MIPS_REG_T0)
        ):
            with self.subTest(arch=arch):
                self.check_registers(arch, mode, ((reg, 0x12345678),))


if __name__ == '__main__':
    regress.main()
