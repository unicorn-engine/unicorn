import regress
from unicorn import *
from unicorn.x86_const import *


ADDRESS = 0x1000
SYSENTER_CS = 0x174


class X86MsrHooks(regress.RegressTest):

    def create_engine(self, code):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(ADDRESS, 0x1000)
        uc.mem_write(ADDRESS, code)
        uc.reg_write(UC_X86_REG_ECX, SYSENTER_CS)
        return uc

    def test_rdmsr_skip(self):
        code = b'\x0f\x32'
        uc = self.create_engine(code)
        calls = []

        def hook(engine, user_data):
            self.assertIs(engine, uc)
            self.assertIs(user_data, calls)
            user_data.append(engine.reg_read(UC_X86_REG_ECX))
            engine.reg_write(UC_X86_REG_EAX, 0x89abcdef)
            engine.reg_write(UC_X86_REG_EDX, 0x01234567)
            return True

        handle = uc.hook_add(UC_HOOK_INSN, hook, calls, aux1=UC_X86_INS_RDMSR)
        uc.emu_start(ADDRESS, ADDRESS + len(code))
        self.assertEqual(calls, [SYSENTER_CS])
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 0x89abcdef)
        self.assertEqual(uc.reg_read(UC_X86_REG_EDX), 0x01234567)
        uc.hook_del(handle)

    def test_rdmsr_continue(self):
        code = b'\x0f\x32'
        uc = self.create_engine(code)
        uc.msr_write(SYSENTER_CS, 0x10)
        calls = []

        def hook(engine, user_data):
            user_data.append(engine.reg_read(UC_X86_REG_ECX))
            return False

        handle = uc.hook_add(UC_HOOK_INSN, hook, calls, aux1=UC_X86_INS_RDMSR)
        uc.emu_start(ADDRESS, ADDRESS + len(code))
        self.assertEqual(calls, [SYSENTER_CS])
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 0x10)
        self.assertEqual(uc.reg_read(UC_X86_REG_EDX), 0)
        uc.hook_del(handle)

    def test_wrmsr_skip(self):
        code = b'\x0f\x30'
        uc = self.create_engine(code)
        uc.msr_write(SYSENTER_CS, 0x10)
        uc.reg_write(UC_X86_REG_EAX, 0x20)
        uc.reg_write(UC_X86_REG_EDX, 0)
        calls = []

        def hook(engine, user_data):
            self.assertIs(engine, uc)
            self.assertIs(user_data, calls)
            user_data.append(engine.reg_read(UC_X86_REG_EAX))
            return True

        handle = uc.hook_add(UC_HOOK_INSN, hook, calls, aux1=UC_X86_INS_WRMSR)
        uc.emu_start(ADDRESS, ADDRESS + len(code))
        self.assertEqual(calls, [0x20])
        uc.hook_del(handle)
        self.assertEqual(uc.msr_read(SYSENTER_CS), 0x10)

    def test_wrmsr_continue(self):
        code = b'\x0f\x30'
        uc = self.create_engine(code)
        uc.reg_write(UC_X86_REG_EAX, 0x20)
        uc.reg_write(UC_X86_REG_EDX, 0)
        calls = []

        def hook(engine, user_data):
            user_data.append(engine.reg_read(UC_X86_REG_EAX))
            return False

        handle = uc.hook_add(UC_HOOK_INSN, hook, calls, aux1=UC_X86_INS_WRMSR)
        uc.emu_start(ADDRESS, ADDRESS + len(code))
        self.assertEqual(calls, [0x20])
        uc.hook_del(handle)
        self.assertEqual(uc.msr_read(SYSENTER_CS), 0x20)


if __name__ == '__main__':
    regress.main()
