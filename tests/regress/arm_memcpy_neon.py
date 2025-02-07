import regress
import sys
import unittest
from unicorn import *
from unicorn.arm_const import *

SHELLCODE = (
    b'\x03\xF0\x8F\xE0'  # 0001F894        ADD         PC, PC, R3
    b'\x0D\x07\x21\xF4'  # 0001F898        VLD1.8      {D0}, [R1]!
    b'\x0D\x07\x0C\xF4'  # 0001F89C        VST1.8      {D0}, [R12]!
    b'\x0D\x07\x21\xF4'  # 0001F8A0        VLD1.8      {D0}, [R1]!
    b'\x0D\x07\x0C\xF4'  # 0001F8A4        VST1.8      {D0}, [R12]!
    b'\x0D\x07\x21\xF4'  # 0001F8A8        VLD1.8      {D0}, [R1]!
    b'\x0D\x07\x0C\xF4'  # 0001F8AC        VST1.8      {D0}, [R12]!
    b'\x0D\x07\x21\xF4'  # 0001F8B0        VLD1.8      {D0}, [R1]!
    b'\x0D\x07\x0C\xF4'  # 0001F8B4        VST1.8      {D0}, [R12]!
    b'\x0D\x07\x21\xF4'  # 0001F8B8        VLD1.8      {D0}, [R1]!
    b'\x0D\x07\x0C\xF4'  # 0001F8BC        VST1.8      {D0}, [R12]!
    b'\x0D\x07\x21\xF4'  # 0001F8C0        VLD1.8      {D0}, [R1]!
    b'\x0D\x07\x0C\xF4'  # 0001F8C4        VST1.8      {D0}, [R12]!
    b'\x0D\x07\x21\xF4'  # 0001F8C8        VLD1.8      {D0}, [R1]!
    b'\x0D\x07\x0C\xF4'  # 0001F8CC        VST1.8      {D0}, [R12]!
    b'\x04\x00\x12\xE3'  # 0001F8D0        TST         R2, #4
    b'\x04\x30\x91\x14'  # 0001F8D4        LDRNE       R3, [R1],#4
    b'\x04\x30\x8C\x14'  # 0001F8D8        STRNE       R3, [R12],#4
    b'\x82\x2F\xB0\xE1'  # 0001F8DC        MOVS        R2, R2,LSL#31
    b'\xB2\x30\xD1\x20'  # 0001F8E0        LDRHCS      R3, [R1],#2
    b'\x00\x10\xD1\x15'  # 0001F8E4        LDRBNE      R1, [R1]
    b'\xB2\x30\xCC\x20'  # 0001F8E8        STRHCS      R3, [R12],#2
    b'\x00\x10\xCC\x15'  # 0001F8EC        STRBNE      R1, [R12]
)
BASE = 0x1F894
COPY_SRC = 0x1000
COPY_DST = 0x2000
COPY_LEN = 8
DATA = b'c8' * COPY_LEN


class ArmMemcpy(regress.RegressTest):

    @unittest.skipIf(sys.version_info < (3, 7), reason="requires python3.7 or higher")
    def test_arm_memcpy(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        uc.mem_map(COPY_SRC, 0x1000)
        uc.mem_map(COPY_DST, 0x1000)
        uc.mem_map(BASE & ~(0x1000 - 1), 0x1000)
        uc.mem_write(COPY_SRC, DATA)
        uc.mem_write(BASE, SHELLCODE)

        uc.reg_write_batch((
            (UC_ARM_REG_R12, COPY_DST),
            (UC_ARM_REG_R1, COPY_SRC),
            (UC_ARM_REG_R2, COPY_LEN),
            (UC_ARM_REG_R3, 0x24)
        ))

        # enable_vfp

        # coproc=15, is64=0, sec=0, CRn=1, CRm=0, opc1=0, opc2=2
        CPACR = (15, 0, 0, 1, 0, 0, 2)

        cpacr = uc.reg_read(UC_ARM_REG_CP_REG, CPACR)
        uc.reg_write(UC_ARM_REG_CP_REG, CPACR + (cpacr | (0b11 << 20) | (0b11 << 22),))
        uc.reg_write(UC_ARM_REG_FPEXC, (0b1 << 30))

        uc.emu_start(BASE, BASE + len(SHELLCODE))
        src = uc.mem_read(COPY_SRC, len(DATA))
        dst = uc.mem_read(COPY_DST, len(DATA))

        self.assertEqual(DATA, src)
        self.assertEqual(DATA, dst)


if __name__ == '__main__':
    regress.main()
