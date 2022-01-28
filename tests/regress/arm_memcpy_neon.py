from unicorn import *
from unicorn.arm_const import *

# .text:0001F894                 ADD             PC, PC, R3
# .text:0001F898 ; ---------------------------------------------------------------------------
# .text:0001F898                 VLD1.8          {D0}, [R1]!
# .text:0001F89C                 VST1.8          {D0}, [R12]!
# .text:0001F8A0                 VLD1.8          {D0}, [R1]!
# .text:0001F8A4                 VST1.8          {D0}, [R12]!
# .text:0001F8A8                 VLD1.8          {D0}, [R1]!
# .text:0001F8AC                 VST1.8          {D0}, [R12]!
# .text:0001F8B0                 VLD1.8          {D0}, [R1]!
# .text:0001F8B4                 VST1.8          {D0}, [R12]!
# .text:0001F8B8                 VLD1.8          {D0}, [R1]!
# .text:0001F8BC                 VST1.8          {D0}, [R12]!
# .text:0001F8C0                 VLD1.8          {D0}, [R1]!
# .text:0001F8C4                 VST1.8          {D0}, [R12]!
# .text:0001F8C8                 VLD1.8          {D0}, [R1]!
# .text:0001F8CC                 VST1.8          {D0}, [R12]!
# .text:0001F8D0                 TST             R2, #4
# .text:0001F8D4                 LDRNE           R3, [R1],#4
# .text:0001F8D8                 STRNE           R3, [R12],#4
# .text:0001F8DC                 MOVS            R2, R2,LSL#31
# .text:0001F8E0                 LDRHCS          R3, [R1],#2
# .text:0001F8E4                 LDRBNE          R1, [R1]
# .text:0001F8E8                 STRHCS          R3, [R12],#2
# .text:0001F8EC                 STRBNE          R1, [R12]
shellcode = [0x3, 0xf0, 0x8f, 0xe0, 0xd, 0x7, 0x21, 0xf4, 0xd, 0x7, 0xc, 0xf4, 0xd, 0x7, 0x21, 0xf4, 0xd, 0x7, 0xc, 0xf4, 0xd, 0x7, 0x21, 0xf4, 0xd, 0x7, 0xc, 0xf4, 0xd, 0x7, 0x21, 0xf4, 0xd, 0x7, 0xc, 0xf4, 0xd, 0x7, 0x21, 0xf4, 0xd, 0x7, 0xc, 0xf4, 0xd, 0x7, 0x21, 0xf4, 0xd, 0x7, 0xc, 0xf4, 0xd, 0x7, 0x21, 0xf4, 0xd, 0x7, 0xc, 0xf4, 0x4, 0x0, 0x12, 0xe3, 0x4, 0x30, 0x91, 0x14, 0x4, 0x30, 0x8c, 0x14, 0x82, 0x2f, 0xb0, 0xe1, 0xb2, 0x30, 0xd1, 0x20, 0x0, 0x10, 0xd1, 0x15, 0xb2, 0x30, 0xcc, 0x20, 0x0, 0x10, 0xcc, 0x15]
base = 0x1F894
from_address = 0x1000
to_address = 0x2000
cplen = 8
bs = b"c8"*cplen

uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
uc.mem_map(from_address, 0x1000)
uc.mem_map(to_address, 0x1000)
uc.mem_map(0x1F000, 0x1000)
uc.mem_write(from_address, bs)
uc.mem_write(base, bytes(shellcode))
uc.reg_write(UC_ARM_REG_R12, to_address)
uc.reg_write(UC_ARM_REG_R1, from_address)
uc.reg_write(UC_ARM_REG_R2, cplen)
uc.reg_write(UC_ARM_REG_R3, 0x24)
# enable_vfp
uc.reg_write(UC_ARM_REG_C1_C0_2, uc.reg_read(UC_ARM_REG_C1_C0_2) | (0xf << 20))
uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)

uc.emu_start(base, base+len(shellcode))
fr = uc.mem_read(from_address, len(bs))
to = uc.mem_read(to_address, len(bs))
print(f"memcpy result:\nfrom: {bytes(fr)}\nto: {bytes(to)}")