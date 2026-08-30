#!/usr/bin/env python
# Correctness tests for Cavium Octeon (cnMIPS) instruction support on
# UC_CPU_MIPS64_OCTEON_PLUS: BBIT0/BBIT1/BBIT032/BBIT132, CINS/CINS32,
# EXTS/EXTS32, DMUL, SEQ/SNE, SEQI/SNEI, SAA/SAAD, BADDU, POP/DPOP.  Each
# test encodes a single instruction (terminated by `jr $ra`), runs it, and
# compares the result against the CN50XX HRM spec.

import struct
import sys

from unicorn import *
from unicorn.mips_const import *

CODE_ADDR = 0x10000
DATA_ADDR = CODE_ADDR + 0x800  # scratch, naturally aligned, in mapped page
RA_SENTINEL = 0xdeadbeef
U64_MASK = (1 << 64) - 1


def be32(words):
    return b"".join(struct.pack(">I", w) for w in words)


def run(words, init_regs=None, mem_writes=None):
    mu = Uc(UC_ARCH_MIPS, UC_MODE_64 | UC_MODE_BIG_ENDIAN)
    mu.ctl_set_cpu_model(UC_CPU_MIPS64_OCTEON_PLUS)
    mu.ctl_set_tlb_mode(UC_TLB_VIRTUAL)
    mu.mem_map(CODE_ADDR, 0x1000)
    mu.mem_write(CODE_ADDR, be32(words))
    for addr, data in (mem_writes or {}).items():
        mu.mem_write(addr, data)
    mu.reg_write(UC_MIPS_REG_RA, RA_SENTINEL)
    for reg, val in (init_regs or {}).items():
        mu.reg_write(reg, val & U64_MASK)
    mu.emu_start(CODE_ADDR, RA_SENTINEL)
    return mu


def special2(rs, rt, rd_or_msbf, sa_or_p, func):
    return ((0x1C << 26) | (rs << 21) | (rt << 16) |
            (rd_or_msbf << 11) | (sa_or_p << 6) | func)


def seqi_form(rs, rt, imm10, func):
    # 10-bit signed immediate sits in bits[15:6].
    return (0x1C << 26) | (rs << 21) | (rt << 16) | ((imm10 & 0x3FF) << 6) | func


def bbit_form(primary, rs, p, offset):
    return (primary << 26) | (rs << 21) | (p << 16) | (offset & 0xFFFF)


JR_RA = 0x03e00008
NOP = 0x00000000

A0, A1, V0 = 4, 5, 2


def reg(num):
    return UC_MIPS_REG_0 + num


FAILED = []


def check(name, want, got):
    if (want & U64_MASK) == (got & U64_MASK):
        print("PASS %s: 0x%016x" % (name, got))
    else:
        print("FAIL %s: want 0x%016x, got 0x%016x" % (name, want, got))
        FAILED.append(name)


# ---- SEQ / SNE ----

def t_seq():
    code = [special2(A0, A1, V0, 0, 0x2A), JR_RA, NOP]
    mu = run(code, {reg(A0): 0x1234, reg(A1): 0x1234})
    check("SEQ equal -> 1", 1, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): 0x1234, reg(A1): 0x5678})
    check("SEQ not-equal -> 0", 0, mu.reg_read(reg(V0)))


def t_sne():
    code = [special2(A0, A1, V0, 0, 0x2B), JR_RA, NOP]
    mu = run(code, {reg(A0): 0x1234, reg(A1): 0x1234})
    check("SNE equal -> 0", 0, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): 0x1234, reg(A1): 0x5678})
    check("SNE not-equal -> 1", 1, mu.reg_read(reg(V0)))


# ---- SEQI / SNEI: imm is 10-bit signed ----

def t_seqi():
    code = [seqi_form(A0, V0, 5, 0x2E), JR_RA, NOP]
    mu = run(code, {reg(A0): 5})
    check("SEQI ==imm -> 1", 1, mu.reg_read(reg(V0)))
    code = [seqi_form(A0, V0, -3 & 0x3FF, 0x2E), JR_RA, NOP]
    mu = run(code, {reg(A0): (-3) & U64_MASK})
    check("SEQI ==neg-imm -> 1", 1, mu.reg_read(reg(V0)))


def t_snei():
    code = [seqi_form(A0, V0, 5, 0x2F), JR_RA, NOP]
    mu = run(code, {reg(A0): 6})
    check("SNEI !=imm -> 1", 1, mu.reg_read(reg(V0)))


# ---- DMUL ----

def t_dmul():
    code = [special2(A0, A1, V0, 0, 0x03), JR_RA, NOP]
    mu = run(code, {reg(A0): 7, reg(A1): 11})
    check("DMUL 7*11", 77, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): (-3) & U64_MASK, reg(A1): 5})
    check("DMUL -3*5", (-15) & U64_MASK, mu.reg_read(reg(V0)))


# ---- CINS / CINS32 ----

def t_cins():
    # cins v0, a0, p=4, lenm1=7 -> (a0 & 0xff) << 4
    code = [special2(A0, V0, 7, 4, 0x32), JR_RA, NOP]
    mu = run(code, {reg(A0): 0xDEADBEEF})
    check("CINS p=4 lenm1=7", 0xEF << 4, mu.reg_read(reg(V0)))


def t_cins32():
    # cins32 v0, a0, p=4, lenm1=7 -> (a0 & 0xff) << (4+32)
    code = [special2(A0, V0, 7, 4, 0x33), JR_RA, NOP]
    mu = run(code, {reg(A0): 0xFF})
    check("CINS32 p=4 lenm1=7", 0xFF << 36, mu.reg_read(reg(V0)))


# ---- EXTS / EXTS32 ----

def t_exts():
    # exts v0, a0, p=4, lenm1=3 -> sign_extend(a0<7:4>, 4)
    code = [special2(A0, V0, 3, 4, 0x3A), JR_RA, NOP]
    mu = run(code, {reg(A0): 0xF0})
    check("EXTS p=4 lenm1=3 (sign)", (-1) & U64_MASK, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): 0x70})
    check("EXTS p=4 lenm1=3 (no sign)", 7, mu.reg_read(reg(V0)))


def t_exts32():
    # exts32 v0, a0, p=0, lenm1=7 -> sign_extend(a0<39:32>, 8)
    code = [special2(A0, V0, 7, 0, 0x3B), JR_RA, NOP]
    mu = run(code, {reg(A0): 0xFF << 32})
    check("EXTS32 p=0 lenm1=7", (-1) & U64_MASK, mu.reg_read(reg(V0)))


# ---- BBIT0 / BBIT1 / BBIT032 / BBIT132 ----
# Program layout:
#   0x00: bbit rs, p, +5        ; offset=5 -> target = 0x18
#   0x04: nop                    ; bbit delay slot
#   0x08: addiu v0, $0, 1       ; not-taken path
#   0x0c: jr $ra
#   0x10: nop                    ; jr delay slot
#   0x14: nop
#   0x18: addiu v0, $0, 2       ; taken path
#   0x1c: jr $ra
#   0x20: nop

def bbit_program(primary, p, rs):
    return [
        bbit_form(primary, rs, p, 5),
        NOP,
        0x24020001,
        JR_RA,
        NOP,
        NOP,
        0x24020002,
        JR_RA,
        NOP,
    ]


def t_bbit():
    # BBIT0 (primary 0x32): branch if rs<p> == 0
    code = bbit_program(0x32, p=3, rs=A0)
    mu = run(code, {reg(A0): 0})
    check("BBIT0 bit-clear taken", 2, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): 1 << 3})
    check("BBIT0 bit-set not-taken", 1, mu.reg_read(reg(V0)))

    # BBIT1 (primary 0x3A): branch if rs<p> == 1
    code = bbit_program(0x3A, p=3, rs=A0)
    mu = run(code, {reg(A0): 1 << 3})
    check("BBIT1 bit-set taken", 2, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): 0})
    check("BBIT1 bit-clear not-taken", 1, mu.reg_read(reg(V0)))

    # BBIT032 (primary 0x36): branch if rs<p+32> == 0
    code = bbit_program(0x36, p=3, rs=A0)
    mu = run(code, {reg(A0): 0})
    check("BBIT032 bit-clear taken", 2, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): 1 << (3 + 32)})
    check("BBIT032 bit-set not-taken", 1, mu.reg_read(reg(V0)))

    # BBIT132 (primary 0x3E): branch if rs<p+32> == 1
    code = bbit_program(0x3E, p=3, rs=A0)
    mu = run(code, {reg(A0): 1 << (3 + 32)})
    check("BBIT132 bit-set taken", 2, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): 0})
    check("BBIT132 bit-clear not-taken", 1, mu.reg_read(reg(V0)))


# ---- SAA / SAAD: store-atomic-add to memory ----

def t_saa():
    # saa a1, (a0): mem32[a0] += a1<31:0>
    code = [special2(A0, A1, 0, 0, 0x18), JR_RA, NOP]
    mu = run(code, {reg(A0): DATA_ADDR, reg(A1): 0x11111111},
             {DATA_ADDR: struct.pack(">I", 0x22222222)})
    got = struct.unpack(">I", mu.mem_read(DATA_ADDR, 4))[0]
    check("SAA add word", 0x33333333, got)
    # 32-bit wrap: 0xFFFFFFFF + 1 -> 0, and only the word is touched
    mu = run(code, {reg(A0): DATA_ADDR, reg(A1): 1},
             {DATA_ADDR: struct.pack(">II", 0xFFFFFFFF, 0xAABBCCDD)})
    lo, hi = struct.unpack(">II", mu.mem_read(DATA_ADDR, 8))
    check("SAA word wrap", 0, lo)
    check("SAA leaves next word", 0xAABBCCDD, hi)


def t_saad():
    # saad a1, (a0): mem64[a0] += a1<63:0>
    code = [special2(A0, A1, 0, 0, 0x19), JR_RA, NOP]
    mu = run(code, {reg(A0): DATA_ADDR, reg(A1): 0x1111111122222222},
             {DATA_ADDR: struct.pack(">Q", 0x2222222233333333)})
    got = struct.unpack(">Q", mu.mem_read(DATA_ADDR, 8))[0]
    check("SAAD add dword", 0x3333333355555555, got)


# ---- BADDU: rd = (rs + rt) & 0xff ----

def t_baddu():
    code = [special2(A0, A1, V0, 0, 0x28), JR_RA, NOP]
    mu = run(code, {reg(A0): 0x40, reg(A1): 0x05})
    check("BADDU 0x40+5", 0x45, mu.reg_read(reg(V0)))
    # carry out of byte is discarded: 0x1FF + 2 = 0x201 -> 0x01
    mu = run(code, {reg(A0): 0x1FF, reg(A1): 0x02})
    check("BADDU byte truncation", 0x01, mu.reg_read(reg(V0)))


# ---- POP / DPOP: population count ----

def t_pop():
    # pop v0, a0 -> popcount(a0<31:0>)
    code = [special2(A0, 0, V0, 0, 0x2C), JR_RA, NOP]
    mu = run(code, {reg(A0): 0xF0F0F0F0})
    check("POP low32", 16, mu.reg_read(reg(V0)))
    # upper 32 bits are ignored
    mu = run(code, {reg(A0): 0xFFFFFFFF00000001})
    check("POP ignores upper32", 1, mu.reg_read(reg(V0)))


def t_dpop():
    # dpop v0, a0 -> popcount(a0<63:0>)
    code = [special2(A0, 0, V0, 0, 0x2D), JR_RA, NOP]
    mu = run(code, {reg(A0): 0xFFFFFFFF00000001})
    check("DPOP all64", 33, mu.reg_read(reg(V0)))
    mu = run(code, {reg(A0): 0})
    check("DPOP zero", 0, mu.reg_read(reg(V0)))


# ---- rdhwr $31: Octeon CvmCount free-running cycle counter ----

def rdhwr(rt, rd):
    # SPECIAL3 (0x1F) | rt | rd | funct 0x3B
    return (0x1F << 26) | (rt << 16) | (rd << 11) | 0x3B


def t_rdhwr_cvmcount():
    # rdhwr v0,$31 ; rdhwr v1,$31 : hardware register 31 is a monotonically
    # advancing cycle counter (no fault, and each read is strictly greater).
    code = [rdhwr(V0, 31), rdhwr(A1, 31), JR_RA, NOP]
    mu = run(code)
    first = mu.reg_read(reg(V0))
    second = mu.reg_read(reg(A1))
    check("CvmCount first read nonzero", True, first > 0)
    check("CvmCount advances", True, second > first)


if __name__ == '__main__':
    for fn in (t_seq, t_sne, t_seqi, t_snei, t_dmul,
               t_cins, t_cins32, t_exts, t_exts32, t_bbit,
               t_saa, t_saad, t_baddu, t_pop, t_dpop,
               t_rdhwr_cvmcount):
        fn()
    if FAILED:
        print("FAILURES: %s" % ", ".join(FAILED))
        sys.exit(1)
    print("All Octeon tests passed.")
