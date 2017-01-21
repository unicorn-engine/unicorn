/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008-2009 Arnaud Patard <arnaud.patard@rtp-net.org>
 * Copyright (c) 2009 Aurelien Jarno <aurelien@aurel32.net>
 * Based on i386/tcg-target.c - Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "tcg-be-ldst.h"

#ifdef HOST_WORDS_BIGENDIAN
# define MIPS_BE  1
#else
# define MIPS_BE  0
#endif

#define LO_OFF    (MIPS_BE * 4)
#define HI_OFF    (4 - LO_OFF)

#ifndef NDEBUG
static const char * const tcg_target_reg_names[TCG_TARGET_NB_REGS] = {
    "zero",
    "at",
    "v0",
    "v1",
    "a0",
    "a1",
    "a2",
    "a3",
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "t7",
    "s0",
    "s1",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "t8",
    "t9",
    "k0",
    "k1",
    "gp",
    "sp",
    "s8",
    "ra",
};
#endif

#define TCG_TMP0  TCG_REG_AT
#define TCG_TMP1  TCG_REG_T9

/* check if we really need so many registers :P */
static const TCGReg tcg_target_reg_alloc_order[] = {
    /* Call saved registers.  */
    TCG_REG_S0,
    TCG_REG_S1,
    TCG_REG_S2,
    TCG_REG_S3,
    TCG_REG_S4,
    TCG_REG_S5,
    TCG_REG_S6,
    TCG_REG_S7,
    TCG_REG_S8,

    /* Call clobbered registers.  */
    TCG_REG_T0,
    TCG_REG_T1,
    TCG_REG_T2,
    TCG_REG_T3,
    TCG_REG_T4,
    TCG_REG_T5,
    TCG_REG_T6,
    TCG_REG_T7,
    TCG_REG_T8,
    TCG_REG_T9,
    TCG_REG_V1,
    TCG_REG_V0,

    /* Argument registers, opposite order of allocation.  */
    TCG_REG_A3,
    TCG_REG_A2,
    TCG_REG_A1,
    TCG_REG_A0,
};

static const TCGReg tcg_target_call_iarg_regs[4] = {
    TCG_REG_A0,
    TCG_REG_A1,
    TCG_REG_A2,
    TCG_REG_A3
};

static const TCGReg tcg_target_call_oarg_regs[2] = {
    TCG_REG_V0,
    TCG_REG_V1
};

static tcg_insn_unit *tb_ret_addr;

static inline uint32_t reloc_pc16_val(tcg_insn_unit *pc, tcg_insn_unit *target)
{
    /* Let the compiler perform the right-shift as part of the arithmetic.  */
    ptrdiff_t disp = target - (pc + 1);
    assert(disp == (int16_t)disp);
    return disp & 0xffff;
}

static inline void reloc_pc16(tcg_insn_unit *pc, tcg_insn_unit *target)
{
    *pc = deposit32(*pc, 0, 16, reloc_pc16_val(pc, target));
}

static inline uint32_t reloc_26_val(tcg_insn_unit *pc, tcg_insn_unit *target)
{
    assert((((uintptr_t)pc ^ (uintptr_t)target) & 0xf0000000) == 0);
    return ((uintptr_t)target >> 2) & 0x3ffffff;
}

static inline void reloc_26(tcg_insn_unit *pc, tcg_insn_unit *target)
{
    *pc = deposit32(*pc, 0, 26, reloc_26_val(pc, target));
}

static void patch_reloc(tcg_insn_unit *code_ptr, int type,
                        intptr_t value, intptr_t addend)
{
    assert(type == R_MIPS_PC16);
    assert(addend == 0);
    reloc_pc16(code_ptr, (tcg_insn_unit *)value);
}

#define TCG_CT_CONST_ZERO 0x100
#define TCG_CT_CONST_U16  0x200    /* Unsigned 16-bit: 0 - 0xffff.  */
#define TCG_CT_CONST_S16  0x400    /* Signed 16-bit: -32768 - 32767 */
#define TCG_CT_CONST_P2M1 0x800    /* Power of 2 minus 1.  */
#define TCG_CT_CONST_N16  0x1000   /* "Negatable" 16-bit: -32767 - 32767 */

static inline bool is_p2m1(tcg_target_long val)
{
    return val && ((val + 1) & val) == 0;
}

/* parse target specific constraints */
static int target_parse_constraint(TCGArgConstraint *ct, const char **pct_str)
{
    const char *ct_str;

    ct_str = *pct_str;
    switch(ct_str[0]) {
    case 'r':
        ct->ct |= TCG_CT_REG;
        tcg_regset_set(ct->u.regs, 0xffffffff);
        break;
    case 'L': /* qemu_ld output arg constraint */
        ct->ct |= TCG_CT_REG;
        tcg_regset_set(ct->u.regs, 0xffffffff);
        tcg_regset_reset_reg(ct->u.regs, TCG_REG_V0);
        break;
    case 'l': /* qemu_ld input arg constraint */
        ct->ct |= TCG_CT_REG;
        tcg_regset_set(ct->u.regs, 0xffffffff);
        tcg_regset_reset_reg(ct->u.regs, TCG_REG_A0);
#if defined(CONFIG_SOFTMMU)
        if (TARGET_LONG_BITS == 64) {
            tcg_regset_reset_reg(ct->u.regs, TCG_REG_A2);
        }
#endif
        break;
    case 'S': /* qemu_st constraint */
        ct->ct |= TCG_CT_REG;
        tcg_regset_set(ct->u.regs, 0xffffffff);
        tcg_regset_reset_reg(ct->u.regs, TCG_REG_A0);
#if defined(CONFIG_SOFTMMU)
        if (TARGET_LONG_BITS == 32) {
            tcg_regset_reset_reg(ct->u.regs, TCG_REG_A1);
        } else {
            tcg_regset_reset_reg(ct->u.regs, TCG_REG_A2);
            tcg_regset_reset_reg(ct->u.regs, TCG_REG_A3);
        }
#endif
        break;
    case 'I':
        ct->ct |= TCG_CT_CONST_U16;
        break;
    case 'J':
        ct->ct |= TCG_CT_CONST_S16;
        break;
    case 'K':
        ct->ct |= TCG_CT_CONST_P2M1;
        break;
    case 'N':
        ct->ct |= TCG_CT_CONST_N16;
        break;
    case 'Z':
        /* We are cheating a bit here, using the fact that the register
           ZERO is also the register number 0. Hence there is no need
           to check for const_args in each instruction. */
        ct->ct |= TCG_CT_CONST_ZERO;
        break;
    default:
        return -1;
    }
    ct_str++;
    *pct_str = ct_str;
    return 0;
}

/* test if a constant matches the constraint */
static inline int tcg_target_const_match(tcg_target_long val, TCGType type,
                                         const TCGArgConstraint *arg_ct)
{
    int ct;
    ct = arg_ct->ct;
    if (ct & TCG_CT_CONST) {
        return 1;
    } else if ((ct & TCG_CT_CONST_ZERO) && val == 0) {
        return 1;
    } else if ((ct & TCG_CT_CONST_U16) && val == (uint16_t)val) {
        return 1;
    } else if ((ct & TCG_CT_CONST_S16) && val == (int16_t)val) {
        return 1;
    } else if ((ct & TCG_CT_CONST_N16) && val >= -32767 && val <= 32767) {
        return 1;
    } else if ((ct & TCG_CT_CONST_P2M1)
               && use_mips32r2_instructions && is_p2m1(val)) {
        return 1;
    }
    return 0;
}

/* instruction opcodes */
typedef enum {
    OPC_J        = 0x02 << 26,
    OPC_JAL      = 0x03 << 26,
    OPC_BEQ      = 0x04 << 26,
    OPC_BNE      = 0x05 << 26,
    OPC_BLEZ     = 0x06 << 26,
    OPC_BGTZ     = 0x07 << 26,
    OPC_ADDIU    = 0x09 << 26,
    OPC_SLTI     = 0x0A << 26,
    OPC_SLTIU    = 0x0B << 26,
    OPC_ANDI     = 0x0C << 26,
    OPC_ORI      = 0x0D << 26,
    OPC_XORI     = 0x0E << 26,
    OPC_LUI      = 0x0F << 26,
    OPC_LB       = 0x20 << 26,
    OPC_LH       = 0x21 << 26,
    OPC_LW       = 0x23 << 26,
    OPC_LBU      = 0x24 << 26,
    OPC_LHU      = 0x25 << 26,
    OPC_LWU      = 0x27 << 26,
    OPC_SB       = 0x28 << 26,
    OPC_SH       = 0x29 << 26,
    OPC_SW       = 0x2B << 26,

    OPC_SPECIAL  = 0x00 << 26,
    OPC_SLL      = OPC_SPECIAL | 0x00,
    OPC_SRL      = OPC_SPECIAL | 0x02,
    OPC_ROTR     = OPC_SPECIAL | (0x01 << 21) | 0x02,
    OPC_SRA      = OPC_SPECIAL | 0x03,
    OPC_SLLV     = OPC_SPECIAL | 0x04,
    OPC_SRLV     = OPC_SPECIAL | 0x06,
    OPC_ROTRV    = OPC_SPECIAL | (0x01 <<  6) | 0x06,
    OPC_SRAV     = OPC_SPECIAL | 0x07,
    OPC_JR       = OPC_SPECIAL | 0x08,
    OPC_JALR     = OPC_SPECIAL | 0x09,
    OPC_MOVZ     = OPC_SPECIAL | 0x0A,
    OPC_MOVN     = OPC_SPECIAL | 0x0B,
    OPC_MFHI     = OPC_SPECIAL | 0x10,
    OPC_MFLO     = OPC_SPECIAL | 0x12,
    OPC_MULT     = OPC_SPECIAL | 0x18,
    OPC_MULTU    = OPC_SPECIAL | 0x19,
    OPC_DIV      = OPC_SPECIAL | 0x1A,
    OPC_DIVU     = OPC_SPECIAL | 0x1B,
    OPC_ADDU     = OPC_SPECIAL | 0x21,
    OPC_SUBU     = OPC_SPECIAL | 0x23,
    OPC_AND      = OPC_SPECIAL | 0x24,
    OPC_OR       = OPC_SPECIAL | 0x25,
    OPC_XOR      = OPC_SPECIAL | 0x26,
    OPC_NOR      = OPC_SPECIAL | 0x27,
    OPC_SLT      = OPC_SPECIAL | 0x2A,
    OPC_SLTU     = OPC_SPECIAL | 0x2B,

    OPC_REGIMM   = 0x01 << 26,
    OPC_BLTZ     = OPC_REGIMM | (0x00 << 16),
    OPC_BGEZ     = OPC_REGIMM | (0x01 << 16),

    OPC_SPECIAL2 = 0x1c << 26,
    OPC_MUL      = OPC_SPECIAL2 | 0x002,

    OPC_SPECIAL3 = 0x1f << 26,
    OPC_EXT      = OPC_SPECIAL3 | 0x000,
    OPC_INS      = OPC_SPECIAL3 | 0x004,
    OPC_WSBH     = OPC_SPECIAL3 | 0x0a0,
    OPC_SEB      = OPC_SPECIAL3 | 0x420,
    OPC_SEH      = OPC_SPECIAL3 | 0x620,
} MIPSInsn;

/*
 * Type reg
 */
static inline void tcg_out_opc_reg(TCGContext *s, MIPSInsn opc,
                                   TCGReg rd, TCGReg rs, TCGReg rt)
{
    int32_t inst;

    inst = opc;
    inst |= (rs & 0x1F) << 21;
    inst |= (rt & 0x1F) << 16;
    inst |= (rd & 0x1F) << 11;
    tcg_out32(s, inst);
}

/*
 * Type immediate
 */
static inline void tcg_out_opc_imm(TCGContext *s, MIPSInsn opc,
                                   TCGReg rt, TCGReg rs, TCGArg imm)
{
    int32_t inst;

    inst = opc;
    inst |= (rs & 0x1F) << 21;
    inst |= (rt & 0x1F) << 16;
    inst |= (imm & 0xffff);
    tcg_out32(s, inst);
}

/*
 * Type bitfield
 */
static inline void tcg_out_opc_bf(TCGContext *s, MIPSInsn opc, TCGReg rt,
                                  TCGReg rs, int msb, int lsb)
{
    int32_t inst;

    inst = opc;
    inst |= (rs & 0x1F) << 21;
    inst |= (rt & 0x1F) << 16;
    inst |= (msb & 0x1F) << 11;
    inst |= (lsb & 0x1F) << 6;
    tcg_out32(s, inst);
}

/*
 * Type branch
 */
static inline void tcg_out_opc_br(TCGContext *s, MIPSInsn opc,
                                  TCGReg rt, TCGReg rs)
{
    /* We pay attention here to not modify the branch target by reading
       the existing value and using it again. This ensure that caches and
       memory are kept coherent during retranslation. */
    uint16_t offset = (uint16_t)*s->code_ptr;

    tcg_out_opc_imm(s, opc, rt, rs, offset);
}

/*
 * Type sa
 */
static inline void tcg_out_opc_sa(TCGContext *s, MIPSInsn opc,
                                  TCGReg rd, TCGReg rt, TCGArg sa)
{
    int32_t inst;

    inst = opc;
    inst |= (rt & 0x1F) << 16;
    inst |= (rd & 0x1F) << 11;
    inst |= (sa & 0x1F) <<  6;
    tcg_out32(s, inst);

}

/*
 * Type jump.
 * Returns true if the branch was in range and the insn was emitted.
 */
static bool tcg_out_opc_jmp(TCGContext *s, MIPSInsn opc, void *target)
{
    uintptr_t dest = (uintptr_t)target;
    uintptr_t from = (uintptr_t)s->code_ptr + 4;
    int32_t inst;

    /* The pc-region branch happens within the 256MB region of
       the delay slot (thus the +4).  */
    if ((from ^ dest) & -(1 << 28)) {
        return false;
    }
    assert((dest & 3) == 0);

    inst = opc;
    inst |= (dest >> 2) & 0x3ffffff;
    tcg_out32(s, inst);
    return true;
}

static inline void tcg_out_nop(TCGContext *s)
{
    tcg_out32(s, 0);
}

static inline void tcg_out_mov(TCGContext *s, TCGType type,
                               TCGReg ret, TCGReg arg)
{
    /* Simple reg-reg move, optimising out the 'do nothing' case */
    if (ret != arg) {
        tcg_out_opc_reg(s, OPC_ADDU, ret, arg, TCG_REG_ZERO);
    }
}

static inline void tcg_out_movi(TCGContext *s, TCGType type,
                                TCGReg reg, tcg_target_long arg)
{
    if (arg == (int16_t)arg) {
        tcg_out_opc_imm(s, OPC_ADDIU, reg, TCG_REG_ZERO, arg);
    } else if (arg == (uint16_t)arg) {
        tcg_out_opc_imm(s, OPC_ORI, reg, TCG_REG_ZERO, arg);
    } else {
        tcg_out_opc_imm(s, OPC_LUI, reg, TCG_REG_ZERO, arg >> 16);
        if (arg & 0xffff) {
            tcg_out_opc_imm(s, OPC_ORI, reg, reg, arg & 0xffff);
        }
    }
}

static inline void tcg_out_bswap16(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (use_mips32r2_instructions) {
        tcg_out_opc_reg(s, OPC_WSBH, ret, 0, arg);
    } else {
        /* ret and arg can't be register at */
        if (ret == TCG_TMP0 || arg == TCG_TMP0) {
            tcg_abort();
        }

        tcg_out_opc_sa(s, OPC_SRL, TCG_TMP0, arg, 8);
        tcg_out_opc_sa(s, OPC_SLL, ret, arg, 8);
        tcg_out_opc_imm(s, OPC_ANDI, ret, ret, 0xff00);
        tcg_out_opc_reg(s, OPC_OR, ret, ret, TCG_TMP0);
    }
}

static inline void tcg_out_bswap16s(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (use_mips32r2_instructions) {
        tcg_out_opc_reg(s, OPC_WSBH, ret, 0, arg);
        tcg_out_opc_reg(s, OPC_SEH, ret, 0, ret);
    } else {
        /* ret and arg can't be register at */
        if (ret == TCG_TMP0 || arg == TCG_TMP0) {
            tcg_abort();
        }

        tcg_out_opc_sa(s, OPC_SRL, TCG_TMP0, arg, 8);
        tcg_out_opc_sa(s, OPC_SLL, ret, arg, 24);
        tcg_out_opc_sa(s, OPC_SRA, ret, ret, 16);
        tcg_out_opc_reg(s, OPC_OR, ret, ret, TCG_TMP0);
    }
}

static inline void tcg_out_bswap32(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (use_mips32r2_instructions) {
        tcg_out_opc_reg(s, OPC_WSBH, ret, 0, arg);
        tcg_out_opc_sa(s, OPC_ROTR, ret, ret, 16);
    } else {
        /* ret and arg must be different and can't be register at */
        if (ret == arg || ret == TCG_TMP0 || arg == TCG_TMP0) {
            tcg_abort();
        }

        tcg_out_opc_sa(s, OPC_SLL, ret, arg, 24);

        tcg_out_opc_sa(s, OPC_SRL, TCG_TMP0, arg, 24);
        tcg_out_opc_reg(s, OPC_OR, ret, ret, TCG_TMP0);

        tcg_out_opc_imm(s, OPC_ANDI, TCG_TMP0, arg, 0xff00);
        tcg_out_opc_sa(s, OPC_SLL, TCG_TMP0, TCG_TMP0, 8);
        tcg_out_opc_reg(s, OPC_OR, ret, ret, TCG_TMP0);

        tcg_out_opc_sa(s, OPC_SRL, TCG_TMP0, arg, 8);
        tcg_out_opc_imm(s, OPC_ANDI, TCG_TMP0, TCG_TMP0, 0xff00);
        tcg_out_opc_reg(s, OPC_OR, ret, ret, TCG_TMP0);
    }
}

static inline void tcg_out_ext8s(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (use_mips32r2_instructions) {
        tcg_out_opc_reg(s, OPC_SEB, ret, 0, arg);
    } else {
        tcg_out_opc_sa(s, OPC_SLL, ret, arg, 24);
        tcg_out_opc_sa(s, OPC_SRA, ret, ret, 24);
    }
}

static inline void tcg_out_ext16s(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (use_mips32r2_instructions) {
        tcg_out_opc_reg(s, OPC_SEH, ret, 0, arg);
    } else {
        tcg_out_opc_sa(s, OPC_SLL, ret, arg, 16);
        tcg_out_opc_sa(s, OPC_SRA, ret, ret, 16);
    }
}

static void tcg_out_ldst(TCGContext *s, MIPSInsn opc, TCGReg data,
                         TCGReg addr, intptr_t ofs)
{
    int16_t lo = ofs;
    if (ofs != lo) {
        tcg_out_movi(s, TCG_TYPE_PTR, TCG_TMP0, ofs - lo);
        if (addr != TCG_REG_ZERO) {
            tcg_out_opc_reg(s, OPC_ADDU, TCG_TMP0, TCG_TMP0, addr);
        }
        addr = TCG_TMP0;
    }
    tcg_out_opc_imm(s, opc, data, addr, lo);
}

static inline void tcg_out_ld(TCGContext *s, TCGType type, TCGReg arg,
                              TCGReg arg1, intptr_t arg2)
{
    tcg_out_ldst(s, OPC_LW, arg, arg1, arg2);
}

static inline void tcg_out_st(TCGContext *s, TCGType type, TCGReg arg,
                              TCGReg arg1, intptr_t arg2)
{
    tcg_out_ldst(s, OPC_SW, arg, arg1, arg2);
}

static inline void tcg_out_addi(TCGContext *s, TCGReg reg, TCGArg val)
{
    if (val == (int16_t)val) {
        tcg_out_opc_imm(s, OPC_ADDIU, reg, reg, val);
    } else {
        tcg_out_movi(s, TCG_TYPE_PTR, TCG_TMP0, val);
        tcg_out_opc_reg(s, OPC_ADDU, reg, reg, TCG_TMP0);
    }
}

/* Bit 0 set if inversion required; bit 1 set if swapping required.  */
#define MIPS_CMP_INV  1
#define MIPS_CMP_SWAP 2

static const uint8_t mips_cmp_map[16] = {
    [TCG_COND_LT]  = 0,
    [TCG_COND_LTU] = 0,
    [TCG_COND_GE]  = MIPS_CMP_INV,
    [TCG_COND_GEU] = MIPS_CMP_INV,
    [TCG_COND_LE]  = MIPS_CMP_INV | MIPS_CMP_SWAP,
    [TCG_COND_LEU] = MIPS_CMP_INV | MIPS_CMP_SWAP,
    [TCG_COND_GT]  = MIPS_CMP_SWAP,
    [TCG_COND_GTU] = MIPS_CMP_SWAP,
};

static void tcg_out_setcond(TCGContext *s, TCGCond cond, TCGReg ret,
                            TCGReg arg1, TCGReg arg2)
{
    MIPSInsn s_opc = OPC_SLTU;
    int cmp_map;

    switch (cond) {
    case TCG_COND_EQ:
        if (arg2 != 0) {
            tcg_out_opc_reg(s, OPC_XOR, ret, arg1, arg2);
            arg1 = ret;
        }
        tcg_out_opc_imm(s, OPC_SLTIU, ret, arg1, 1);
        break;

    case TCG_COND_NE:
        if (arg2 != 0) {
            tcg_out_opc_reg(s, OPC_XOR, ret, arg1, arg2);
            arg1 = ret;
        }
        tcg_out_opc_reg(s, OPC_SLTU, ret, TCG_REG_ZERO, arg1);
        break;

    case TCG_COND_LT:
    case TCG_COND_GE:
    case TCG_COND_LE:
    case TCG_COND_GT:
        s_opc = OPC_SLT;
        /* FALLTHRU */

    case TCG_COND_LTU:
    case TCG_COND_GEU:
    case TCG_COND_LEU:
    case TCG_COND_GTU:
        cmp_map = mips_cmp_map[cond];
        if (cmp_map & MIPS_CMP_SWAP) {
            TCGReg t = arg1;
            arg1 = arg2;
            arg2 = t;
        }
        tcg_out_opc_reg(s, s_opc, ret, arg1, arg2);
        if (cmp_map & MIPS_CMP_INV) {
            tcg_out_opc_imm(s, OPC_XORI, ret, ret, 1);
        }
        break;

     default:
         tcg_abort();
         break;
     }
}

static void tcg_out_brcond(TCGContext *s, TCGCond cond, TCGReg arg1,
                           TCGReg arg2, int label_index)
{
    static const MIPSInsn b_zero[16] = {
        [TCG_COND_LT] = OPC_BLTZ,
        [TCG_COND_GT] = OPC_BGTZ,
        [TCG_COND_LE] = OPC_BLEZ,
        [TCG_COND_GE] = OPC_BGEZ,
    };

    TCGLabel *l;
    MIPSInsn s_opc = OPC_SLTU;
    MIPSInsn b_opc;
    int cmp_map;

    switch (cond) {
    case TCG_COND_EQ:
        b_opc = OPC_BEQ;
        break;
    case TCG_COND_NE:
        b_opc = OPC_BNE;
        break;

    case TCG_COND_LT:
    case TCG_COND_GT:
    case TCG_COND_LE:
    case TCG_COND_GE:
        if (arg2 == 0) {
            b_opc = b_zero[cond];
            arg2 = arg1;
            arg1 = 0;
            break;
        }
        s_opc = OPC_SLT;
        /* FALLTHRU */

    case TCG_COND_LTU:
    case TCG_COND_GTU:
    case TCG_COND_LEU:
    case TCG_COND_GEU:
        cmp_map = mips_cmp_map[cond];
        if (cmp_map & MIPS_CMP_SWAP) {
            TCGReg t = arg1;
            arg1 = arg2;
            arg2 = t;
        }
        tcg_out_opc_reg(s, s_opc, TCG_TMP0, arg1, arg2);
        b_opc = (cmp_map & MIPS_CMP_INV ? OPC_BEQ : OPC_BNE);
        arg1 = TCG_TMP0;
        arg2 = TCG_REG_ZERO;
        break;

    default:
        tcg_abort();
        break;
    }

    tcg_out_opc_br(s, b_opc, arg1, arg2);
    l = &s->labels[label_index];
    if (l->has_value) {
        reloc_pc16(s->code_ptr - 1, l->u.value_ptr);
    } else {
        tcg_out_reloc(s, s->code_ptr - 1, R_MIPS_PC16, label_index, 0);
    }
    tcg_out_nop(s);
}

static TCGReg tcg_out_reduce_eq2(TCGContext *s, TCGReg tmp0, TCGReg tmp1,
                                 TCGReg al, TCGReg ah,
                                 TCGReg bl, TCGReg bh)
{
    /* Merge highpart comparison into AH.  */
    if (bh != 0) {
        if (ah != 0) {
            tcg_out_opc_reg(s, OPC_XOR, tmp0, ah, bh);
            ah = tmp0;
        } else {
            ah = bh;
        }
    }
    /* Merge lowpart comparison into AL.  */
    if (bl != 0) {
        if (al != 0) {
            tcg_out_opc_reg(s, OPC_XOR, tmp1, al, bl);
            al = tmp1;
        } else {
            al = bl;
        }
    }
    /* Merge high and low part comparisons into AL.  */
    if (ah != 0) {
        if (al != 0) {
            tcg_out_opc_reg(s, OPC_OR, tmp0, ah, al);
            al = tmp0;
        } else {
            al = ah;
        }
    }
    return al;
}

static void tcg_out_setcond2(TCGContext *s, TCGCond cond, TCGReg ret,
                             TCGReg al, TCGReg ah, TCGReg bl, TCGReg bh)
{
    TCGReg tmp0 = TCG_TMP0;
    TCGReg tmp1 = ret;

    assert(ret != TCG_TMP0);
    if (ret == ah || ret == bh) {
        assert(ret != TCG_TMP1);
        tmp1 = TCG_TMP1;
    }

    switch (cond) {
    case TCG_COND_EQ:
    case TCG_COND_NE:
        tmp1 = tcg_out_reduce_eq2(s, tmp0, tmp1, al, ah, bl, bh);
        tcg_out_setcond(s, cond, ret, tmp1, TCG_REG_ZERO);
        break;

    default:
        tcg_out_setcond(s, TCG_COND_EQ, tmp0, ah, bh);
        tcg_out_setcond(s, tcg_unsigned_cond(cond), tmp1, al, bl);
        tcg_out_opc_reg(s, OPC_AND, tmp1, tmp1, tmp0);
        tcg_out_setcond(s, tcg_high_cond(cond), tmp0, ah, bh);
        tcg_out_opc_reg(s, OPC_OR, ret, tmp1, tmp0);
        break;
    }
}

static void tcg_out_brcond2(TCGContext *s, TCGCond cond, TCGReg al, TCGReg ah,
                            TCGReg bl, TCGReg bh, int label_index)
{
    TCGCond b_cond = TCG_COND_NE;
    TCGReg tmp = TCG_TMP1;

    /* With branches, we emit between 4 and 9 insns with 2 or 3 branches.
       With setcond, we emit between 3 and 10 insns and only 1 branch,
       which ought to get better branch prediction.  */
     switch (cond) {
     case TCG_COND_EQ:
     case TCG_COND_NE:
        b_cond = cond;
        tmp = tcg_out_reduce_eq2(s, TCG_TMP0, TCG_TMP1, al, ah, bl, bh);
        break;

    default:
        /* Minimize code size by preferring a compare not requiring INV.  */
        if (mips_cmp_map[cond] & MIPS_CMP_INV) {
            cond = tcg_invert_cond(cond);
            b_cond = TCG_COND_EQ;
        }
        tcg_out_setcond2(s, cond, tmp, al, ah, bl, bh);
        break;
    }

    tcg_out_brcond(s, b_cond, tmp, TCG_REG_ZERO, label_index);
}

static void tcg_out_movcond(TCGContext *s, TCGCond cond, TCGReg ret,
                            TCGReg c1, TCGReg c2, TCGReg v)
{
    MIPSInsn m_opc = OPC_MOVN;

    switch (cond) {
    case TCG_COND_EQ:
        m_opc = OPC_MOVZ;
        /* FALLTHRU */
    case TCG_COND_NE:
        if (c2 != 0) {
            tcg_out_opc_reg(s, OPC_XOR, TCG_TMP0, c1, c2);
            c1 = TCG_TMP0;
        }
        break;

    default:
        /* Minimize code size by preferring a compare not requiring INV.  */
        if (mips_cmp_map[cond] & MIPS_CMP_INV) {
            cond = tcg_invert_cond(cond);
            m_opc = OPC_MOVZ;
        }
        tcg_out_setcond(s, cond, TCG_TMP0, c1, c2);
        c1 = TCG_TMP0;
        break;
    }

    tcg_out_opc_reg(s, m_opc, ret, v, c1);
}

static void tcg_out_call_int(TCGContext *s, tcg_insn_unit *arg, bool tail)
{
    /* Note that the ABI requires the called function's address to be
       loaded into T9, even if a direct branch is in range.  */
    tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_T9, (uintptr_t)arg);

    /* But do try a direct branch, allowing the cpu better insn prefetch.  */
    if (tail) {
        if (!tcg_out_opc_jmp(s, OPC_J, arg)) {
            tcg_out_opc_reg(s, OPC_JR, 0, TCG_REG_T9, 0);
        }
    } else {
        if (!tcg_out_opc_jmp(s, OPC_JAL, arg)) {
            tcg_out_opc_reg(s, OPC_JALR, TCG_REG_RA, TCG_REG_T9, 0);
        }
    }
}

static void tcg_out_call(TCGContext *s, tcg_insn_unit *arg)
{
    tcg_out_call_int(s, arg, false);
    tcg_out_nop(s);
}

#if defined(CONFIG_SOFTMMU)
static void * const qemu_ld_helpers[16] = {
    [MO_UB]   = helper_ret_ldub_mmu,
    [MO_SB]   = helper_ret_ldsb_mmu,
    [MO_LEUW] = helper_le_lduw_mmu,
    [MO_LESW] = helper_le_ldsw_mmu,
    [MO_LEUL] = helper_le_ldul_mmu,
    [MO_LEQ]  = helper_le_ldq_mmu,
    [MO_BEUW] = helper_be_lduw_mmu,
    [MO_BESW] = helper_be_ldsw_mmu,
    [MO_BEUL] = helper_be_ldul_mmu,
    [MO_BEQ]  = helper_be_ldq_mmu,
};

static void * const qemu_st_helpers[16] = {
    [MO_UB]   = helper_ret_stb_mmu,
    [MO_LEUW] = helper_le_stw_mmu,
    [MO_LEUL] = helper_le_stl_mmu,
    [MO_LEQ]  = helper_le_stq_mmu,
    [MO_BEUW] = helper_be_stw_mmu,
    [MO_BEUL] = helper_be_stl_mmu,
    [MO_BEQ]  = helper_be_stq_mmu,
};

/* Helper routines for marshalling helper function arguments into
 * the correct registers and stack.
 * I is where we want to put this argument, and is updated and returned
 * for the next call. ARG is the argument itself.
 *
 * We provide routines for arguments which are: immediate, 32 bit
 * value in register, 16 and 8 bit values in register (which must be zero
 * extended before use) and 64 bit value in a lo:hi register pair.
 */

static int tcg_out_call_iarg_reg(TCGContext *s, int i, TCGReg arg)
{
    if (i < ARRAY_SIZE(tcg_target_call_iarg_regs)) {
        tcg_out_mov(s, TCG_TYPE_REG, tcg_target_call_iarg_regs[i], arg);
    } else {
        tcg_out_st(s, TCG_TYPE_REG, arg, TCG_REG_SP, 4 * i);
    }
    return i + 1;
}

static int tcg_out_call_iarg_reg8(TCGContext *s, int i, TCGReg arg)
{
    TCGReg tmp = TCG_TMP0;
    if (i < ARRAY_SIZE(tcg_target_call_iarg_regs)) {
        tmp = tcg_target_call_iarg_regs[i];
    }
    tcg_out_opc_imm(s, OPC_ANDI, tmp, arg, 0xff);
    return tcg_out_call_iarg_reg(s, i, tmp);
}

static int tcg_out_call_iarg_reg16(TCGContext *s, int i, TCGReg arg)
{
    TCGReg tmp = TCG_TMP0;
    if (i < ARRAY_SIZE(tcg_target_call_iarg_regs)) {
        tmp = tcg_target_call_iarg_regs[i];
    }
    tcg_out_opc_imm(s, OPC_ANDI, tmp, arg, 0xffff);
    return tcg_out_call_iarg_reg(s, i, tmp);
}

static int tcg_out_call_iarg_imm(TCGContext *s, int i, TCGArg arg)
{
    TCGReg tmp = TCG_TMP0;
    if (arg == 0) {
        tmp = TCG_REG_ZERO;
    } else {
        if (i < ARRAY_SIZE(tcg_target_call_iarg_regs)) {
            tmp = tcg_target_call_iarg_regs[i];
        }
        tcg_out_movi(s, TCG_TYPE_REG, tmp, arg);
    }
    return tcg_out_call_iarg_reg(s, i, tmp);
}

static int tcg_out_call_iarg_reg2(TCGContext *s, int i, TCGReg al, TCGReg ah)
{
    i = (i + 1) & ~1;
    i = tcg_out_call_iarg_reg(s, i, (MIPS_BE ? ah : al));
    i = tcg_out_call_iarg_reg(s, i, (MIPS_BE ? al : ah));
    return i;
}

/* Perform the tlb comparison operation.  The complete host address is
   placed in BASE.  Clobbers AT, T0, A0.  */
static void tcg_out_tlb_load(TCGContext *s, TCGReg base, TCGReg addrl,
                             TCGReg addrh, int mem_index, TCGMemOp s_bits,
                             tcg_insn_unit *label_ptr[2], bool is_load)
{
    int cmp_off
        = (is_load
           ? offsetof(CPUArchState, tlb_table[mem_index][0].addr_read)
           : offsetof(CPUArchState, tlb_table[mem_index][0].addr_write));
    int add_off = offsetof(CPUArchState, tlb_table[mem_index][0].addend);

    tcg_out_opc_sa(s, OPC_SRL, TCG_REG_A0, addrl,
                   TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);
    tcg_out_opc_imm(s, OPC_ANDI, TCG_REG_A0, TCG_REG_A0,
                    (CPU_TLB_SIZE - 1) << CPU_TLB_ENTRY_BITS);
    tcg_out_opc_reg(s, OPC_ADDU, TCG_REG_A0, TCG_REG_A0, TCG_AREG0);

    /* Compensate for very large offsets.  */
    if (add_off >= 0x8000) {
        /* Most target env are smaller than 32k; none are larger than 64k.
           Simplify the logic here merely to offset by 0x7ff0, giving us a
           range just shy of 64k.  Check this assumption.  */
        QEMU_BUILD_BUG_ON(offsetof(CPUArchState,
                                   tlb_table[NB_MMU_MODES - 1][1])
                          > 0x7ff0 + 0x7fff);
        tcg_out_opc_imm(s, OPC_ADDIU, TCG_REG_A0, TCG_REG_A0, 0x7ff0);
        cmp_off -= 0x7ff0;
        add_off -= 0x7ff0;
    }

    /* Load the tlb comparator.  */
    tcg_out_opc_imm(s, OPC_LW, TCG_TMP0, TCG_REG_A0, cmp_off + LO_OFF);
    if (TARGET_LONG_BITS == 64) {
        tcg_out_opc_imm(s, OPC_LW, base, TCG_REG_A0, cmp_off + HI_OFF);
    }

    /* Mask the page bits, keeping the alignment bits to compare against.
       In between, load the tlb addend for the fast path.  */
    tcg_out_movi(s, TCG_TYPE_I32, TCG_TMP1,
                 TARGET_PAGE_MASK | ((1 << s_bits) - 1));
    tcg_out_opc_imm(s, OPC_LW, TCG_REG_A0, TCG_REG_A0, add_off);
    tcg_out_opc_reg(s, OPC_AND, TCG_TMP1, TCG_TMP1, addrl);

    label_ptr[0] = s->code_ptr;
    tcg_out_opc_br(s, OPC_BNE, TCG_TMP1, TCG_TMP0);

    if (TARGET_LONG_BITS == 64) {
        /* delay slot */
        tcg_out_nop(s);

        label_ptr[1] = s->code_ptr;
        tcg_out_opc_br(s, OPC_BNE, addrh, base);
    }

    /* delay slot */
    tcg_out_opc_reg(s, OPC_ADDU, base, TCG_REG_A0, addrl);
}

static void add_qemu_ldst_label(TCGContext *s, int is_ld, TCGMemOp opc,
                                TCGReg datalo, TCGReg datahi,
                                TCGReg addrlo, TCGReg addrhi,
                                int mem_index, void *raddr,
                                tcg_insn_unit *label_ptr[2])
{
    TCGLabelQemuLdst *label = new_ldst_label(s);

    label->is_ld = is_ld;
    label->opc = opc;
    label->datalo_reg = datalo;
    label->datahi_reg = datahi;
    label->addrlo_reg = addrlo;
    label->addrhi_reg = addrhi;
    label->mem_index = mem_index;
    label->raddr = raddr;
    label->label_ptr[0] = label_ptr[0];
    if (TARGET_LONG_BITS == 64) {
        label->label_ptr[1] = label_ptr[1];
    }
}

static void tcg_out_qemu_ld_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    TCGMemOp opc = l->opc;
    TCGReg v0;
    int i;

    /* resolve label address */
    reloc_pc16(l->label_ptr[0], s->code_ptr);
    if (TARGET_LONG_BITS == 64) {
        reloc_pc16(l->label_ptr[1], s->code_ptr);
    }

    i = 1;
    if (TARGET_LONG_BITS == 64) {
        i = tcg_out_call_iarg_reg2(s, i, l->addrlo_reg, l->addrhi_reg);
    } else {
        i = tcg_out_call_iarg_reg(s, i, l->addrlo_reg);
    }
    i = tcg_out_call_iarg_imm(s, i, l->mem_index);
    i = tcg_out_call_iarg_imm(s, i, (intptr_t)l->raddr);
    tcg_out_call_int(s, qemu_ld_helpers[opc], false);
    /* delay slot */
    tcg_out_mov(s, TCG_TYPE_PTR, tcg_target_call_iarg_regs[0], TCG_AREG0);

    v0 = l->datalo_reg;
    if ((opc & MO_SIZE) == MO_64) {
        /* We eliminated V0 from the possible output registers, so it
           cannot be clobbered here.  So we must move V1 first.  */
        if (MIPS_BE) {
            tcg_out_mov(s, TCG_TYPE_I32, v0, TCG_REG_V1);
            v0 = l->datahi_reg;
        } else {
            tcg_out_mov(s, TCG_TYPE_I32, l->datahi_reg, TCG_REG_V1);
        }
    }

    reloc_pc16(s->code_ptr, l->raddr);
    tcg_out_opc_br(s, OPC_BEQ, TCG_REG_ZERO, TCG_REG_ZERO);
    /* delay slot */
    tcg_out_mov(s, TCG_TYPE_REG, v0, TCG_REG_V0);
}

static void tcg_out_qemu_st_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    TCGMemOp opc = l->opc;
    TCGMemOp s_bits = opc & MO_SIZE;
    int i;

    /* resolve label address */
    reloc_pc16(l->label_ptr[0], s->code_ptr);
    if (TARGET_LONG_BITS == 64) {
        reloc_pc16(l->label_ptr[1], s->code_ptr);
    }

    i = 1;
    if (TARGET_LONG_BITS == 64) {
        i = tcg_out_call_iarg_reg2(s, i, l->addrlo_reg, l->addrhi_reg);
    } else {
        i = tcg_out_call_iarg_reg(s, i, l->addrlo_reg);
    }
    switch (s_bits) {
    case MO_8:
        i = tcg_out_call_iarg_reg8(s, i, l->datalo_reg);
        break;
    case MO_16:
        i = tcg_out_call_iarg_reg16(s, i, l->datalo_reg);
        break;
    case MO_32:
        i = tcg_out_call_iarg_reg(s, i, l->datalo_reg);
        break;
    case MO_64:
        i = tcg_out_call_iarg_reg2(s, i, l->datalo_reg, l->datahi_reg);
        break;
    default:
        tcg_abort();
    }
    i = tcg_out_call_iarg_imm(s, i, l->mem_index);

    /* Tail call to the store helper.  Thus force the return address
       computation to take place in the return address register.  */
    tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_RA, (intptr_t)l->raddr);
    i = tcg_out_call_iarg_reg(s, i, TCG_REG_RA);
    tcg_out_call_int(s, qemu_st_helpers[opc], true);
    /* delay slot */
    tcg_out_mov(s, TCG_TYPE_PTR, tcg_target_call_iarg_regs[0], TCG_AREG0);
}
#endif

static void tcg_out_qemu_ld_direct(TCGContext *s, TCGReg datalo, TCGReg datahi,
                                   TCGReg base, TCGMemOp opc)
{
    switch (opc) {
    case MO_UB:
        tcg_out_opc_imm(s, OPC_LBU, datalo, base, 0);
        break;
    case MO_SB:
        tcg_out_opc_imm(s, OPC_LB, datalo, base, 0);
        break;
    case MO_UW | MO_BSWAP:
        tcg_out_opc_imm(s, OPC_LHU, TCG_TMP1, base, 0);
        tcg_out_bswap16(s, datalo, TCG_TMP1);
        break;
    case MO_UW:
        tcg_out_opc_imm(s, OPC_LHU, datalo, base, 0);
        break;
    case MO_SW | MO_BSWAP:
        tcg_out_opc_imm(s, OPC_LHU, TCG_TMP1, base, 0);
        tcg_out_bswap16s(s, datalo, TCG_TMP1);
        break;
    case MO_SW:
        tcg_out_opc_imm(s, OPC_LH, datalo, base, 0);
        break;
    case MO_UL | MO_BSWAP:
        tcg_out_opc_imm(s, OPC_LW, TCG_TMP1, base, 0);
        tcg_out_bswap32(s, datalo, TCG_TMP1);
        break;
    case MO_UL:
        tcg_out_opc_imm(s, OPC_LW, datalo, base, 0);
        break;
    case MO_Q | MO_BSWAP:
        tcg_out_opc_imm(s, OPC_LW, TCG_TMP1, base, HI_OFF);
        tcg_out_bswap32(s, datalo, TCG_TMP1);
        tcg_out_opc_imm(s, OPC_LW, TCG_TMP1, base, LO_OFF);
        tcg_out_bswap32(s, datahi, TCG_TMP1);
        break;
    case MO_Q:
        tcg_out_opc_imm(s, OPC_LW, datalo, base, LO_OFF);
        tcg_out_opc_imm(s, OPC_LW, datahi, base, HI_OFF);
        break;
    default:
        tcg_abort();
    }
}

static void tcg_out_qemu_ld(TCGContext *s, const TCGArg *args, bool is_64)
{
    TCGReg addr_regl, addr_regh QEMU_UNUSED_VAR;
    TCGReg data_regl, data_regh;
    TCGMemOp opc;
#if defined(CONFIG_SOFTMMU)
    tcg_insn_unit *label_ptr[2];
    int mem_index;
    TCGMemOp s_bits;
#endif
    /* Note that we've eliminated V0 from the output registers,
       so we won't overwrite the base register during loading.  */
    TCGReg base = TCG_REG_V0;

    data_regl = *args++;
    data_regh = (is_64 ? *args++ : 0);
    addr_regl = *args++;
    addr_regh = (TARGET_LONG_BITS == 64 ? *args++ : 0);
    opc = *args++;

#if defined(CONFIG_SOFTMMU)
    mem_index = *args;
    s_bits = opc & MO_SIZE;

    tcg_out_tlb_load(s, base, addr_regl, addr_regh, mem_index,
                     s_bits, label_ptr, 1);
    tcg_out_qemu_ld_direct(s, data_regl, data_regh, base, opc);
    add_qemu_ldst_label(s, 1, opc, data_regl, data_regh, addr_regl, addr_regh,
                        mem_index, s->code_ptr, label_ptr);
#else
    if (GUEST_BASE == 0 && data_regl != addr_regl) {
        base = addr_regl;
    } else if (GUEST_BASE == (int16_t)GUEST_BASE) {
        tcg_out_opc_imm(s, OPC_ADDIU, base, addr_regl, GUEST_BASE);
    } else {
        tcg_out_movi(s, TCG_TYPE_PTR, base, GUEST_BASE);
        tcg_out_opc_reg(s, OPC_ADDU, base, base, addr_regl);
    }
    tcg_out_qemu_ld_direct(s, data_regl, data_regh, base, opc);
#endif
}

static void tcg_out_qemu_st_direct(TCGContext *s, TCGReg datalo, TCGReg datahi,
                                   TCGReg base, TCGMemOp opc)
{
    switch (opc) {
    case MO_8:
        tcg_out_opc_imm(s, OPC_SB, datalo, base, 0);
        break;

    case MO_16 | MO_BSWAP:
        tcg_out_opc_imm(s, OPC_ANDI, TCG_TMP1, datalo, 0xffff);
        tcg_out_bswap16(s, TCG_TMP1, TCG_TMP1);
        datalo = TCG_TMP1;
        /* FALLTHRU */
    case MO_16:
        tcg_out_opc_imm(s, OPC_SH, datalo, base, 0);
        break;

    case MO_32 | MO_BSWAP:
        tcg_out_bswap32(s, TCG_TMP1, datalo);
        datalo = TCG_TMP1;
        /* FALLTHRU */
    case MO_32:
        tcg_out_opc_imm(s, OPC_SW, datalo, base, 0);
        break;

    case MO_64 | MO_BSWAP:
        tcg_out_bswap32(s, TCG_TMP1, datalo);
        tcg_out_opc_imm(s, OPC_SW, TCG_TMP1, base, HI_OFF);
        tcg_out_bswap32(s, TCG_TMP1, datahi);
        tcg_out_opc_imm(s, OPC_SW, TCG_TMP1, base, LO_OFF);
        break;
    case MO_64:
        tcg_out_opc_imm(s, OPC_SW, datalo, base, LO_OFF);
        tcg_out_opc_imm(s, OPC_SW, datahi, base, HI_OFF);
        break;

    default:
        tcg_abort();
    }
}

static void tcg_out_addsub2(TCGContext *s, TCGReg rl, TCGReg rh, TCGReg al,
                            TCGReg ah, TCGArg bl, TCGArg bh, bool cbl,
                            bool cbh, bool is_sub)
{
    TCGReg th = TCG_TMP1;

    /* If we have a negative constant such that negating it would
       make the high part zero, we can (usually) eliminate one insn.  */
    if (cbl && cbh && bh == -1 && bl != 0) {
        bl = -bl;
        bh = 0;
        is_sub = !is_sub;
    }

    /* By operating on the high part first, we get to use the final
       carry operation to move back from the temporary.  */
    if (!cbh) {
        tcg_out_opc_reg(s, (is_sub ? OPC_SUBU : OPC_ADDU), th, ah, bh);
    } else if (bh != 0 || ah == rl) {
        tcg_out_opc_imm(s, OPC_ADDIU, th, ah, (is_sub ? -bh : bh));
    } else {
        th = ah;
    }

    /* Note that tcg optimization should eliminate the bl == 0 case.  */
    if (is_sub) {
        if (cbl) {
            tcg_out_opc_imm(s, OPC_SLTIU, TCG_TMP0, al, bl);
            tcg_out_opc_imm(s, OPC_ADDIU, rl, al, -bl);
        } else {
            tcg_out_opc_reg(s, OPC_SLTU, TCG_TMP0, al, bl);
            tcg_out_opc_reg(s, OPC_SUBU, rl, al, bl);
        }
        tcg_out_opc_reg(s, OPC_SUBU, rh, th, TCG_TMP0);
    } else {
        if (cbl) {
            tcg_out_opc_imm(s, OPC_ADDIU, rl, al, bl);
            tcg_out_opc_imm(s, OPC_SLTIU, TCG_TMP0, rl, bl);
        } else {
            tcg_out_opc_reg(s, OPC_ADDU, rl, al, bl);
            tcg_out_opc_reg(s, OPC_SLTU, TCG_TMP0, rl, (rl == bl ? al : bl));
        }
        tcg_out_opc_reg(s, OPC_ADDU, rh, th, TCG_TMP0);
    }
}

static void tcg_out_qemu_st(TCGContext *s, const TCGArg *args, bool is_64)
{
    TCGReg addr_regl, addr_regh QEMU_UNUSED_VAR;
    TCGReg data_regl, data_regh, base;
    TCGMemOp opc;
#if defined(CONFIG_SOFTMMU)
    tcg_insn_unit *label_ptr[2];
    int mem_index;
    TCGMemOp s_bits;
#endif

    data_regl = *args++;
    data_regh = (is_64 ? *args++ : 0);
    addr_regl = *args++;
    addr_regh = (TARGET_LONG_BITS == 64 ? *args++ : 0);
    opc = *args++;

#if defined(CONFIG_SOFTMMU)
    mem_index = *args;
    s_bits = opc & 3;

    /* Note that we eliminated the helper's address argument,
       so we can reuse that for the base.  */
    base = (TARGET_LONG_BITS == 32 ? TCG_REG_A1 : TCG_REG_A2);
    tcg_out_tlb_load(s, base, addr_regl, addr_regh, mem_index,
                     s_bits, label_ptr, 0);
    tcg_out_qemu_st_direct(s, data_regl, data_regh, base, opc);
    add_qemu_ldst_label(s, 0, opc, data_regl, data_regh, addr_regl, addr_regh,
                        mem_index, s->code_ptr, label_ptr);
#else
    if (GUEST_BASE == 0) {
        base = addr_regl;
    } else {
        base = TCG_REG_A0;
        if (GUEST_BASE == (int16_t)GUEST_BASE) {
            tcg_out_opc_imm(s, OPC_ADDIU, base, addr_regl, GUEST_BASE);
        } else {
            tcg_out_movi(s, TCG_TYPE_PTR, base, GUEST_BASE);
            tcg_out_opc_reg(s, OPC_ADDU, base, base, addr_regl);
        }
    }
    tcg_out_qemu_st_direct(s, data_regl, data_regh, base, opc);
#endif
}

static inline void tcg_out_op(TCGContext *s, TCGOpcode opc,
                              const TCGArg *args, const int *const_args)
{
    MIPSInsn i1, i2;
    TCGArg a0, a1, a2;
    int c2;

    a0 = args[0];
    a1 = args[1];
    a2 = args[2];
    c2 = const_args[2];

    switch (opc) {
    case INDEX_op_exit_tb:
        {
            TCGReg b0 = TCG_REG_ZERO;

            if (a0 & ~0xffff) {
                tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_V0, a0 & ~0xffff);
                b0 = TCG_REG_V0;
            }
            if (!tcg_out_opc_jmp(s, OPC_J, tb_ret_addr)) {
                tcg_out_movi(s, TCG_TYPE_PTR, TCG_TMP0,
                             (uintptr_t)tb_ret_addr);
                tcg_out_opc_reg(s, OPC_JR, 0, TCG_TMP0, 0);
            }
            tcg_out_opc_imm(s, OPC_ORI, TCG_REG_V0, b0, a0 & 0xffff);
        }
        break;
    case INDEX_op_goto_tb:
        if (s->tb_jmp_offset) {
            /* direct jump method */
            s->tb_jmp_offset[a0] = tcg_current_code_size(s);
            /* Avoid clobbering the address during retranslation.  */
            tcg_out32(s, OPC_J | (*(uint32_t *)s->code_ptr & 0x3ffffff));
        } else {
            /* indirect jump method */
            tcg_out_ld(s, TCG_TYPE_PTR, TCG_TMP0, TCG_REG_ZERO,
                       (uintptr_t)(s->tb_next + a0));
            tcg_out_opc_reg(s, OPC_JR, 0, TCG_TMP0, 0);
        }
        tcg_out_nop(s);
        s->tb_next_offset[a0] = tcg_current_code_size(s);
        break;
    case INDEX_op_br:
        tcg_out_brcond(s, TCG_COND_EQ, TCG_REG_ZERO, TCG_REG_ZERO, a0);
        break;

    case INDEX_op_ld8u_i32:
        i1 = OPC_LBU;
        goto do_ldst;
    case INDEX_op_ld8s_i32:
        i1 = OPC_LB;
        goto do_ldst;
    case INDEX_op_ld16u_i32:
        i1 = OPC_LHU;
        goto do_ldst;
    case INDEX_op_ld16s_i32:
        i1 = OPC_LH;
        goto do_ldst;
    case INDEX_op_ld_i32:
        i1 = OPC_LW;
        goto do_ldst;
    case INDEX_op_st8_i32:
        i1 = OPC_SB;
        goto do_ldst;
    case INDEX_op_st16_i32:
        i1 = OPC_SH;
        goto do_ldst;
    case INDEX_op_st_i32:
        i1 = OPC_SW;
    do_ldst:
        tcg_out_ldst(s, i1, a0, a1, a2);
        break;

    case INDEX_op_add_i32:
        i1 = OPC_ADDU, i2 = OPC_ADDIU;
        goto do_binary;
    case INDEX_op_or_i32:
        i1 = OPC_OR, i2 = OPC_ORI;
        goto do_binary;
    case INDEX_op_xor_i32:
        i1 = OPC_XOR, i2 = OPC_XORI;
    do_binary:
        if (c2) {
            tcg_out_opc_imm(s, i2, a0, a1, a2);
            break;
        }
    do_binaryv:
        tcg_out_opc_reg(s, i1, a0, a1, a2);
        break;

    case INDEX_op_sub_i32:
        if (c2) {
            tcg_out_opc_imm(s, OPC_ADDIU, a0, a1, -a2);
            break;
        }
        i1 = OPC_SUBU;
        goto do_binary;
    case INDEX_op_and_i32:
        if (c2 && a2 != (uint16_t)a2) {
            int msb = ctz32(~a2) - 1;
            assert(use_mips32r2_instructions);
            assert(is_p2m1(a2));
            tcg_out_opc_bf(s, OPC_EXT, a0, a1, msb, 0);
            break;
        }
        i1 = OPC_AND, i2 = OPC_ANDI;
        goto do_binary;
    case INDEX_op_nor_i32:
        i1 = OPC_NOR;
        goto do_binaryv;

    case INDEX_op_mul_i32:
        if (use_mips32_instructions) {
            tcg_out_opc_reg(s, OPC_MUL, a0, a1, a2);
            break;
        }
        i1 = OPC_MULT, i2 = OPC_MFLO;
        goto do_hilo1;
    case INDEX_op_mulsh_i32:
        i1 = OPC_MULT, i2 = OPC_MFHI;
        goto do_hilo1;
    case INDEX_op_muluh_i32:
        i1 = OPC_MULTU, i2 = OPC_MFHI;
        goto do_hilo1;
    case INDEX_op_div_i32:
        i1 = OPC_DIV, i2 = OPC_MFLO;
        goto do_hilo1;
    case INDEX_op_divu_i32:
        i1 = OPC_DIVU, i2 = OPC_MFLO;
        goto do_hilo1;
    case INDEX_op_rem_i32:
        i1 = OPC_DIV, i2 = OPC_MFHI;
        goto do_hilo1;
    case INDEX_op_remu_i32:
        i1 = OPC_DIVU, i2 = OPC_MFHI;
    do_hilo1:
        tcg_out_opc_reg(s, i1, 0, a1, a2);
        tcg_out_opc_reg(s, i2, a0, 0, 0);
        break;

    case INDEX_op_muls2_i32:
        i1 = OPC_MULT;
        goto do_hilo2;
    case INDEX_op_mulu2_i32:
        i1 = OPC_MULTU;
    do_hilo2:
        tcg_out_opc_reg(s, i1, 0, a2, args[3]);
        tcg_out_opc_reg(s, OPC_MFLO, a0, 0, 0);
        tcg_out_opc_reg(s, OPC_MFHI, a1, 0, 0);
        break;

    case INDEX_op_not_i32:
        i1 = OPC_NOR;
        goto do_unary;
    case INDEX_op_bswap16_i32:
        i1 = OPC_WSBH;
        goto do_unary;
    case INDEX_op_ext8s_i32:
        i1 = OPC_SEB;
        goto do_unary;
    case INDEX_op_ext16s_i32:
        i1 = OPC_SEH;
    do_unary:
        tcg_out_opc_reg(s, i1, a0, TCG_REG_ZERO, a1);
        break;

    case INDEX_op_sar_i32:
        i1 = OPC_SRAV, i2 = OPC_SRA;
        goto do_shift;
    case INDEX_op_shl_i32:
        i1 = OPC_SLLV, i2 = OPC_SLL;
        goto do_shift;
    case INDEX_op_shr_i32:
        i1 = OPC_SRLV, i2 = OPC_SRL;
        goto do_shift;
    case INDEX_op_rotr_i32:
        i1 = OPC_ROTRV, i2 = OPC_ROTR;
    do_shift:
        if (c2) {
            tcg_out_opc_sa(s, i2, a0, a1, a2);
        } else {
            tcg_out_opc_reg(s, i1, a0, a2, a1);
        }
        break;
    case INDEX_op_rotl_i32:
        if (c2) {
            tcg_out_opc_sa(s, OPC_ROTR, a0, a1, 32 - a2);
        } else {
            tcg_out_opc_reg(s, OPC_SUBU, TCG_TMP0, TCG_REG_ZERO, a2);
            tcg_out_opc_reg(s, OPC_ROTRV, a0, TCG_TMP0, a1);
        }
        break;

    case INDEX_op_bswap32_i32:
        tcg_out_opc_reg(s, OPC_WSBH, a0, 0, a1);
        tcg_out_opc_sa(s, OPC_ROTR, a0, a0, 16);
        break;

    case INDEX_op_deposit_i32:
        tcg_out_opc_bf(s, OPC_INS, a0, a2, args[3] + args[4] - 1, args[3]);
        break;

    case INDEX_op_brcond_i32:
        tcg_out_brcond(s, a2, a0, a1, args[3]);
        break;
    case INDEX_op_brcond2_i32:
        tcg_out_brcond2(s, args[4], a0, a1, a2, args[3], args[5]);
        break;

    case INDEX_op_movcond_i32:
        tcg_out_movcond(s, args[5], a0, a1, a2, args[3]);
        break;

    case INDEX_op_setcond_i32:
        tcg_out_setcond(s, args[3], a0, a1, a2);
        break;
    case INDEX_op_setcond2_i32:
        tcg_out_setcond2(s, args[5], a0, a1, a2, args[3], args[4]);
        break;

    case INDEX_op_qemu_ld_i32:
        tcg_out_qemu_ld(s, args, false);
        break;
    case INDEX_op_qemu_ld_i64:
        tcg_out_qemu_ld(s, args, true);
        break;
    case INDEX_op_qemu_st_i32:
        tcg_out_qemu_st(s, args, false);
        break;
    case INDEX_op_qemu_st_i64:
        tcg_out_qemu_st(s, args, true);
        break;

    case INDEX_op_add2_i32:
        tcg_out_addsub2(s, a0, a1, a2, args[3], args[4], args[5],
                        const_args[4], const_args[5], false);
        break;
    case INDEX_op_sub2_i32:
        tcg_out_addsub2(s, a0, a1, a2, args[3], args[4], args[5],
                        const_args[4], const_args[5], true);
        break;

    case INDEX_op_mov_i32:  /* Always emitted via tcg_out_mov.  */
    case INDEX_op_movi_i32: /* Always emitted via tcg_out_movi.  */
    case INDEX_op_call:     /* Always emitted via tcg_out_call.  */
    default:
        tcg_abort();
    }
}

static const TCGTargetOpDef mips_op_defs[] = {
    { INDEX_op_exit_tb, { } },
    { INDEX_op_goto_tb, { } },
    { INDEX_op_br, { } },

    { INDEX_op_ld8u_i32, { "r", "r" } },
    { INDEX_op_ld8s_i32, { "r", "r" } },
    { INDEX_op_ld16u_i32, { "r", "r" } },
    { INDEX_op_ld16s_i32, { "r", "r" } },
    { INDEX_op_ld_i32, { "r", "r" } },
    { INDEX_op_st8_i32, { "rZ", "r" } },
    { INDEX_op_st16_i32, { "rZ", "r" } },
    { INDEX_op_st_i32, { "rZ", "r" } },

    { INDEX_op_add_i32, { "r", "rZ", "rJ" } },
    { INDEX_op_mul_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_muls2_i32, { "r", "r", "rZ", "rZ" } },
    { INDEX_op_mulu2_i32, { "r", "r", "rZ", "rZ" } },
    { INDEX_op_mulsh_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_muluh_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_div_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_divu_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_rem_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_remu_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_sub_i32, { "r", "rZ", "rN" } },

    { INDEX_op_and_i32, { "r", "rZ", "rIK" } },
    { INDEX_op_nor_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_not_i32, { "r", "rZ" } },
    { INDEX_op_or_i32, { "r", "rZ", "rIZ" } },
    { INDEX_op_xor_i32, { "r", "rZ", "rIZ" } },

    { INDEX_op_shl_i32, { "r", "rZ", "ri" } },
    { INDEX_op_shr_i32, { "r", "rZ", "ri" } },
    { INDEX_op_sar_i32, { "r", "rZ", "ri" } },
    { INDEX_op_rotr_i32, { "r", "rZ", "ri" } },
    { INDEX_op_rotl_i32, { "r", "rZ", "ri" } },

    { INDEX_op_bswap16_i32, { "r", "r" } },
    { INDEX_op_bswap32_i32, { "r", "r" } },

    { INDEX_op_ext8s_i32, { "r", "rZ" } },
    { INDEX_op_ext16s_i32, { "r", "rZ" } },

    { INDEX_op_deposit_i32, { "r", "0", "rZ" } },

    { INDEX_op_brcond_i32, { "rZ", "rZ" } },
    { INDEX_op_movcond_i32, { "r", "rZ", "rZ", "rZ", "0" } },
    { INDEX_op_setcond_i32, { "r", "rZ", "rZ" } },
    { INDEX_op_setcond2_i32, { "r", "rZ", "rZ", "rZ", "rZ" } },

    { INDEX_op_add2_i32, { "r", "r", "rZ", "rZ", "rN", "rN" } },
    { INDEX_op_sub2_i32, { "r", "r", "rZ", "rZ", "rN", "rN" } },
    { INDEX_op_brcond2_i32, { "rZ", "rZ", "rZ", "rZ" } },

#if TARGET_LONG_BITS == 32
    { INDEX_op_qemu_ld_i32, { "L", "lZ" } },
    { INDEX_op_qemu_st_i32, { "SZ", "SZ" } },
    { INDEX_op_qemu_ld_i64, { "L", "L", "lZ" } },
    { INDEX_op_qemu_st_i64, { "SZ", "SZ", "SZ" } },
#else
    { INDEX_op_qemu_ld_i32, { "L", "lZ", "lZ" } },
    { INDEX_op_qemu_st_i32, { "SZ", "SZ", "SZ" } },
    { INDEX_op_qemu_ld_i64, { "L", "L", "lZ", "lZ" } },
    { INDEX_op_qemu_st_i64, { "SZ", "SZ", "SZ", "SZ" } },
#endif
    { -1 },
};

static int tcg_target_callee_save_regs[] = {
    TCG_REG_S0,       /* used for the global env (TCG_AREG0) */
    TCG_REG_S1,
    TCG_REG_S2,
    TCG_REG_S3,
    TCG_REG_S4,
    TCG_REG_S5,
    TCG_REG_S6,
    TCG_REG_S7,
    TCG_REG_S8,
    TCG_REG_RA,       /* should be last for ABI compliance */
};

/* The Linux kernel doesn't provide any information about the available
   instruction set. Probe it using a signal handler. */

#include <signal.h>

#ifndef use_movnz_instructions
bool use_movnz_instructions = false;
#endif

#ifndef use_mips32_instructions
bool use_mips32_instructions = false;
#endif

#ifndef use_mips32r2_instructions
bool use_mips32r2_instructions = false;
#endif

static volatile sig_atomic_t got_sigill;

static void sigill_handler(int signo, siginfo_t *si, void *data)
{
    /* Skip the faulty instruction */
    ucontext_t *uc = (ucontext_t *)data;
    uc->uc_mcontext.pc += 4;

    got_sigill = 1;
}

static void tcg_target_detect_isa(void)
{
    struct sigaction sa_old, sa_new;

    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_flags = SA_SIGINFO;
    sa_new.sa_sigaction = sigill_handler;
    sigaction(SIGILL, &sa_new, &sa_old);

    /* Probe for movn/movz, necessary to implement movcond. */
#ifndef use_movnz_instructions
    got_sigill = 0;
    asm volatile(".set push\n"
                 ".set mips32\n"
                 "movn $zero, $zero, $zero\n"
                 "movz $zero, $zero, $zero\n"
                 ".set pop\n"
                 : : : );
    use_movnz_instructions = !got_sigill;
#endif

    /* Probe for MIPS32 instructions. As no subsetting is allowed
       by the specification, it is only necessary to probe for one
       of the instructions. */
#ifndef use_mips32_instructions
    got_sigill = 0;
    asm volatile(".set push\n"
                 ".set mips32\n"
                 "mul $zero, $zero\n"
                 ".set pop\n"
                 : : : );
    use_mips32_instructions = !got_sigill;
#endif

    /* Probe for MIPS32r2 instructions if MIPS32 instructions are
       available. As no subsetting is allowed by the specification,
       it is only necessary to probe for one of the instructions. */
#ifndef use_mips32r2_instructions
    if (use_mips32_instructions) {
        got_sigill = 0;
        asm volatile(".set push\n"
                     ".set mips32r2\n"
                     "seb $zero, $zero\n"
                     ".set pop\n"
                     : : : );
        use_mips32r2_instructions = !got_sigill;
    }
#endif

    sigaction(SIGILL, &sa_old, NULL);
}

/* Generate global QEMU prologue and epilogue code */
static void tcg_target_qemu_prologue(TCGContext *s)
{
    int i, frame_size;

    /* reserve some stack space, also for TCG temps. */
    frame_size = ARRAY_SIZE(tcg_target_callee_save_regs) * 4
                 + TCG_STATIC_CALL_ARGS_SIZE
                 + CPU_TEMP_BUF_NLONGS * sizeof(long);
    frame_size = (frame_size + TCG_TARGET_STACK_ALIGN - 1) &
                 ~(TCG_TARGET_STACK_ALIGN - 1);
    tcg_set_frame(s, TCG_REG_SP, ARRAY_SIZE(tcg_target_callee_save_regs) * 4
                  + TCG_STATIC_CALL_ARGS_SIZE,
                  CPU_TEMP_BUF_NLONGS * sizeof(long));

    /* TB prologue */
    tcg_out_addi(s, TCG_REG_SP, -frame_size);
    for(i = 0 ; i < ARRAY_SIZE(tcg_target_callee_save_regs) ; i++) {
        tcg_out_st(s, TCG_TYPE_I32, tcg_target_callee_save_regs[i],
                   TCG_REG_SP, TCG_STATIC_CALL_ARGS_SIZE + i * 4);
    }

    /* Call generated code */
    tcg_out_opc_reg(s, OPC_JR, 0, tcg_target_call_iarg_regs[1], 0);
    tcg_out_mov(s, TCG_TYPE_PTR, TCG_AREG0, tcg_target_call_iarg_regs[0]);
    tb_ret_addr = s->code_ptr;

    /* TB epilogue */
    for(i = 0 ; i < ARRAY_SIZE(tcg_target_callee_save_regs) ; i++) {
        tcg_out_ld(s, TCG_TYPE_I32, tcg_target_callee_save_regs[i],
                   TCG_REG_SP, TCG_STATIC_CALL_ARGS_SIZE + i * 4);
    }

    tcg_out_opc_reg(s, OPC_JR, 0, TCG_REG_RA, 0);
    tcg_out_addi(s, TCG_REG_SP, frame_size);
}

static void tcg_target_init(TCGContext *s)
{
    tcg_target_detect_isa();
    tcg_regset_set(s->tcg_target_available_regs[TCG_TYPE_I32], 0xffffffff);
    tcg_regset_set(s->tcg_target_call_clobber_regs,
                   (1 << TCG_REG_V0) |
                   (1 << TCG_REG_V1) |
                   (1 << TCG_REG_A0) |
                   (1 << TCG_REG_A1) |
                   (1 << TCG_REG_A2) |
                   (1 << TCG_REG_A3) |
                   (1 << TCG_REG_T0) |
                   (1 << TCG_REG_T1) |
                   (1 << TCG_REG_T2) |
                   (1 << TCG_REG_T3) |
                   (1 << TCG_REG_T4) |
                   (1 << TCG_REG_T5) |
                   (1 << TCG_REG_T6) |
                   (1 << TCG_REG_T7) |
                   (1 << TCG_REG_T8) |
                   (1 << TCG_REG_T9));

    tcg_regset_clear(s->reserved_regs);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_ZERO); /* zero register */
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_K0);   /* kernel use only */
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_K1);   /* kernel use only */
    tcg_regset_set_reg(s->reserved_regs, TCG_TMP0);     /* internal use */
    tcg_regset_set_reg(s->reserved_regs, TCG_TMP1);     /* internal use */
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_RA);   /* return address */
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_SP);   /* stack pointer */
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_GP);   /* global pointer */

    tcg_add_target_add_op_defs(s, mips_op_defs);
}

void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
    uint32_t *ptr = (uint32_t *)jmp_addr;
    *ptr = deposit32(*ptr, 0, 26, addr >> 2);
    flush_icache_range(jmp_addr, jmp_addr + 4);
}
