/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2021 WANG Xuerui <git@xen0n.name>
 *
 * Based on tcg/riscv/tcg-target.c.inc
 *
 * Copyright (c) 2018 SiFive, Inc
 * Copyright (c) 2008-2009 Arnaud Patard <arnaud.patard@rtp-net.org>
 * Copyright (c) 2009 Aurelien Jarno <aurelien@aurel32.net>
 * Copyright (c) 2008 Fabrice Bellard
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

#include "../tcg-ldst.inc.c"
#include <asm/hwcap.h>

#ifdef CONFIG_DEBUG_TCG
static const char * const tcg_target_reg_names[TCG_TARGET_NB_REGS] = {
    "zero",
    "ra",
    "tp",
    "sp",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "t7",
    "t8",
    "r21", /* reserved in the LP64* ABI, hence no ABI name */
    "s9",
    "s0",
    "s1",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "s8",
    "vr0",
    "vr1",
    "vr2",
    "vr3",
    "vr4",
    "vr5",
    "vr6",
    "vr7",
    "vr8",
    "vr9",
    "vr10",
    "vr11",
    "vr12",
    "vr13",
    "vr14",
    "vr15",
    "vr16",
    "vr17",
    "vr18",
    "vr19",
    "vr20",
    "vr21",
    "vr22",
    "vr23",
    "vr24",
    "vr25",
    "vr26",
    "vr27",
    "vr28",
    "vr29",
    "vr30",
    "vr31",
};
#endif

static const int tcg_target_reg_alloc_order[] = {
    /* Registers preserved across calls */
    /* TCG_REG_S0 reserved for TCG_AREG0 */
    TCG_REG_S1,
    TCG_REG_S2,
    TCG_REG_S3,
    TCG_REG_S4,
    TCG_REG_S5,
    TCG_REG_S6,
    TCG_REG_S7,
    TCG_REG_S8,
    TCG_REG_S9,

    /* Registers (potentially) clobbered across calls */
    TCG_REG_T0,
    TCG_REG_T1,
    TCG_REG_T2,
    TCG_REG_T3,
    TCG_REG_T4,
    TCG_REG_T5,
    TCG_REG_T6,
    TCG_REG_T7,
    TCG_REG_T8,

    /* Argument registers, opposite order of allocation.  */
    TCG_REG_A7,
    TCG_REG_A6,
    TCG_REG_A5,
    TCG_REG_A4,
    TCG_REG_A3,
    TCG_REG_A2,
    TCG_REG_A1,
    TCG_REG_A0,

    /* Vector registers */
    TCG_REG_V0, TCG_REG_V1, TCG_REG_V2, TCG_REG_V3,
    TCG_REG_V4, TCG_REG_V5, TCG_REG_V6, TCG_REG_V7,
    TCG_REG_V8, TCG_REG_V9, TCG_REG_V10, TCG_REG_V11,
    TCG_REG_V12, TCG_REG_V13, TCG_REG_V14, TCG_REG_V15,
    TCG_REG_V16, TCG_REG_V17, TCG_REG_V18, TCG_REG_V19,
    TCG_REG_V20, TCG_REG_V21, TCG_REG_V22, TCG_REG_V23,
    /* V24 - V31 are caller-saved, and skipped.  */
};

static const int tcg_target_call_iarg_regs[] = {
    TCG_REG_A0,
    TCG_REG_A1,
    TCG_REG_A2,
    TCG_REG_A3,
    TCG_REG_A4,
    TCG_REG_A5,
    TCG_REG_A6,
    TCG_REG_A7,
};

static const TCGReg tcg_target_call_oarg_regs[2] = {
    TCG_REG_A0,
    TCG_REG_A1
};

#ifndef CONFIG_SOFTMMU
#define USE_GUEST_BASE     (guest_base != 0)
#define TCG_GUEST_BASE_REG TCG_REG_S1
#endif

#define TCG_CT_CONST_ZERO  0x100
#define TCG_CT_CONST_S12   0x200
#define TCG_CT_CONST_S32   0x400
#define TCG_CT_CONST_U12   0x800
#define TCG_CT_CONST_C12   0x1000
#define TCG_CT_CONST_WSZ   0x2000
#define TCG_CT_CONST_VCMP  0x4000
#define TCG_CT_CONST_VADD  0x8000

#define ALL_GENERAL_REGS   MAKE_64BIT_MASK(0, 32)
#define ALL_VECTOR_REGS    MAKE_64BIT_MASK(32, 32)

static inline tcg_target_long sextreg(tcg_target_long val, int pos, int len)
{
    return sextract64(val, pos, len);
}

/* test if a constant matches the constraint */
static inline int tcg_target_const_match(tcg_target_long val, TCGType type, 
                                         const TCGArgConstraint *arg_ct)
{
    int ct;
    ct = arg_ct->ct;
    if (ct & TCG_CT_CONST) {
        return true;
    }
    if ((ct & TCG_CT_CONST_ZERO) && val == 0) {
        return true;
    }
    if ((ct & TCG_CT_CONST_S12) && val == sextreg(val, 0, 12)) {
        return true;
    }
    if ((ct & TCG_CT_CONST_S32) && val == (int32_t)val) {
        return true;
    }
    if ((ct & TCG_CT_CONST_U12) && val >= 0 && val <= 0xfff) {
        return true;
    }
    if ((ct & TCG_CT_CONST_C12) && ~val >= 0 && ~val <= 0xfff) {
        return true;
    }
    if ((ct & TCG_CT_CONST_WSZ) && val == (type == TCG_TYPE_I32 ? 32 : 64)) {
        return true;
    }
#if 0
    int64_t vec_val = sextract64(val, 0, 8 << vece);
    if ((ct & TCG_CT_CONST_VCMP) && -0x10 <= vec_val && vec_val <= 0x1f) {
        return true;
    }
    if ((ct & TCG_CT_CONST_VADD) && -0x1f <= vec_val && vec_val <= 0x1f) {
        return true;
    }
#else
    /* tcg does not pass vece to us */
    if ((ct & TCG_CT_CONST_VADD) || (ct & TCG_CT_CONST_VCMP)) {
        return true;
    }
#endif

    return false;
}

/* parse target specific constraints */
static const char *target_parse_constraint(TCGArgConstraint *ct,
                                           const char *ct_str, TCGType type)
{
    switch(*ct_str++) {
    case 'r':
        ct->ct |= TCG_CT_REG;
        ct->u.regs = ALL_GENERAL_REGS;
        break;
    case 'l':
        ct->ct |= TCG_CT_REG;
        ct->u.regs = ALL_GENERAL_REGS;
#ifdef CONFIG_SOFTMMU
        tcg_regset_reset_reg(ct->u.regs, TCG_AREG0);
        tcg_regset_reset_reg(ct->u.regs, TCG_REG_TMP0);
        tcg_regset_reset_reg(ct->u.regs, TCG_REG_TMP1);
        tcg_regset_reset_reg(ct->u.regs, TCG_REG_TMP2);
#endif
        break;
    case 'w':
        ct->ct |= TCG_CT_REG;
        ct->u.regs = ALL_VECTOR_REGS;
        break;
    case 'I': 
        ct->ct |= TCG_CT_CONST_S12;
        break;
    case 'J':
        ct->ct |= TCG_CT_CONST_S32;
        break;
    case 'U':
        ct->ct |= TCG_CT_CONST_U12;
        break;
    case 'Z':
        ct->ct |= TCG_CT_CONST_ZERO;
        break;
    case 'C':
        ct->ct |= TCG_CT_CONST_C12;
        break;
    case 'W':
        ct->ct |= TCG_CT_CONST_WSZ;
        break;
    case 'M':
        ct->ct |= TCG_CT_CONST_VCMP;
        break;
    case 'A':
        ct->ct |= TCG_CT_CONST_VADD;
        break;
    default:
        return NULL;
    }
    return ct_str;
}

/*
 * Relocations
 */

/*
 * Relocation records defined in LoongArch ELF psABI v1.00 is way too
 * complicated; a whopping stack machine is needed to stuff the fields, at
 * the very least one SOP_PUSH and one SOP_POP (of the correct format) are
 * needed.
 *
 * Hence, define our own simpler relocation types. Numbers are chosen as to
 * not collide with potential future additions to the true ELF relocation
 * type enum.
 */

/* Field Sk16, shifted right by 2; suitable for conditional jumps */
#define R_LOONGARCH_BR_SK16     256
/* Field Sd10k16, shifted right by 2; suitable for B and BL */
#define R_LOONGARCH_BR_SD10K16  257

static bool reloc_br_sk16(tcg_insn_unit *src_rw, const tcg_insn_unit *target)
{
    intptr_t offset = (intptr_t)target - (intptr_t)src_rw;

    tcg_debug_assert((offset & 3) == 0);
    offset >>= 2;
    if (offset == sextreg(offset, 0, 16)) {
        *src_rw = deposit64(*src_rw, 10, 16, offset);
        return true;
    }

    return false;
}

static bool reloc_br_sd10k16(tcg_insn_unit *src_rw,
                             const tcg_insn_unit *target)
{
    intptr_t offset = (intptr_t)target - (intptr_t)src_rw;

    tcg_debug_assert((offset & 3) == 0);
    offset >>= 2;
    if (offset == sextreg(offset, 0, 26)) {
        *src_rw = deposit64(*src_rw, 0, 10, offset >> 16); /* slot d10 */
        *src_rw = deposit64(*src_rw, 10, 16, offset); /* slot k16 */
        return true;
    }

    return false;
}

static bool patch_reloc(tcg_insn_unit *code_ptr, int type,
                        intptr_t value, intptr_t addend)
{
    tcg_debug_assert(addend == 0);
    switch (type) {
    case R_LOONGARCH_BR_SK16:
        return reloc_br_sk16(code_ptr, (tcg_insn_unit *)value);
    case R_LOONGARCH_BR_SD10K16:
        return reloc_br_sd10k16(code_ptr, (tcg_insn_unit *)value);
    default:
        g_assert_not_reached();
    }
}

#include "tcg-insn-defs.c.inc"

/*
 * TCG intrinsics
 */

static void tcg_out_mb(TCGContext *s, TCGArg a0)
{
    /* Baseline LoongArch only has the full barrier, unfortunately.  */
    tcg_out_opc_dbar(s, 0);
}

static bool tcg_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    if (ret == arg) {
        return true;
    }
    switch (type) {
    case TCG_TYPE_I32:
    case TCG_TYPE_I64:
        /*
         * Conventional register-register move used in LoongArch is
         * `or dst, src, zero`.
         */
        tcg_out_opc_or(s, ret, arg, TCG_REG_ZERO);
        break;
    default:
        g_assert_not_reached();
    }
    return true;
}

/* Loads a 32-bit immediate into rd, sign-extended.  */
static void tcg_out_movi_i32(TCGContext *s, TCGReg rd, int32_t val)
{
    tcg_target_long lo = sextreg(val, 0, 12);
    tcg_target_long hi12 = sextreg(val, 12, 20);

    /* Single-instruction cases.  */
    if (hi12 == 0) {
        /* val fits in uimm12: ori rd, zero, val */
        tcg_out_opc_ori(s, rd, TCG_REG_ZERO, val);
        return;
    }
    if (hi12 == sextreg(lo, 12, 20)) {
        /* val fits in simm12: addi.w rd, zero, val */
        tcg_out_opc_addi_w(s, rd, TCG_REG_ZERO, val);
        return;
    }

    /* High bits must be set; load with lu12i.w + optional ori.  */
    tcg_out_opc_lu12i_w(s, rd, hi12);
    if (lo != 0) {
        tcg_out_opc_ori(s, rd, rd, lo & 0xfff);
    }
}

static void tcg_out_movi(TCGContext *s, TCGType type, TCGReg rd,
                         tcg_target_long val)
{
    /*
     * LoongArch conventionally loads 64-bit immediates in at most 4 steps,
     * with dedicated instructions for filling the respective bitfields
     * below:
     *
     *        6                   5                   4               3
     *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2
     * +-----------------------+---------------------------------------+...
     * |          hi52         |                  hi32                 |
     * +-----------------------+---------------------------------------+...
     *       3                   2                   1
     *     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
     * ...+-------------------------------------+-------------------------+
     *    |                 hi12                |            lo           |
     * ...+-------------------------------------+-------------------------+
     *
     * Check if val belong to one of the several fast cases, before falling
     * back to the slow path.
     */

    intptr_t pc_offset;
    tcg_target_long val_lo, val_hi, pc_hi, offset_hi;
    tcg_target_long hi12, hi32, hi52;

    /* Value fits in signed i32.  */
    if (type == TCG_TYPE_I32 || val == (int32_t)val) {
        tcg_out_movi_i32(s, rd, val);
        return;
    }

    /* PC-relative cases.  */
    pc_offset = tcg_pcrel_diff(s, (void *)val);
    if (pc_offset == sextreg(pc_offset, 0, 22) && (pc_offset & 3) == 0) {
        /* Single pcaddu2i.  */
        tcg_out_opc_pcaddu2i(s, rd, pc_offset >> 2);
        return;
    }

    if (pc_offset == (int32_t)pc_offset) {
        /* Offset within 32 bits; load with pcalau12i + ori.  */
        val_lo = sextreg(val, 0, 12);
        val_hi = val >> 12;
        pc_hi = (val - pc_offset) >> 12;
        offset_hi = val_hi - pc_hi;

        tcg_debug_assert(offset_hi == sextreg(offset_hi, 0, 20));
        tcg_out_opc_pcalau12i(s, rd, offset_hi);
        if (val_lo != 0) {
            tcg_out_opc_ori(s, rd, rd, val_lo & 0xfff);
        }
        return;
    }

    hi12 = sextreg(val, 12, 20);
    hi32 = sextreg(val, 32, 20);
    hi52 = sextreg(val, 52, 12);

    /* Single cu52i.d case.  */
    if ((hi52 != 0) && (ctz64(val) >= 52)) {
        tcg_out_opc_cu52i_d(s, rd, TCG_REG_ZERO, hi52);
        return;
    }

    /* Slow path.  Initialize the low 32 bits, then concat high bits.  */
    tcg_out_movi_i32(s, rd, val);

    /* Load hi32 and hi52 explicitly when they are unexpected values. */
    if (hi32 != sextreg(hi12, 20, 20)) {
        tcg_out_opc_cu32i_d(s, rd, hi32);
    }

    if (hi52 != sextreg(hi32, 20, 12)) {
        tcg_out_opc_cu52i_d(s, rd, rd, hi52);
    }
}

static void tcg_out_addi(TCGContext *s, TCGType type, TCGReg rd,
                         TCGReg rs, tcg_target_long imm)
{
    tcg_target_long lo12 = sextreg(imm, 0, 12);
    tcg_target_long hi16 = sextreg(imm - lo12, 16, 16);

    /*
     * Note that there's a hole in between hi16 and lo12:
     *
     *       3                   2                   1                   0
     *     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
     * ...+-------------------------------+-------+-----------------------+
     *    |             hi16              |       |          lo12         |
     * ...+-------------------------------+-------+-----------------------+
     *
     * For bits within that hole, it's more efficient to use LU12I and ADD.
     */
    if (imm == (hi16 << 16) + lo12) {
        if (hi16) {
            tcg_out_opc_addu16i_d(s, rd, rs, hi16);
            rs = rd;
        }
        if (type == TCG_TYPE_I32) {
            tcg_out_opc_addi_w(s, rd, rs, lo12);
        } else if (lo12) {
            tcg_out_opc_addi_d(s, rd, rs, lo12);
        } else {
            tcg_out_mov(s, type, rd, rs);
        }
    } else {
        tcg_out_movi(s, type, TCG_REG_TMP0, imm);
        if (type == TCG_TYPE_I32) {
            tcg_out_opc_add_w(s, rd, rs, TCG_REG_TMP0);
        } else {
            tcg_out_opc_add_d(s, rd, rs, TCG_REG_TMP0);
        }
    }
}

static bool tcg_out_xchg(TCGContext *s, TCGType type, TCGReg r1, TCGReg r2)
{
    return false;
}

static void tcg_out_addi_ptr(TCGContext *s, TCGReg rd, TCGReg rs,
                             tcg_target_long imm)
{
    /* This function is only used for passing structs by reference. */
    g_assert_not_reached();
}

static void tcg_out_ext8u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    tcg_out_opc_andi(s, ret, arg, 0xff);
}

static void tcg_out_ext16u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    tcg_out_opc_bstrpick_w(s, ret, arg, 0, 15);
}

static void tcg_out_ext32u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    tcg_out_opc_bstrpick_d(s, ret, arg, 0, 31);
}

static void tcg_out_ext8s(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    tcg_out_opc_sext_b(s, ret, arg);
}

static void tcg_out_ext16s(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    tcg_out_opc_sext_h(s, ret, arg);
}

static void tcg_out_ext32s(TCGContext *s, TCGReg ret, TCGReg arg)
{
    tcg_out_opc_addi_w(s, ret, arg, 0);
}

static void tcg_out_exts_i32_i64(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (ret != arg) {
        tcg_out_ext32s(s, ret, arg);
    }
}

static void tcg_out_extu_i32_i64(TCGContext *s, TCGReg ret, TCGReg arg)
{
    tcg_out_ext32u(s, ret, arg);
}

static void tcg_out_extrl_i64_i32(TCGContext *s, TCGReg ret, TCGReg arg)
{
    tcg_out_ext32s(s, ret, arg);
}

static void tcg_out_clzctz(TCGContext *s, LoongArchInsn opc,
                           TCGReg a0, TCGReg a1, TCGReg a2,
                           bool c2, bool is_32bit)
{
    if (c2) {
        /*
         * Fast path: semantics already satisfied due to constraint and
         * insn behavior, single instruction is enough.
         */
        tcg_debug_assert(a2 == (is_32bit ? 32 : 64));
        /* all clz/ctz insns belong to DJ-format */
        tcg_out32(s, encode_dj_insn(opc, a0, a1));
        return;
    }

    tcg_out32(s, encode_dj_insn(opc, TCG_REG_TMP0, a1));
    /* a0 = a1 ? REG_TMP0 : a2 */
    tcg_out_opc_maskeqz(s, TCG_REG_TMP0, TCG_REG_TMP0, a1);
    tcg_out_opc_masknez(s, a0, a2, a1);
    tcg_out_opc_or(s, a0, TCG_REG_TMP0, a0);
}

#define SETCOND_INV    TCG_TARGET_NB_REGS
#define SETCOND_NEZ    (SETCOND_INV << 1)
#define SETCOND_FLAGS  (SETCOND_INV | SETCOND_NEZ)

static int tcg_out_setcond_int(TCGContext *s, TCGCond cond, TCGReg ret,
                               TCGReg arg1, tcg_target_long arg2, bool c2)
{
    int flags = 0;

    switch (cond) {
    case TCG_COND_EQ:    /* -> NE  */
    case TCG_COND_GE:    /* -> LT  */
    case TCG_COND_GEU:   /* -> LTU */
    case TCG_COND_GT:    /* -> LE  */
    case TCG_COND_GTU:   /* -> LEU */
        cond = tcg_invert_cond(cond);
        flags ^= SETCOND_INV;
        break;
    default:
        break;
    }

    switch (cond) {
    case TCG_COND_LE:
    case TCG_COND_LEU:
        /*
         * If we have a constant input, the most efficient way to implement
         * LE is by adding 1 and using LT.  Watch out for wrap around for LEU.
         * We don't need to care for this for LE because the constant input
         * is still constrained to int32_t, and INT32_MAX+1 is representable
         * in the 64-bit temporary register.
         */
        if (c2) {
            if (cond == TCG_COND_LEU) {
                /* unsigned <= -1 is true */
                if (arg2 == -1) {
                    tcg_out_movi(s, TCG_TYPE_REG, ret, !(flags & SETCOND_INV));
                    return ret;
                }
                cond = TCG_COND_LTU;
            } else {
                cond = TCG_COND_LT;
            }
            arg2 += 1;
        } else {
            TCGReg tmp = arg2;
            arg2 = arg1;
            arg1 = tmp;
            cond = tcg_swap_cond(cond);    /* LE -> GE */
            cond = tcg_invert_cond(cond);  /* GE -> LT */
            flags ^= SETCOND_INV;
        }
        break;
    default:
        break;
    }

    switch (cond) {
    case TCG_COND_NE:
        flags |= SETCOND_NEZ;
        if (!c2) {
            tcg_out_opc_xor(s, ret, arg1, arg2);
        } else if (arg2 == 0) {
            ret = arg1;
        } else if (arg2 >= 0 && arg2 <= 0xfff) {
            tcg_out_opc_xori(s, ret, arg1, arg2);
        } else {
            tcg_out_addi(s, TCG_TYPE_REG, ret, arg1, -arg2);
        }
        break;

    case TCG_COND_LT:
    case TCG_COND_LTU:
        if (c2) {
            if (arg2 >= -0x800 && arg2 <= 0x7ff) {
                if (cond == TCG_COND_LT) {
                    tcg_out_opc_slti(s, ret, arg1, arg2);
                } else {
                    tcg_out_opc_sltui(s, ret, arg1, arg2);
                }
                break;
            }
            tcg_out_movi(s, TCG_TYPE_REG, TCG_REG_TMP0, arg2);
            arg2 = TCG_REG_TMP0;
        }
        if (cond == TCG_COND_LT) {
            tcg_out_opc_slt(s, ret, arg1, arg2);
        } else {
            tcg_out_opc_sltu(s, ret, arg1, arg2);
        }
        break;

    default:
        g_assert_not_reached();
        break;
    }

    return ret | flags;
}

static void tcg_out_setcond(TCGContext *s, TCGCond cond, TCGReg ret,
                            TCGReg arg1, tcg_target_long arg2, bool c2)
{
    int tmpflags = tcg_out_setcond_int(s, cond, ret, arg1, arg2, c2);

    if (tmpflags != ret) {
        TCGReg tmp = tmpflags & ~SETCOND_FLAGS;

        switch (tmpflags & SETCOND_FLAGS) {
        case SETCOND_INV:
            /* Intermediate result is boolean: simply invert. */
            tcg_out_opc_xori(s, ret, tmp, 1);
            break;
        case SETCOND_NEZ:
            /* Intermediate result is zero/non-zero: test != 0. */
            tcg_out_opc_sltu(s, ret, TCG_REG_ZERO, tmp);
            break;
        case SETCOND_NEZ | SETCOND_INV:
            /* Intermediate result is zero/non-zero: test == 0. */
            tcg_out_opc_sltui(s, ret, tmp, 1);
            break;
        default:
            g_assert_not_reached();
        }
    }
}

static void tcg_out_movcond(TCGContext *s, TCGCond cond, TCGReg ret,
                            TCGReg c1, tcg_target_long c2, bool const2,
                            TCGReg v1, TCGReg v2)
{
    int tmpflags = tcg_out_setcond_int(s, cond, TCG_REG_TMP0, c1, c2, const2);
    TCGReg t;

    /* Standardize the test below to t != 0. */
    if (tmpflags & SETCOND_INV) {
        t = v1, v1 = v2, v2 = t;
    }

    t = tmpflags & ~SETCOND_FLAGS;
    if (v1 == TCG_REG_ZERO) {
        tcg_out_opc_masknez(s, ret, v2, t);
    } else if (v2 == TCG_REG_ZERO) {
        tcg_out_opc_maskeqz(s, ret, v1, t);
    } else {
        tcg_out_opc_masknez(s, TCG_REG_TMP2, v2, t); /* t ? 0 : v2 */
        tcg_out_opc_maskeqz(s, TCG_REG_TMP1, v1, t); /* t ? v1 : 0 */
        tcg_out_opc_or(s, ret, TCG_REG_TMP1, TCG_REG_TMP2);
    }
}

/*
 * Branch helpers
 */

static const struct {
    LoongArchInsn op;
    bool swap;
} tcg_brcond_to_loongarch[] = {
    [TCG_COND_EQ] =  { OPC_BEQ,  false },
    [TCG_COND_NE] =  { OPC_BNE,  false },
    [TCG_COND_LT] =  { OPC_BGT,  true  },
    [TCG_COND_GE] =  { OPC_BLE,  true  },
    [TCG_COND_LE] =  { OPC_BLE,  false },
    [TCG_COND_GT] =  { OPC_BGT,  false },
    [TCG_COND_LTU] = { OPC_BGTU, true  },
    [TCG_COND_GEU] = { OPC_BLEU, true  },
    [TCG_COND_LEU] = { OPC_BLEU, false },
    [TCG_COND_GTU] = { OPC_BGTU, false }
};

static void tcg_out_brcond(TCGContext *s, TCGCond cond, TCGReg arg1,
                           TCGReg arg2, TCGLabel *l)
{
    LoongArchInsn op = tcg_brcond_to_loongarch[cond].op;

    tcg_debug_assert(op != 0);

    if (tcg_brcond_to_loongarch[cond].swap) {
        TCGReg t = arg1;
        arg1 = arg2;
        arg2 = t;
    }

    /* all conditional branch insns belong to DJSk16-format */
    tcg_out_reloc(s, s->code_ptr, R_LOONGARCH_BR_SK16, l, 0);
    tcg_out32(s, encode_djsk16_insn(op, arg1, arg2, 0));
}

static void tcg_out_call_int(TCGContext *s, const tcg_insn_unit *arg, bool tail)
{
    TCGReg link = tail ? TCG_REG_ZERO : TCG_REG_RA;
    ptrdiff_t offset = tcg_pcrel_diff(s, (void *)arg);

    tcg_debug_assert((offset & 3) == 0);
    if (offset == sextreg(offset, 0, 28)) {
        /* short jump: +/- 256MiB */
        if (tail) {
            tcg_out_opc_b(s, offset >> 2);
        } else {
            tcg_out_opc_bl(s, offset >> 2);
        }
    } else if (offset == sextreg(offset, 0, 38)) {
        /* long jump: +/- 256GiB */
        tcg_target_long lo = sextreg(offset, 0, 18);
        tcg_target_long hi = offset - lo;
        tcg_out_opc_pcaddu18i(s, TCG_REG_TMP0, hi >> 18);
        tcg_out_opc_jirl(s, link, TCG_REG_TMP0, lo >> 2);
    } else {
        /* far jump: 64-bit */
        tcg_target_long lo = sextreg((tcg_target_long)arg, 0, 18);
        tcg_target_long hi = (tcg_target_long)arg - lo;
        tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_TMP0, hi);
        tcg_out_opc_jirl(s, link, TCG_REG_TMP0, lo >> 2);
    }
}

static void tcg_out_call(TCGContext *s, tcg_insn_unit *target)
{
    tcg_out_call_int(s, target, false);
}

/*
 * Load/store helpers
 */

static void tcg_out_ldst(TCGContext *s, LoongArchInsn opc, TCGReg data,
                         TCGReg addr, intptr_t offset)
{
    intptr_t imm12 = sextreg(offset, 0, 12);

    if (offset != imm12) {
        intptr_t diff = tcg_pcrel_diff(s, (void *)offset);

        if (addr == TCG_REG_ZERO && diff == (int32_t)diff) {
            imm12 = sextreg(diff, 0, 12);
            tcg_out_opc_pcaddu12i(s, TCG_REG_TMP2, (diff - imm12) >> 12);
        } else {
            tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_TMP2, offset - imm12);
            if (addr != TCG_REG_ZERO) {
                tcg_out_opc_add_d(s, TCG_REG_TMP2, TCG_REG_TMP2, addr);
            }
        }
        addr = TCG_REG_TMP2;
    }

    switch (opc) {
    case OPC_LD_B:
    case OPC_LD_BU:
    case OPC_LD_H:
    case OPC_LD_HU:
    case OPC_LD_W:
    case OPC_LD_WU:
    case OPC_LD_D:
    case OPC_ST_B:
    case OPC_ST_H:
    case OPC_ST_W:
    case OPC_ST_D:
        tcg_out32(s, encode_djsk12_insn(opc, data, addr, imm12));
        break;
    default:
        g_assert_not_reached();
    }
}

static void tcg_out_ld(TCGContext *s, TCGType type, TCGReg arg,
                       TCGReg arg1, intptr_t arg2)
{
    bool is_32bit = type == TCG_TYPE_I32;
    tcg_out_ldst(s, is_32bit ? OPC_LD_W : OPC_LD_D, arg, arg1, arg2);
}

static void tcg_out_st(TCGContext *s, TCGType type, TCGReg arg,
                       TCGReg arg1, intptr_t arg2)
{
    bool is_32bit = type == TCG_TYPE_I32;
    tcg_out_ldst(s, is_32bit ? OPC_ST_W : OPC_ST_D, arg, arg1, arg2);
}

static bool tcg_out_sti(TCGContext *s, TCGType type, TCGArg val,
                        TCGReg base, intptr_t ofs)
{
    if (val == 0) {
        tcg_out_st(s, type, TCG_REG_ZERO, base, ofs);
        return true;
    }
    return false;
}

/*
 * Load/store helpers for SoftMMU, and qemu_ld/st implementations
 */
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
#if TCG_TARGET_REG_BITS == 64
    [MO_LESL] = helper_le_ldsl_mmu,
    [MO_BESL] = helper_be_ldsl_mmu,
#endif
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
 * extended before use).
 */

static int tcg_out_call_iarg_reg(TCGContext *s, int i, TCGReg arg)
{
    if (i < ARRAY_SIZE(tcg_target_call_iarg_regs)) {
        tcg_out_mov(s, TCG_TYPE_REG, tcg_target_call_iarg_regs[i], arg);
    } 
    return i + 1;
}

static int tcg_out_call_iarg_reg8(TCGContext *s, int i, TCGReg arg)
{
    TCGReg tmp = TCG_REG_TMP0;
    if (i < ARRAY_SIZE(tcg_target_call_iarg_regs)) {
        tmp = tcg_target_call_iarg_regs[i];
    }
    tcg_out_opc_andi(s, tmp, arg, 0xff);
    return tcg_out_call_iarg_reg(s, i, tmp);
}

static int tcg_out_call_iarg_reg16(TCGContext *s, int i, TCGReg arg)
{
    TCGReg tmp = TCG_REG_TMP0;
    if (i < ARRAY_SIZE(tcg_target_call_iarg_regs)) {
        tmp = tcg_target_call_iarg_regs[i];
    }
    tcg_out_opc_andi(s, tmp, arg, 0xffff);
    return tcg_out_call_iarg_reg(s, i, tmp);
}

static int tcg_out_call_iarg_imm(TCGContext *s, int i, TCGArg arg)
{
    TCGReg tmp = TCG_REG_TMP0;
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

static bool tcg_out_goto(TCGContext *s, const tcg_insn_unit *target)
{
    tcg_out_opc_b(s, 0);
    return reloc_br_sd10k16(s->code_ptr - 1, target);
}

static bool tcg_out_qemu_ld_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    TCGMemOpIdx oi = l->oi;
    MemOp opc = get_memop(oi);
    MemOp size = opc & MO_SIZE;
    TCGType type = l->type;

    /* resolve label address */
    if (!reloc_br_sk16(l->label_ptr[0], (s->code_ptr))) {
        return false;
    }

    /* call load helper */
    tcg_out_mov(s, TCG_TYPE_PTR, TCG_REG_A0, TCG_AREG0);
    tcg_out_mov(s, TCG_TYPE_PTR, TCG_REG_A1, l->addrlo_reg);
    tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_A2, oi);
    tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_A3, (tcg_target_long)l->raddr);

    tcg_out_call(s, qemu_ld_helpers[size]);

    switch (opc & MO_SSIZE) {
    case MO_SB:
        tcg_out_ext8s(s, type, l->datalo_reg, TCG_REG_A0);
        break;
    case MO_SW:
        tcg_out_ext16s(s, type, l->datalo_reg, TCG_REG_A0);
        break;
    case MO_SL:
        tcg_out_ext32s(s, l->datalo_reg, TCG_REG_A0);
        break;
    case MO_UL:
        if (type == TCG_TYPE_I32) {
            /* MO_UL loads of i32 should be sign-extended too */
            tcg_out_ext32s(s, l->datalo_reg, TCG_REG_A0);
            break;
        }
        /* fallthrough */
    default:
        tcg_out_mov(s, type, l->datalo_reg, TCG_REG_A0);
        break;
    }

    return tcg_out_goto(s, l->raddr);
}

static bool tcg_out_qemu_st_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    TCGMemOpIdx oi = l->oi;
    MemOp opc = get_memop(oi);
    MemOp size = opc & MO_SIZE;

    /* resolve label address */
    if (!reloc_br_sk16(l->label_ptr[0], (s->code_ptr))) {
        return false;
    }

    /* call store helper */
    tcg_out_mov(s, TCG_TYPE_PTR, TCG_REG_A0, TCG_AREG0);
    tcg_out_mov(s, TCG_TYPE_PTR, TCG_REG_A1, l->addrlo_reg);
    switch (size) {
    case MO_8:
        tcg_out_ext8u(s, TCG_REG_A2, l->datalo_reg);
        break;
    case MO_16:
        tcg_out_ext16u(s, TCG_REG_A2, l->datalo_reg);
        break;
    case MO_32:
        tcg_out_ext32u(s, TCG_REG_A2, l->datalo_reg);
        break;
    case MO_64:
        tcg_out_mov(s, TCG_TYPE_I64, TCG_REG_A2, l->datalo_reg);
        break;
    default:
        g_assert_not_reached();
        break;
    }
    tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_A3, oi);
    tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_A4, (tcg_target_long)l->raddr);

    tcg_out_call(s, qemu_st_helpers[size]);

    return tcg_out_goto(s, l->raddr);
}

typedef struct {
    MemOp atom;   /* lg2 bits of atomicity required */
    MemOp align;  /* lg2 bits of alignment to use */
} TCGAtomAlign;

typedef struct {
    TCGReg base;
    TCGReg index;
} HostAddress;

// bool tcg_target_has_memory_bswap(MemOp memop)
// {
//     return false;
// }

/* We expect to use a 12-bit negative offset from ENV.  */
#define MIN_TLB_MASK_TABLE_OFS  -(1 << 11)

#if defined(CONFIG_SOFTMMU) && !defined(CONFIG_TCG_INTERPRETER)
static int tlb_mask_table_ofs(TCGContext *s, int which)
{
    return (offsetof(CPUNegativeOffsetState, tlb.f[which]) -
            sizeof(CPUNegativeOffsetState));
}
#endif

/*
 * For softmmu, perform the TLB load and compare.
 * For useronly, perform any required alignment tests.
 * In both cases, return a TCGLabelQemuLdst structure if the slow path
 * is required and fill in @h with the host address for the fast path.
 */
static TCGLabelQemuLdst *prepare_host_addr(TCGContext *s, HostAddress *h,
                                           TCGReg addr_reg, TCGMemOpIdx oi,
                                           bool is_ld, TCGType addr_type)
{
#ifdef TARGET_ARM
    struct uc_struct *uc = s->uc;
#endif

    TCGLabelQemuLdst *ldst = NULL;
    MemOp opc = get_memop(oi);
    MemOp a_bits = get_alignment_bits(opc);

#ifdef CONFIG_SOFTMMU
    unsigned s_bits = opc & MO_SIZE;
    int mem_index = get_mmuidx(oi);
    int fast_ofs = TLB_MASK_TABLE_OFS(mem_index);
    int mask_ofs = fast_ofs + offsetof(CPUTLBDescFast, mask);
    int table_ofs = fast_ofs + offsetof(CPUTLBDescFast, table);

    ldst = new_ldst_label(s);
    ldst->is_ld = is_ld;
    ldst->oi = oi;
    ldst->addrlo_reg = addr_reg;

    tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_TMP0, TCG_AREG0, mask_ofs);
    tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_TMP1, TCG_AREG0, table_ofs);

    tcg_out_opc_srli_d(s, TCG_REG_TMP2, addr_reg,
                    TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);
    tcg_out_opc_and(s, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP0);
    tcg_out_opc_add_d(s, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP1);

    /* Load the tlb comparator and the addend.  */
    // QEMU_BUILD_BUG_ON(HOST_BIG_ENDIAN);
    tcg_out_ld(s, addr_type, TCG_REG_TMP0, TCG_REG_TMP2,
               is_ld ? offsetof(CPUTLBEntry, addr_read)
                     : offsetof(CPUTLBEntry, addr_write));
    tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_TMP2, TCG_REG_TMP2,
               offsetof(CPUTLBEntry, addend));

    /*
     * For aligned accesses, we check the first byte and include the alignment
     * bits within the address.  For unaligned access, we check that we don't
     * cross pages using the address of the last byte of the access.
     */
    if (a_bits < s_bits) {
        unsigned a_mask = (1u << a_bits) - 1;
        unsigned s_mask = (1u << s_bits) - 1;
        tcg_out_addi(s, addr_type, TCG_REG_TMP1, addr_reg, s_mask - a_mask);
    } else {
        tcg_out_mov(s, addr_type, TCG_REG_TMP1, addr_reg);
    }
    tcg_out_opc_bstrins_d(s, TCG_REG_TMP1, TCG_REG_ZERO,
                          a_bits, TARGET_PAGE_BITS - 1);

    /* Compare masked address with the TLB entry.  */
    ldst->label_ptr[0] = s->code_ptr;
    // tcg_out_opc_bne(s, TCG_REG_TMP0, TCG_REG_TMP1, 0);
    tcg_out_opc_beq(s, 0, 0, 0);

    h->index = TCG_REG_TMP2;
#else
    if (a_bits) {
        ldst = new_ldst_label(s);

        ldst->is_ld = is_ld;
        ldst->oi = oi;
        ldst->addrlo_reg = addr_reg;

        /*
         * Without micro-architecture details, we don't know which of
         * bstrpick or andi is faster, so use bstrpick as it's not
         * constrained by imm field width. Not to say alignments >= 2^12
         * are going to happen any time soon.
         */
        tcg_out_opc_bstrpick_d(s, TCG_REG_TMP1, addr_reg, 0, a_bits - 1);

        ldst->label_ptr[0] = s->code_ptr;
        tcg_out_opc_bne(s, TCG_REG_TMP1, TCG_REG_ZERO, 0);
    }

    h->index = USE_GUEST_BASE ? TCG_GUEST_BASE_REG : TCG_REG_ZERO;
#endif

    if (addr_type == TCG_TYPE_I32) {
        h->base = TCG_REG_TMP0;
        tcg_out_ext32u(s, h->base, addr_reg);
    } else {
        h->base = addr_reg;
    }

    return ldst;
}

// static TCGLabelQemuLdst *prepare_host_addr(TCGContext *s, HostAddress *h,
//                                            TCGReg addr_reg, TCGMemOpIdx oi,
//                                            bool is_ld, TCGType addr_type)
// {
//     TCGLabelQemuLdst *ldst = NULL;
//     MemOp opc = get_memop(oi);
//     unsigned a_bits = get_alignment_bits(opc);

// #ifdef CONFIG_SOFTMMU
//     unsigned s_bits = opc & MO_SIZE;
//     int mem_index = get_mmuidx(oi);
//     int table_ofs = offsetof(CPUArchState, tlb_table[mem_index][0]);
//     int mask = (target_ulong)TARGET_PAGE_MASK | ((1 << a_bits) - 1);

//     ldst = new_ldst_label(s);
//     ldst->is_ld = is_ld;
//     ldst->oi = oi;
//     ldst->addrlo_reg = addr_reg;

//     tcg_out_movi(s, TCG_TYPE_TL, TCG_REG_TMP0, mask);

//     tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_TMP1, TCG_AREG0, table_ofs);

//     tcg_out_opc_srli_d(s, TCG_REG_TMP2, addr_reg,
//                     TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);
//     tcg_out_opc_and(s, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP0);
//     tcg_out_opc_add_d(s, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP1);

//     /* Load the tlb comparator and the addend.  */
//     tcg_out_ld(s, addr_type, TCG_REG_TMP0, TCG_REG_TMP2,
//                is_ld ? offsetof(CPUTLBEntry, addr_read)
//                      : offsetof(CPUTLBEntry, addr_write));
//     tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_TMP2, TCG_REG_TMP2,
//                offsetof(CPUTLBEntry, addend));

//     /*
//      * For aligned accesses, we check the first byte and include the alignment
//      * bits within the address.  For unaligned access, we check that we don't
//      * cross pages using the address of the last byte of the access.
//      */
//     if (a_bits < s_bits) {
//         unsigned a_mask = (1u << a_bits) - 1;
//         unsigned s_mask = (1u << s_bits) - 1;
//         tcg_out_addi(s, addr_type, TCG_REG_TMP1, addr_reg, s_mask - a_mask);
//     } else {
//         tcg_out_mov(s, addr_type, TCG_REG_TMP1, addr_reg);
//     }
//     tcg_out_opc_bstrins_d(s, TCG_REG_TMP1, TCG_REG_ZERO,
//                           a_bits, TARGET_PAGE_BITS - 1);

//     /* Compare masked address with the TLB entry.  */
//     ldst->label_ptr[0] = s->code_ptr;
//     tcg_out_opc_bne(s, TCG_REG_TMP0, TCG_REG_TMP1, 0);

//     h->index = TCG_REG_TMP2;
// #else
//     if (a_bits) {
//         ldst = new_ldst_label(s);

//         ldst->is_ld = is_ld;
//         ldst->oi = oi;
//         ldst->addrlo_reg = addr_reg;

//         /*
//          * Without micro-architecture details, we don't know which of
//          * bstrpick or andi is faster, so use bstrpick as it's not
//          * constrained by imm field width. Not to say alignments >= 2^12
//          * are going to happen any time soon.
//          */
//         tcg_out_opc_bstrpick_d(s, TCG_REG_TMP1, addr_reg, 0, a_bits - 1);

//         ldst->label_ptr[0] = s->code_ptr;
//         tcg_out_opc_bne(s, TCG_REG_TMP1, TCG_REG_ZERO, 0);
//     }

//     h->index = USE_GUEST_BASE ? TCG_GUEST_BASE_REG : TCG_REG_ZERO;
// #endif

//     if (addr_type == TCG_TYPE_I32) {
//         h->base = TCG_REG_TMP0;
//         tcg_out_ext32u(s, h->base, addr_reg);
//     } else {
//         h->base = addr_reg;
//     }

//     return ldst;
// }

static void tcg_out_qemu_ld_indexed(TCGContext *s, MemOp opc, TCGType type,
                                    TCGReg rd, HostAddress h)
{
    /* Byte swapping is left to middle-end expansion.  */
    tcg_debug_assert((opc & MO_BSWAP) == 0);

    switch (opc & MO_SSIZE) {
    case MO_UB:
        tcg_out_opc_ldx_bu(s, rd, h.base, h.index);
        break;
    case MO_SB:
        tcg_out_opc_ldx_b(s, rd, h.base, h.index);
        break;
    case MO_UW:
        tcg_out_opc_ldx_hu(s, rd, h.base, h.index);
        break;
    case MO_SW:
        tcg_out_opc_ldx_h(s, rd, h.base, h.index);
        break;
    case MO_UL:
        if (type == TCG_TYPE_I64) {
            tcg_out_opc_ldx_wu(s, rd, h.base, h.index);
            break;
        }
        /* fallthrough */
    case MO_SL:
        tcg_out_opc_ldx_w(s, rd, h.base, h.index);
        break;
    case MO_Q:
        tcg_out_opc_ldx_d(s, rd, h.base, h.index);
        break;
    default:
        g_assert_not_reached();
    }
}

static void tcg_out_qemu_ld(TCGContext *s, TCGReg data_reg, TCGReg addr_reg,
                            TCGMemOpIdx oi, TCGType data_type)
{
    TCGLabelQemuLdst *ldst;
    HostAddress h;

    ldst = prepare_host_addr(s, &h, addr_reg, oi, true, data_type);
    tcg_out_qemu_ld_indexed(s, get_memop(oi), data_type, data_reg, h);

    if (ldst) {
        ldst->type = data_type;
        ldst->datalo_reg = data_reg;
        ldst->raddr = s->code_ptr;
    }
}

static void tcg_out_qemu_st_indexed(TCGContext *s, MemOp opc,
                                    TCGReg rd, HostAddress h)
{
    /* Byte swapping is left to middle-end expansion.  */
    tcg_debug_assert((opc & MO_BSWAP) == 0);

    switch (opc & MO_SIZE) {
    case MO_8:
        tcg_out_opc_stx_b(s, rd, h.base, h.index);
        break;
    case MO_16:
        tcg_out_opc_stx_h(s, rd, h.base, h.index);
        break;
    case MO_32:
        tcg_out_opc_stx_w(s, rd, h.base, h.index);
        break;
    case MO_64:
        tcg_out_opc_stx_d(s, rd, h.base, h.index);
        break;
    default:
        g_assert_not_reached();
    }
}

static void tcg_out_qemu_st(TCGContext *s, TCGReg data_reg, TCGReg addr_reg,
                            TCGMemOpIdx oi, TCGType data_type)
{
    TCGLabelQemuLdst *ldst;
    HostAddress h;

    ldst = prepare_host_addr(s, &h, addr_reg, oi, false, data_type);
    tcg_out_qemu_st_indexed(s, get_memop(oi), data_reg, h);

    if (ldst) {
        ldst->type = data_type;
        ldst->datalo_reg = data_reg;
        ldst->raddr = s->code_ptr;
    }
}

/*
 * Entry-points
 */

// static tcg_insn_unit *tcg_code_gen_epilogue;
// static tcg_insn_unit *tb_ret_addr;

static void tcg_out_exit_tb(TCGContext *s, uintptr_t a0)
{
    /* Reuse the zeroing that exists for goto_ptr.  */
    if (a0 == 0) {
        tcg_out_call_int(s, s->code_gen_epilogue, true);
    } else {
        tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_A0, a0);
        tcg_out_call_int(s, s->tb_ret_addr, true);
    }
}

void tb_target_set_jmp_target(uintptr_t tc_ptr, uintptr_t jmp_addr,
                              uintptr_t addr)
{
    uintptr_t d_addr = addr;
    ptrdiff_t d_disp = (ptrdiff_t)(d_addr - jmp_addr) >> 2;
    tcg_insn_unit insn;

    /* Either directly branch, or load slot address for indirect branch. */
    if (d_disp == sextreg(d_disp, 0, 26)) {
        insn = encode_sd10k16_insn(OPC_B, d_disp);
    } else {
        uintptr_t i_addr = addr;
        intptr_t i_disp = i_addr - jmp_addr;
        insn = encode_dsj20_insn(OPC_PCADDU2I, TCG_REG_TMP0, i_disp >> 2);
    }

    *(tcg_insn_unit *)jmp_addr =  insn;
    // flush_idcache_range(jmp_rx, jmp_rw, 4);
    flush_icache_range(jmp_addr, jmp_addr + 8);
}

static void tcg_out_op(TCGContext *s, TCGOpcode opc,
                       const TCGArg args[TCG_MAX_OP_ARGS],
                       const int const_args[TCG_MAX_OP_ARGS])
{
    TCGArg a0 = args[0];
    TCGArg a1 = args[1];
    TCGArg a2 = args[2];
    TCGArg a3 = args[3];
    int c2 = const_args[2];

    switch (opc) {
    case INDEX_op_mb:
        tcg_out_mb(s, a0);
        break;

    case INDEX_op_goto_ptr:
        tcg_out_opc_jirl(s, TCG_REG_ZERO, a0, 0);
        break;

    case INDEX_op_br:
        tcg_out_reloc(s, s->code_ptr, R_LOONGARCH_BR_SD10K16, arg_label(a0),
                      0);
        tcg_out_opc_b(s, 0);
        break;

    case INDEX_op_brcond_i32:
    case INDEX_op_brcond_i64:
        tcg_out_brcond(s, a2, a0, a1, arg_label(args[3]));
        break;

    case INDEX_op_extrh_i64_i32:
        tcg_out_opc_srai_d(s, a0, a1, 32);
        break;

    case INDEX_op_not_i32:
    case INDEX_op_not_i64:
        tcg_out_opc_nor(s, a0, a1, TCG_REG_ZERO);
        break;

    case INDEX_op_nor_i32:
    case INDEX_op_nor_i64:
        if (c2) {
            tcg_out_opc_ori(s, a0, a1, a2);
            tcg_out_opc_nor(s, a0, a0, TCG_REG_ZERO);
        } else {
            tcg_out_opc_nor(s, a0, a1, a2);
        }
        break;

    case INDEX_op_andc_i32:
    case INDEX_op_andc_i64:
        if (c2) {
            /* guaranteed to fit due to constraint */
            tcg_out_opc_andi(s, a0, a1, ~a2);
        } else {
            tcg_out_opc_andn(s, a0, a1, a2);
        }
        break;

    case INDEX_op_orc_i32:
    case INDEX_op_orc_i64:
        if (c2) {
            /* guaranteed to fit due to constraint */
            tcg_out_opc_ori(s, a0, a1, ~a2);
        } else {
            tcg_out_opc_orn(s, a0, a1, a2);
        }
        break;

    case INDEX_op_and_i32:
    case INDEX_op_and_i64:
        if (c2) {
            tcg_out_opc_andi(s, a0, a1, a2);
        } else {
            tcg_out_opc_and(s, a0, a1, a2);
        }
        break;

    case INDEX_op_or_i32:
    case INDEX_op_or_i64:
        if (c2) {
            tcg_out_opc_ori(s, a0, a1, a2);
        } else {
            tcg_out_opc_or(s, a0, a1, a2);
        }
        break;

    case INDEX_op_xor_i32:
    case INDEX_op_xor_i64:
        if (c2) {
            tcg_out_opc_xori(s, a0, a1, a2);
        } else {
            tcg_out_opc_xor(s, a0, a1, a2);
        }
        break;

    case INDEX_op_extract_i32:
        tcg_out_opc_bstrpick_w(s, a0, a1, a2, a2 + args[3] - 1);
        break;
    case INDEX_op_extract_i64:
        tcg_out_opc_bstrpick_d(s, a0, a1, a2, a2 + args[3] - 1);
        break;

    case INDEX_op_deposit_i32:
        tcg_out_opc_bstrins_w(s, a0, a2, args[3], args[3] + args[4] - 1);
        break;
    case INDEX_op_deposit_i64:
        tcg_out_opc_bstrins_d(s, a0, a2, args[3], args[3] + args[4] - 1);
        break;

    case INDEX_op_bswap16_i32:
    case INDEX_op_bswap16_i64:
        tcg_out_opc_revb_2h(s, a0, a1);
        break;

    case INDEX_op_bswap32_i32:
        /* All 32-bit values are computed sign-extended in the register.  */
        /* fallthrough */
    case INDEX_op_bswap32_i64:
        tcg_out_opc_revb_2w(s, a0, a1);
        break;

    case INDEX_op_bswap64_i64:
        tcg_out_opc_revb_d(s, a0, a1);
        break;

    case INDEX_op_clz_i32:
        tcg_out_clzctz(s, OPC_CLZ_W, a0, a1, a2, c2, true);
        break;
    case INDEX_op_clz_i64:
        tcg_out_clzctz(s, OPC_CLZ_D, a0, a1, a2, c2, false);
        break;

    case INDEX_op_ctz_i32:
        tcg_out_clzctz(s, OPC_CTZ_W, a0, a1, a2, c2, true);
        break;
    case INDEX_op_ctz_i64:
        tcg_out_clzctz(s, OPC_CTZ_D, a0, a1, a2, c2, false);
        break;

    case INDEX_op_shl_i32:
        if (c2) {
            tcg_out_opc_slli_w(s, a0, a1, a2 & 0x1f);
        } else {
            tcg_out_opc_sll_w(s, a0, a1, a2);
        }
        break;
    case INDEX_op_shl_i64:
        if (c2) {
            tcg_out_opc_slli_d(s, a0, a1, a2 & 0x3f);
        } else {
            tcg_out_opc_sll_d(s, a0, a1, a2);
        }
        break;

    case INDEX_op_shr_i32:
        if (c2) {
            tcg_out_opc_srli_w(s, a0, a1, a2 & 0x1f);
        } else {
            tcg_out_opc_srl_w(s, a0, a1, a2);
        }
        break;
    case INDEX_op_shr_i64:
        if (c2) {
            tcg_out_opc_srli_d(s, a0, a1, a2 & 0x3f);
        } else {
            tcg_out_opc_srl_d(s, a0, a1, a2);
        }
        break;

    case INDEX_op_sar_i32:
        if (c2) {
            tcg_out_opc_srai_w(s, a0, a1, a2 & 0x1f);
        } else {
            tcg_out_opc_sra_w(s, a0, a1, a2);
        }
        break;
    case INDEX_op_sar_i64:
        if (c2) {
            tcg_out_opc_srai_d(s, a0, a1, a2 & 0x3f);
        } else {
            tcg_out_opc_sra_d(s, a0, a1, a2);
        }
        break;

    case INDEX_op_rotl_i32:
        /* transform into equivalent rotr/rotri */
        if (c2) {
            tcg_out_opc_rotri_w(s, a0, a1, (32 - a2) & 0x1f);
        } else {
            tcg_out_opc_sub_w(s, TCG_REG_TMP0, TCG_REG_ZERO, a2);
            tcg_out_opc_rotr_w(s, a0, a1, TCG_REG_TMP0);
        }
        break;
    case INDEX_op_rotl_i64:
        /* transform into equivalent rotr/rotri */
        if (c2) {
            tcg_out_opc_rotri_d(s, a0, a1, (64 - a2) & 0x3f);
        } else {
            tcg_out_opc_sub_w(s, TCG_REG_TMP0, TCG_REG_ZERO, a2);
            tcg_out_opc_rotr_d(s, a0, a1, TCG_REG_TMP0);
        }
        break;

    case INDEX_op_rotr_i32:
        if (c2) {
            tcg_out_opc_rotri_w(s, a0, a1, a2 & 0x1f);
        } else {
            tcg_out_opc_rotr_w(s, a0, a1, a2);
        }
        break;
    case INDEX_op_rotr_i64:
        if (c2) {
            tcg_out_opc_rotri_d(s, a0, a1, a2 & 0x3f);
        } else {
            tcg_out_opc_rotr_d(s, a0, a1, a2);
        }
        break;

    case INDEX_op_add_i32:
        if (c2) {
            tcg_out_addi(s, TCG_TYPE_I32, a0, a1, a2);
        } else {
            tcg_out_opc_add_w(s, a0, a1, a2);
        }
        break;
    case INDEX_op_add_i64:
        if (c2) {
            tcg_out_addi(s, TCG_TYPE_I64, a0, a1, a2);
        } else {
            tcg_out_opc_add_d(s, a0, a1, a2);
        }
        break;

    case INDEX_op_sub_i32:
        if (c2) {
            tcg_out_addi(s, TCG_TYPE_I32, a0, a1, -a2);
        } else {
            tcg_out_opc_sub_w(s, a0, a1, a2);
        }
        break;
    case INDEX_op_sub_i64:
        if (c2) {
            tcg_out_addi(s, TCG_TYPE_I64, a0, a1, -a2);
        } else {
            tcg_out_opc_sub_d(s, a0, a1, a2);
        }
        break;

    case INDEX_op_mul_i32:
        tcg_out_opc_mul_w(s, a0, a1, a2);
        break;
    case INDEX_op_mul_i64:
        tcg_out_opc_mul_d(s, a0, a1, a2);
        break;

    case INDEX_op_mulsh_i32:
        tcg_out_opc_mulh_w(s, a0, a1, a2);
        break;
    case INDEX_op_mulsh_i64:
        tcg_out_opc_mulh_d(s, a0, a1, a2);
        break;

    case INDEX_op_muluh_i32:
        tcg_out_opc_mulh_wu(s, a0, a1, a2);
        break;
    case INDEX_op_muluh_i64:
        tcg_out_opc_mulh_du(s, a0, a1, a2);
        break;

    case INDEX_op_div_i32:
        tcg_out_opc_div_w(s, a0, a1, a2);
        break;
    case INDEX_op_div_i64:
        tcg_out_opc_div_d(s, a0, a1, a2);
        break;

    case INDEX_op_divu_i32:
        tcg_out_opc_div_wu(s, a0, a1, a2);
        break;
    case INDEX_op_divu_i64:
        tcg_out_opc_div_du(s, a0, a1, a2);
        break;

    case INDEX_op_rem_i32:
        tcg_out_opc_mod_w(s, a0, a1, a2);
        break;
    case INDEX_op_rem_i64:
        tcg_out_opc_mod_d(s, a0, a1, a2);
        break;

    case INDEX_op_remu_i32:
        tcg_out_opc_mod_wu(s, a0, a1, a2);
        break;
    case INDEX_op_remu_i64:
        tcg_out_opc_mod_du(s, a0, a1, a2);
        break;

    case INDEX_op_setcond_i32:
    case INDEX_op_setcond_i64:
        tcg_out_setcond(s, args[3], a0, a1, a2, c2);
        break;

    case INDEX_op_movcond_i32:
    case INDEX_op_movcond_i64:
        tcg_out_movcond(s, args[5], a0, a1, a2, c2, args[3], args[4]);
        break;

    case INDEX_op_ld8s_i32:
    case INDEX_op_ld8s_i64:
        tcg_out_ldst(s, OPC_LD_B, a0, a1, a2);
        break;
    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8u_i64:
        tcg_out_ldst(s, OPC_LD_BU, a0, a1, a2);
        break;
    case INDEX_op_ld16s_i32:
    case INDEX_op_ld16s_i64:
        tcg_out_ldst(s, OPC_LD_H, a0, a1, a2);
        break;
    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16u_i64:
        tcg_out_ldst(s, OPC_LD_HU, a0, a1, a2);
        break;
    case INDEX_op_ld_i32:
    case INDEX_op_ld32s_i64:
        tcg_out_ldst(s, OPC_LD_W, a0, a1, a2);
        break;
    case INDEX_op_ld32u_i64:
        tcg_out_ldst(s, OPC_LD_WU, a0, a1, a2);
        break;
    case INDEX_op_ld_i64:
        tcg_out_ldst(s, OPC_LD_D, a0, a1, a2);
        break;

    case INDEX_op_st8_i32:
    case INDEX_op_st8_i64:
        tcg_out_ldst(s, OPC_ST_B, a0, a1, a2);
        break;
    case INDEX_op_st16_i32:
    case INDEX_op_st16_i64:
        tcg_out_ldst(s, OPC_ST_H, a0, a1, a2);
        break;
    case INDEX_op_st_i32:
    case INDEX_op_st32_i64:
        tcg_out_ldst(s, OPC_ST_W, a0, a1, a2);
        break;
    case INDEX_op_st_i64:
        tcg_out_ldst(s, OPC_ST_D, a0, a1, a2);
        break;

    case INDEX_op_qemu_ld_i32:
        tcg_out_qemu_ld(s, a0, a1, a2, TCG_TYPE_I32);
        break;
    case INDEX_op_qemu_ld_i64:
        tcg_out_qemu_ld(s, a0, a1, a2, TCG_TYPE_I64);
        break;
    case INDEX_op_qemu_st_i32:
        tcg_out_qemu_st(s, a0, a1, a2, TCG_TYPE_I32);
        break;
    case INDEX_op_qemu_st_i64:
        tcg_out_qemu_st(s, a0, a1, a2, TCG_TYPE_I64);
        break;
    case INDEX_op_goto_tb:
        if (s->tb_jmp_insn_offset) {
            /* TODO */
            g_assert_not_reached();
        } else {
            /* indirect jump method */
            tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_TMP0, TCG_REG_ZERO,
                       (uintptr_t)(s->tb_jmp_target_addr + a0));
            tcg_out_opc_jirl(s, TCG_REG_ZERO, TCG_REG_TMP0, 0);
        }
        s->tb_jmp_reset_offset[a0] = tcg_current_code_size(s);
        break;
    case INDEX_op_exit_tb:
        tcg_out_exit_tb(s, a0);
        break;

    case INDEX_op_ext8s_i32:
        tcg_out_ext8s(s, TCG_TYPE_I32, a0, a1);
        break;
    case INDEX_op_ext8s_i64:
        tcg_out_ext8s(s, TCG_TYPE_I64, a0, a1);
        break;
    case INDEX_op_ext8u_i32:
    case INDEX_op_ext8u_i64:
        tcg_out_ext8u(s, a0, a1);
        break;
    case INDEX_op_ext16s_i32:
        tcg_out_ext16s(s, TCG_TYPE_I32, a0, a1);
        break;
    case INDEX_op_ext16s_i64:
        tcg_out_ext16s(s, TCG_TYPE_I64, a0, a1);
        break;
    case INDEX_op_ext16u_i32:
    case INDEX_op_ext16u_i64:
        tcg_out_ext16u(s, a0, a1);
        break;
    case INDEX_op_ext32s_i64:
        tcg_out_ext32s(s, a0, a1);
        break;
    case INDEX_op_ext32u_i64:
        tcg_out_ext32u(s, a0, a1);
        break;
    case INDEX_op_ext_i32_i64:
        tcg_out_exts_i32_i64(s, a0, a1);
        break;
    case INDEX_op_extu_i32_i64:
        tcg_out_extu_i32_i64(s, a0, a1);
        break;
    case INDEX_op_extrl_i64_i32:
        tcg_out_extrl_i64_i32(s, a0, a1);
        break;
    case INDEX_op_mov_i32:  /* Always emitted via tcg_out_mov.  */
    case INDEX_op_mov_i64:
    case INDEX_op_call:     /* Always emitted via tcg_out_call.  */
    // case INDEX_op_ext8s_i32:  /* Always emitted via tcg_reg_alloc_op.  */
    // case INDEX_op_ext8s_i64:
    // case INDEX_op_ext8u_i32:
    // case INDEX_op_ext8u_i64:
    // case INDEX_op_ext16s_i32:
    // case INDEX_op_ext16s_i64:
    // case INDEX_op_ext16u_i32:
    // case INDEX_op_ext16u_i64:
    // case INDEX_op_ext32s_i64:
    // case INDEX_op_ext32u_i64:
    // case INDEX_op_ext_i32_i64:
    // case INDEX_op_extu_i32_i64:
    // case INDEX_op_extrl_i64_i32:
    default:
        g_assert_not_reached();
    }
}

static bool tcg_out_dup_vec(TCGContext *s, TCGType type, unsigned vece,
                            TCGReg rd, TCGReg rs)
{
    switch (vece) {
    case MO_8:
        tcg_out_opc_vreplgr2vr_b(s, rd, rs);
        break;
    case MO_16:
        tcg_out_opc_vreplgr2vr_h(s, rd, rs);
        break;
    case MO_32:
        tcg_out_opc_vreplgr2vr_w(s, rd, rs);
        break;
    case MO_64:
        tcg_out_opc_vreplgr2vr_d(s, rd, rs);
        break;
    default:
        g_assert_not_reached();
    }
    return true;
}

static bool tcg_out_dupm_vec(TCGContext *s, TCGType type, unsigned vece,
                             TCGReg r, TCGReg base, intptr_t offset)
{
    /* Handle imm overflow and division (vldrepl.d imm is divided by 8) */
    if (offset < -0x800 || offset > 0x7ff || \
        (offset & ((1 << vece) - 1)) != 0) {
        tcg_out_addi(s, TCG_TYPE_I64, TCG_REG_TMP0, base, offset);
        base = TCG_REG_TMP0;
        offset = 0;
    }
    offset >>= vece;

    switch (vece) {
    case MO_8:
        tcg_out_opc_vldrepl_b(s, r, base, offset);
        break;
    case MO_16:
        tcg_out_opc_vldrepl_h(s, r, base, offset);
        break;
    case MO_32:
        tcg_out_opc_vldrepl_w(s, r, base, offset);
        break;
    case MO_64:
        tcg_out_opc_vldrepl_d(s, r, base, offset);
        break;
    default:
        g_assert_not_reached();
    }
    return true;
}

// static void tcg_out_dupi_vec(TCGContext *s, TCGType type, unsigned vece,
//                              TCGReg rd, int64_t v64)
// {
//     /* Try vldi if imm can fit */
//     int64_t value = sextract64(v64, 0, 8 << vece);
//     if (-0x200 <= value && value <= 0x1FF) {
//         uint32_t imm = (vece << 10) | ((uint32_t)v64 & 0x3FF);
//         tcg_out_opc_vldi(s, rd, imm);
//         return;
//     }

//     /* TODO: vldi patterns when imm 12 is set */

//     /* Fallback to vreplgr2vr */
//     tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP0, value);
//     switch (vece) {
//     case MO_8:
//         tcg_out_opc_vreplgr2vr_b(s, rd, TCG_REG_TMP0);
//         break;
//     case MO_16:
//         tcg_out_opc_vreplgr2vr_h(s, rd, TCG_REG_TMP0);
//         break;
//     case MO_32:
//         tcg_out_opc_vreplgr2vr_w(s, rd, TCG_REG_TMP0);
//         break;
//     case MO_64:
//         tcg_out_opc_vreplgr2vr_d(s, rd, TCG_REG_TMP0);
//         break;
//     default:
//         g_assert_not_reached();
//     }
// }

static void tcg_out_addsub_vec(TCGContext *s, unsigned vece, const TCGArg a0,
                               const TCGArg a1, const TCGArg a2,
                               bool a2_is_const, bool is_add)
{
    static const LoongArchInsn add_vec_insn[4] = {
        OPC_VADD_B, OPC_VADD_H, OPC_VADD_W, OPC_VADD_D
    };
    static const LoongArchInsn add_vec_imm_insn[4] = {
        OPC_VADDI_BU, OPC_VADDI_HU, OPC_VADDI_WU, OPC_VADDI_DU
    };
    static const LoongArchInsn sub_vec_insn[4] = {
        OPC_VSUB_B, OPC_VSUB_H, OPC_VSUB_W, OPC_VSUB_D
    };
    static const LoongArchInsn sub_vec_imm_insn[4] = {
        OPC_VSUBI_BU, OPC_VSUBI_HU, OPC_VSUBI_WU, OPC_VSUBI_DU
    };

    if (a2_is_const) {
        int64_t value = sextract64(a2, 0, 8 << vece);
        if (!is_add) {
            value = -value;
        }

        /* Try vaddi/vsubi */
        if (0 <= value && value <= 0x1f) {
            tcg_out32(s, encode_vdvjuk5_insn(add_vec_imm_insn[vece], a0, \
                                             a1, value));
            return;
        } else if (-0x1f <= value && value < 0) {
            tcg_out32(s, encode_vdvjuk5_insn(sub_vec_imm_insn[vece], a0, \
                                             a1, -value));
            return;
        }

        /* constraint TCG_CT_CONST_VADD ensures unreachable */
        g_assert_not_reached();
    }

    if (is_add) {
        tcg_out32(s, encode_vdvjvk_insn(add_vec_insn[vece], a0, a1, a2));
    } else {
        tcg_out32(s, encode_vdvjvk_insn(sub_vec_insn[vece], a0, a1, a2));
    }
}

static void tcg_out_vec_op(TCGContext *s, TCGOpcode opc,
                           unsigned vecl, unsigned vece,
                           const TCGArg args[TCG_MAX_OP_ARGS],
                           const int const_args[TCG_MAX_OP_ARGS])
{
    TCGType type = vecl + TCG_TYPE_V64;
    TCGArg a0, a1, a2, a3;
    TCGReg temp = TCG_REG_TMP0;
    TCGReg temp_vec = TCG_VEC_TMP0;

    static const LoongArchInsn cmp_vec_insn[16][4] = {
        [TCG_COND_EQ] = {OPC_VSEQ_B, OPC_VSEQ_H, OPC_VSEQ_W, OPC_VSEQ_D},
        [TCG_COND_LE] = {OPC_VSLE_B, OPC_VSLE_H, OPC_VSLE_W, OPC_VSLE_D},
        [TCG_COND_LEU] = {OPC_VSLE_BU, OPC_VSLE_HU, OPC_VSLE_WU, OPC_VSLE_DU},
        [TCG_COND_LT] = {OPC_VSLT_B, OPC_VSLT_H, OPC_VSLT_W, OPC_VSLT_D},
        [TCG_COND_LTU] = {OPC_VSLT_BU, OPC_VSLT_HU, OPC_VSLT_WU, OPC_VSLT_DU},
    };
    static const LoongArchInsn cmp_vec_imm_insn[16][4] = {
        [TCG_COND_EQ] = {OPC_VSEQI_B, OPC_VSEQI_H, OPC_VSEQI_W, OPC_VSEQI_D},
        [TCG_COND_LE] = {OPC_VSLEI_B, OPC_VSLEI_H, OPC_VSLEI_W, OPC_VSLEI_D},
        [TCG_COND_LEU] = {OPC_VSLEI_BU, OPC_VSLEI_HU, OPC_VSLEI_WU, OPC_VSLEI_DU},
        [TCG_COND_LT] = {OPC_VSLTI_B, OPC_VSLTI_H, OPC_VSLTI_W, OPC_VSLTI_D},
        [TCG_COND_LTU] = {OPC_VSLTI_BU, OPC_VSLTI_HU, OPC_VSLTI_WU, OPC_VSLTI_DU},
    };
    LoongArchInsn insn;
    static const LoongArchInsn neg_vec_insn[4] = {
        OPC_VNEG_B, OPC_VNEG_H, OPC_VNEG_W, OPC_VNEG_D
    };
    static const LoongArchInsn mul_vec_insn[4] = {
        OPC_VMUL_B, OPC_VMUL_H, OPC_VMUL_W, OPC_VMUL_D
    };
    static const LoongArchInsn smin_vec_insn[4] = {
        OPC_VMIN_B, OPC_VMIN_H, OPC_VMIN_W, OPC_VMIN_D
    };
    static const LoongArchInsn umin_vec_insn[4] = {
        OPC_VMIN_BU, OPC_VMIN_HU, OPC_VMIN_WU, OPC_VMIN_DU
    };
    static const LoongArchInsn smax_vec_insn[4] = {
        OPC_VMAX_B, OPC_VMAX_H, OPC_VMAX_W, OPC_VMAX_D
    };
    static const LoongArchInsn umax_vec_insn[4] = {
        OPC_VMAX_BU, OPC_VMAX_HU, OPC_VMAX_WU, OPC_VMAX_DU
    };
    static const LoongArchInsn ssadd_vec_insn[4] = {
        OPC_VSADD_B, OPC_VSADD_H, OPC_VSADD_W, OPC_VSADD_D
    };
    static const LoongArchInsn usadd_vec_insn[4] = {
        OPC_VSADD_BU, OPC_VSADD_HU, OPC_VSADD_WU, OPC_VSADD_DU
    };
    static const LoongArchInsn sssub_vec_insn[4] = {
        OPC_VSSUB_B, OPC_VSSUB_H, OPC_VSSUB_W, OPC_VSSUB_D
    };
    static const LoongArchInsn ussub_vec_insn[4] = {
        OPC_VSSUB_BU, OPC_VSSUB_HU, OPC_VSSUB_WU, OPC_VSSUB_DU
    };
    static const LoongArchInsn shlv_vec_insn[4] = {
        OPC_VSLL_B, OPC_VSLL_H, OPC_VSLL_W, OPC_VSLL_D
    };
    static const LoongArchInsn shrv_vec_insn[4] = {
        OPC_VSRL_B, OPC_VSRL_H, OPC_VSRL_W, OPC_VSRL_D
    };
    static const LoongArchInsn sarv_vec_insn[4] = {
        OPC_VSRA_B, OPC_VSRA_H, OPC_VSRA_W, OPC_VSRA_D
    };
    static const LoongArchInsn shli_vec_insn[4] = {
        OPC_VSLLI_B, OPC_VSLLI_H, OPC_VSLLI_W, OPC_VSLLI_D
    };
    static const LoongArchInsn shri_vec_insn[4] = {
        OPC_VSRLI_B, OPC_VSRLI_H, OPC_VSRLI_W, OPC_VSRLI_D
    };
    static const LoongArchInsn sari_vec_insn[4] = {
        OPC_VSRAI_B, OPC_VSRAI_H, OPC_VSRAI_W, OPC_VSRAI_D
    };
    static const LoongArchInsn rotrv_vec_insn[4] = {
        OPC_VROTR_B, OPC_VROTR_H, OPC_VROTR_W, OPC_VROTR_D
    };

    a0 = args[0];
    a1 = args[1];
    a2 = args[2];
    a3 = args[3];

    /* Currently only supports V128 */
    tcg_debug_assert(type == TCG_TYPE_V128);

    switch (opc) {
    case INDEX_op_st_vec:
        /* Try to fit vst imm */
        if (-0x800 <= a2 && a2 <= 0x7ff) {
            tcg_out_opc_vst(s, a0, a1, a2);
        } else {
            tcg_out_movi(s, TCG_TYPE_I64, temp, a2);
            tcg_out_opc_vstx(s, a0, a1, temp);
        }
        break;
    case INDEX_op_ld_vec:
        /* Try to fit vld imm */
        if (-0x800 <= a2 && a2 <= 0x7ff) {
            tcg_out_opc_vld(s, a0, a1, a2);
        } else {
            tcg_out_movi(s, TCG_TYPE_I64, temp, a2);
            tcg_out_opc_vldx(s, a0, a1, temp);
        }
        break;
    case INDEX_op_and_vec:
        tcg_out_opc_vand_v(s, a0, a1, a2);
        break;
    case INDEX_op_andc_vec:
        /*
         * vandn vd, vj, vk: vd = vk & ~vj
         * andc_vec vd, vj, vk: vd = vj & ~vk
         * vk and vk are swapped
         */
        tcg_out_opc_vandn_v(s, a0, a2, a1);
        break;
    case INDEX_op_or_vec:
        tcg_out_opc_vor_v(s, a0, a1, a2);
        break;
    case INDEX_op_orc_vec:
        tcg_out_opc_vorn_v(s, a0, a1, a2);
        break;
    case INDEX_op_xor_vec:
        tcg_out_opc_vxor_v(s, a0, a1, a2);
        break;
    case INDEX_op_not_vec:
        tcg_out_opc_vnor_v(s, a0, a1, a1);
        break;
    case INDEX_op_cmp_vec:
        {
            TCGCond cond = args[3];
            if (const_args[2]) {
                /*
                 * cmp_vec dest, src, value
                 * Try vseqi/vslei/vslti
                 */
                int64_t value = sextract64(a2, 0, 8 << vece);
                if ((cond == TCG_COND_EQ || cond == TCG_COND_LE || \
                     cond == TCG_COND_LT) && (-0x10 <= value && value <= 0x0f)) {
                    tcg_out32(s, encode_vdvjsk5_insn(cmp_vec_imm_insn[cond][vece], \
                                                     a0, a1, value));
                    break;
                } else if ((cond == TCG_COND_LEU || cond == TCG_COND_LTU) &&
                    (0x00 <= value && value <= 0x1f)) {
                    tcg_out32(s, encode_vdvjuk5_insn(cmp_vec_imm_insn[cond][vece], \
                                                     a0, a1, value));
                    break;
                }

                /*
                 * Fallback to:
                 * dupi_vec temp, a2
                 * cmp_vec a0, a1, temp, cond
                 */
                // tcg_out_dupi_vec(s, type, vece, temp_vec, a2);
                /* Try vldi if imm can fit */
                if (-0x200 <= value && value <= 0x1FF) {
                    uint32_t imm = (vece << 10) | ((uint32_t)a2 & 0x3FF);
                    tcg_out_opc_vldi(s, temp_vec, imm);
                    goto enddupi;
                }

                /* TODO: vldi patterns when imm 12 is set */

                /* Fallback to vreplgr2vr */
                tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP0, value);
                switch (vece) {
                case MO_8:
                    tcg_out_opc_vreplgr2vr_b(s, temp_vec, TCG_REG_TMP0);
                    break;
                case MO_16:
                    tcg_out_opc_vreplgr2vr_h(s, temp_vec, TCG_REG_TMP0);
                    break;
                case MO_32:
                    tcg_out_opc_vreplgr2vr_w(s, temp_vec, TCG_REG_TMP0);
                    break;
                case MO_64:
                    tcg_out_opc_vreplgr2vr_d(s, temp_vec, TCG_REG_TMP0);
                    break;
                default:
                    g_assert_not_reached();
                }
                enddupi:
                a2 = temp_vec;
            }

            insn = cmp_vec_insn[cond][vece];
            if (insn == 0) {
                TCGArg t;
                t = a1, a1 = a2, a2 = t;
                cond = tcg_swap_cond(cond);
                insn = cmp_vec_insn[cond][vece];
                tcg_debug_assert(insn != 0);
            }
            tcg_out32(s, encode_vdvjvk_insn(insn, a0, a1, a2));
        }
        break;
    case INDEX_op_add_vec:
        tcg_out_addsub_vec(s, vece, a0, a1, a2, const_args[2], true);
        break;
    case INDEX_op_sub_vec:
        tcg_out_addsub_vec(s, vece, a0, a1, a2, const_args[2], false);
        break;
    case INDEX_op_neg_vec:
        tcg_out32(s, encode_vdvj_insn(neg_vec_insn[vece], a0, a1));
        break;
    case INDEX_op_mul_vec:
        tcg_out32(s, encode_vdvjvk_insn(mul_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_smin_vec:
        tcg_out32(s, encode_vdvjvk_insn(smin_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_smax_vec:
        tcg_out32(s, encode_vdvjvk_insn(smax_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_umin_vec:
        tcg_out32(s, encode_vdvjvk_insn(umin_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_umax_vec:
        tcg_out32(s, encode_vdvjvk_insn(umax_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_ssadd_vec:
        tcg_out32(s, encode_vdvjvk_insn(ssadd_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_usadd_vec:
        tcg_out32(s, encode_vdvjvk_insn(usadd_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_sssub_vec:
        tcg_out32(s, encode_vdvjvk_insn(sssub_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_ussub_vec:
        tcg_out32(s, encode_vdvjvk_insn(ussub_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_shlv_vec:
        tcg_out32(s, encode_vdvjvk_insn(shlv_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_shrv_vec:
        tcg_out32(s, encode_vdvjvk_insn(shrv_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_sarv_vec:
        tcg_out32(s, encode_vdvjvk_insn(sarv_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_shli_vec:
        tcg_out32(s, encode_vdvjuk3_insn(shli_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_shri_vec:
        tcg_out32(s, encode_vdvjuk3_insn(shri_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_sari_vec:
        tcg_out32(s, encode_vdvjuk3_insn(sari_vec_insn[vece], a0, a1, a2));
        break;
    case INDEX_op_bitsel_vec:
        /* vbitsel vd, vj, vk, va = bitsel_vec vd, va, vk, vj */
        tcg_out_opc_vbitsel_v(s, a0, a3, a2, a1);
        break;
    case INDEX_op_dupm_vec:
        tcg_out_dupm_vec(s, type, vece, a0, a1, a2);
        break;
    default:
        g_assert_not_reached();
    }
}

// int tcg_can_emit_vec_op(TCGContext *tcg_ctx, TCGOpcode opc, TCGType type, unsigned vece)
// {
//     switch (opc) {
//     case INDEX_op_ld_vec:
//     case INDEX_op_st_vec:
//     case INDEX_op_dup_vec:
//     case INDEX_op_cmp_vec:
//     case INDEX_op_add_vec:
//     case INDEX_op_sub_vec:
//     case INDEX_op_and_vec:
//     case INDEX_op_andc_vec:
//     case INDEX_op_or_vec:
//     case INDEX_op_orc_vec:
//     case INDEX_op_xor_vec:
//     case INDEX_op_not_vec:
//     case INDEX_op_neg_vec:
//     case INDEX_op_mul_vec:
//     case INDEX_op_shlv_vec:
//     case INDEX_op_shrv_vec:
//     case INDEX_op_sarv_vec:
//         return 1;
//     default:
//         return 0;
//     }
// }
int tcg_can_emit_vec_op(TCGContext *tcg_ctx, TCGOpcode opc, TCGType type, unsigned vece)
{
    switch (opc) {
    case INDEX_op_ld_vec:
    case INDEX_op_st_vec:
    case INDEX_op_dup_vec:
    case INDEX_op_dupm_vec:
    case INDEX_op_cmp_vec:
    case INDEX_op_add_vec:
    case INDEX_op_sub_vec:
    case INDEX_op_and_vec:
    case INDEX_op_andc_vec:
    case INDEX_op_or_vec:
    case INDEX_op_orc_vec:
    case INDEX_op_xor_vec:
    case INDEX_op_not_vec:
    case INDEX_op_neg_vec:
    case INDEX_op_mul_vec:
    case INDEX_op_smin_vec:
    case INDEX_op_smax_vec:
    case INDEX_op_umin_vec:
    case INDEX_op_umax_vec:
    case INDEX_op_ssadd_vec:
    case INDEX_op_usadd_vec:
    case INDEX_op_sssub_vec:
    case INDEX_op_ussub_vec:
    case INDEX_op_shlv_vec:
    case INDEX_op_shrv_vec:
    case INDEX_op_sarv_vec:
    case INDEX_op_bitsel_vec:
        return 1;
    default:
        return 0;
    }
}

void tcg_expand_vec_op(TCGContext *tcg_ctx, TCGOpcode opc, TCGType type, unsigned vece,
                       TCGArg a0, ...)
{
    g_assert_not_reached();
}

static const TCGTargetOpDef *tcg_target_op_def(TCGOpcode op)
{
    static const TCGTargetOpDef r = { .args_ct_str = { "r" } };
    static const TCGTargetOpDef rZ_r = { .args_ct_str = { "rZ", "r" } };
    static const TCGTargetOpDef rZ_rZ = { .args_ct_str = { "rZ", "rZ" } };
    //static const TCGTargetOpDef w_r = { .args_ct_str = { "w", "r" } };
    //static const TCGTargetOpDef r_r_r = { .args_ct_str = { "r", "r", "r" } };

    static const TCGTargetOpDef r_l = { .args_ct_str = { "r", "l" } };
    static const TCGTargetOpDef lZ_l = { .args_ct_str = { "lZ", "l" } };

    static const TCGTargetOpDef r_r = { .args_ct_str = { "r", "r" } };
    static const TCGTargetOpDef w_r = { .args_ct_str = { "w", "r" } };
    static const TCGTargetOpDef w_w = { .args_ct_str = { "w", "w" } };
    static const TCGTargetOpDef r_r_rC = { .args_ct_str = { "r", "r", "rC" } };
    static const TCGTargetOpDef r_r_ri = { .args_ct_str = { "r", "r", "ri" } };
    static const TCGTargetOpDef r_r_rI = { .args_ct_str = { "r", "r", "rI" } };
    static const TCGTargetOpDef r_r_rJ = { .args_ct_str = { "r", "r", "rJ" } };
    static const TCGTargetOpDef r_r_rU = { .args_ct_str = { "r", "r", "rU" } };
    static const TCGTargetOpDef r_r_rW = { .args_ct_str = { "r", "r", "rW" } };
    static const TCGTargetOpDef r_r_rZ = { .args_ct_str = { "r", "r", "rZ" } };
    static const TCGTargetOpDef r_0_rZ = { .args_ct_str = { "r", "0", "rZ" } };
    static const TCGTargetOpDef r_rZ_ri = { .args_ct_str = { "r", "rZ", "ri" } };
    static const TCGTargetOpDef r_rZ_rJ = { .args_ct_str = { "r", "rZ", "rJ" } };
    static const TCGTargetOpDef r_rZ_rZ = { .args_ct_str = { "r", "rZ", "rZ" } };
    static const TCGTargetOpDef w_w_w = { .args_ct_str = { "w", "w", "w" } };
    static const TCGTargetOpDef w_w_wM = { .args_ct_str = { "w", "w", "wM" } };
    static const TCGTargetOpDef w_w_wA = { .args_ct_str = { "w", "w", "wA" } };
    static const TCGTargetOpDef w_w_w_w = { .args_ct_str = { "w", "w", "w", "w" } };
    static const TCGTargetOpDef r_rZ_rJ_rZ_rZ = { .args_ct_str = { "r", "rZ", "rJ", "rZ", "rZ" } };

    switch (op) {
    case INDEX_op_goto_ptr:
        return &r;

    case INDEX_op_st8_i32:
    case INDEX_op_st8_i64:
    case INDEX_op_st16_i32:
    case INDEX_op_st16_i64:
    case INDEX_op_st32_i64:
    case INDEX_op_st_i32:
    case INDEX_op_st_i64:
        return &rZ_r;

    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
        return &r_l;
    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_st_i64:
        return &lZ_l;

    case INDEX_op_brcond_i32:
    case INDEX_op_brcond_i64:
        return &rZ_rZ;

    case INDEX_op_ext8s_i32:
    case INDEX_op_ext8s_i64:
    case INDEX_op_ext8u_i32:
    case INDEX_op_ext8u_i64:
    case INDEX_op_ext16s_i32:
    case INDEX_op_ext16s_i64:
    case INDEX_op_ext16u_i32:
    case INDEX_op_ext16u_i64:
    case INDEX_op_ext32s_i64:
    case INDEX_op_ext32u_i64:
    case INDEX_op_extu_i32_i64:
    case INDEX_op_extrl_i64_i32:
    case INDEX_op_extrh_i64_i32:
    case INDEX_op_ext_i32_i64:
    case INDEX_op_not_i32:
    case INDEX_op_not_i64:
    case INDEX_op_extract_i32:
    case INDEX_op_extract_i64:
    case INDEX_op_bswap16_i32:
    case INDEX_op_bswap16_i64:
    case INDEX_op_bswap32_i32:
    case INDEX_op_bswap32_i64:
    case INDEX_op_bswap64_i64:
    case INDEX_op_ld8s_i32:
    case INDEX_op_ld8s_i64:
    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8u_i64:
    case INDEX_op_ld16s_i32:
    case INDEX_op_ld16s_i64:
    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16u_i64:
    case INDEX_op_ld32s_i64:
    case INDEX_op_ld32u_i64:
    case INDEX_op_ld_i32:
    case INDEX_op_ld_i64:
        return &r_r;

    case INDEX_op_andc_i32:
    case INDEX_op_andc_i64:
    case INDEX_op_orc_i32:
    case INDEX_op_orc_i64:
        /*
         * LoongArch insns for these ops don't have reg-imm forms, but we
         * can express using andi/ori if ~constant satisfies
         * TCG_CT_CONST_U12.
         */
        return &r_r_rC;

    case INDEX_op_shl_i32:
    case INDEX_op_shl_i64:
    case INDEX_op_shr_i32:
    case INDEX_op_shr_i64:
    case INDEX_op_sar_i32:
    case INDEX_op_sar_i64:
    case INDEX_op_rotl_i32:
    case INDEX_op_rotl_i64:
    case INDEX_op_rotr_i32:
    case INDEX_op_rotr_i64:
    case INDEX_op_add_i32:
        return &r_r_ri;

    case INDEX_op_add_i64:
        return &r_r_rJ;

    case INDEX_op_and_i32:
    case INDEX_op_and_i64:
    case INDEX_op_nor_i32:
    case INDEX_op_nor_i64:
    case INDEX_op_or_i32:
    case INDEX_op_or_i64:
    case INDEX_op_xor_i32:
    case INDEX_op_xor_i64:
        /* LoongArch reg-imm bitops have their imms ZERO-extended */
        return &r_r_rU;

    case INDEX_op_clz_i32:
    case INDEX_op_clz_i64:
    case INDEX_op_ctz_i32:
    case INDEX_op_ctz_i64:
        return &r_r_rW;

    case INDEX_op_deposit_i32:
    case INDEX_op_deposit_i64:
        /* Must deposit into the same register as input */
        return &r_0_rZ;

    case INDEX_op_sub_i32:
    case INDEX_op_setcond_i32:
        return &r_rZ_ri;
    case INDEX_op_sub_i64:
    case INDEX_op_setcond_i64:
        return &r_rZ_rJ;

    case INDEX_op_mul_i32:
    case INDEX_op_mul_i64:
    case INDEX_op_mulsh_i32:
    case INDEX_op_mulsh_i64:
    case INDEX_op_muluh_i32:
    case INDEX_op_muluh_i64:
    case INDEX_op_div_i32:
    case INDEX_op_div_i64:
    case INDEX_op_divu_i32:
    case INDEX_op_divu_i64:
    case INDEX_op_rem_i32:
    case INDEX_op_rem_i64:
    case INDEX_op_remu_i32:
    case INDEX_op_remu_i64:
        return &r_rZ_rZ;

    case INDEX_op_movcond_i32:
    case INDEX_op_movcond_i64:
        return &r_rZ_rJ_rZ_rZ;

   case INDEX_op_ld_vec:
    case INDEX_op_dup_vec:
    case INDEX_op_dupm_vec:
    case INDEX_op_st_vec:
        return &w_r;

    case INDEX_op_cmp_vec:
        return &w_w_wM;

    case INDEX_op_add_vec:
    case INDEX_op_sub_vec:
        return &w_w_wA;

    case INDEX_op_and_vec:
    case INDEX_op_andc_vec:
    case INDEX_op_or_vec:
    case INDEX_op_orc_vec:
    case INDEX_op_xor_vec:
    case INDEX_op_mul_vec:

    case INDEX_op_smin_vec:
    case INDEX_op_smax_vec:
    case INDEX_op_umin_vec:
    case INDEX_op_umax_vec:
    case INDEX_op_ssadd_vec:
    case INDEX_op_usadd_vec:
    case INDEX_op_sssub_vec:
    case INDEX_op_ussub_vec:

    case INDEX_op_shlv_vec:
    case INDEX_op_shrv_vec:
    case INDEX_op_sarv_vec:
        return &w_w_w;

    case INDEX_op_not_vec:
    case INDEX_op_neg_vec:
    case INDEX_op_shli_vec:
    case INDEX_op_shri_vec:
    case INDEX_op_sari_vec:
        return &w_w;

    case INDEX_op_bitsel_vec:
        return &w_w_w_w;

    default:
        g_assert_not_reached();
    }
}

static const int tcg_target_callee_save_regs[] = {
    TCG_REG_S0,     /* used for the global env (TCG_AREG0) */
    TCG_REG_S1,
    TCG_REG_S2,
    TCG_REG_S3,
    TCG_REG_S4,
    TCG_REG_S5,
    TCG_REG_S6,
    TCG_REG_S7,
    TCG_REG_S8,
    TCG_REG_S9,
    TCG_REG_RA,     /* should be last for ABI compliance */
};

/* Stack frame parameters.  */
#define REG_SIZE   (TCG_TARGET_REG_BITS / 8)
#define SAVE_SIZE  ((int)ARRAY_SIZE(tcg_target_callee_save_regs) * REG_SIZE)
#define TEMP_SIZE  (CPU_TEMP_BUF_NLONGS * (int)sizeof(long))
#define FRAME_SIZE ((TCG_STATIC_CALL_ARGS_SIZE + TEMP_SIZE + SAVE_SIZE \
                     + TCG_TARGET_STACK_ALIGN - 1) \
                    & -TCG_TARGET_STACK_ALIGN)
#define SAVE_OFS   (TCG_STATIC_CALL_ARGS_SIZE + TEMP_SIZE)

/* We're expecting to be able to use an immediate for frame allocation.  */
QEMU_BUILD_BUG_ON(FRAME_SIZE > 0x7ff);

/* Generate global QEMU prologue and epilogue code */
static void tcg_target_qemu_prologue(TCGContext *s)
{
    int i;

    tcg_set_frame(s, TCG_REG_SP, TCG_STATIC_CALL_ARGS_SIZE, TEMP_SIZE);

    /* TB prologue */
    tcg_out_opc_addi_d(s, TCG_REG_SP, TCG_REG_SP, -FRAME_SIZE);
    for (i = 0; i < ARRAY_SIZE(tcg_target_callee_save_regs); i++) {
        tcg_out_st(s, TCG_TYPE_REG, tcg_target_callee_save_regs[i],
                   TCG_REG_SP, SAVE_OFS + i * REG_SIZE);
    }

#if !defined(CONFIG_SOFTMMU)
    if (USE_GUEST_BASE) {
        tcg_out_movi(s, TCG_TYPE_PTR, TCG_GUEST_BASE_REG, guest_base);
        tcg_regset_set_reg(s->reserved_regs, TCG_GUEST_BASE_REG);
    }
#endif

    /* Call generated code */
    tcg_out_mov(s, TCG_TYPE_PTR, TCG_AREG0, tcg_target_call_iarg_regs[0]);
    tcg_out_opc_jirl(s, TCG_REG_ZERO, tcg_target_call_iarg_regs[1], 0);

    /* Return path for goto_ptr. Set return value to 0 */
    s->code_gen_epilogue = s->code_ptr;
    tcg_out_mov(s, TCG_TYPE_REG, TCG_REG_A0, TCG_REG_ZERO);

    /* TB epilogue */
    s->tb_ret_addr = s->code_ptr;
    for (i = 0; i < ARRAY_SIZE(tcg_target_callee_save_regs); i++) {
        tcg_out_ld(s, TCG_TYPE_REG, tcg_target_callee_save_regs[i],
                   TCG_REG_SP, SAVE_OFS + i * REG_SIZE);
    }

    tcg_out_opc_addi_d(s, TCG_REG_SP, TCG_REG_SP, FRAME_SIZE);
    tcg_out_opc_jirl(s, TCG_REG_ZERO, TCG_REG_RA, 0);
}

static void tcg_out_tb_start(TCGContext *s)
{
    /* nothing to do */
}

static void tcg_target_init(TCGContext *s)
{
#if 0
    unsigned long hwcap = qemu_getauxval(AT_HWCAP);

    /* Server and desktop class cpus have UAL; embedded cpus do not. */
    if (!(hwcap & HWCAP_LOONGARCH_UAL)) {
        vreport(REPORT_TYPE_ERROR, "%s\n", "TCG: unaligned access support required; exiting");
        exit(EXIT_FAILURE);
    }

    if (hwcap & HWCAP_LOONGARCH_LSX) {
        s->use_lsx_instructions = 1;
    }
#else
    s->use_lsx_instructions = 1;
#endif

    s->tcg_target_available_regs[TCG_TYPE_I32] = ALL_GENERAL_REGS;
    s->tcg_target_available_regs[TCG_TYPE_I64] = ALL_GENERAL_REGS;

    s->tcg_target_call_clobber_regs = ALL_GENERAL_REGS;
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S0);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S1);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S2);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S3);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S4);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S5);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S6);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S7);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S8);
    tcg_regset_reset_reg(s->tcg_target_call_clobber_regs, TCG_REG_S9);

    s->reserved_regs = 0;
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_ZERO);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TMP0);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TMP1);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TMP2);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_SP);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TP);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_RESERVED);
    tcg_regset_set_reg(s->reserved_regs, TCG_VEC_TMP0);
}

typedef struct {
    DebugFrameHeader h;
    uint8_t fde_def_cfa[4];
    uint8_t fde_reg_ofs[ARRAY_SIZE(tcg_target_callee_save_regs) * 2];
} DebugFrame;

#define ELF_HOST_MACHINE EM_LOONGARCH

static const DebugFrame debug_frame = {
    .h.cie.len = sizeof(DebugFrameCIE) - 4, /* length after .len member */
    .h.cie.id = -1,
    .h.cie.version = 1,
    .h.cie.code_align = 1,
    .h.cie.data_align = -(TCG_TARGET_REG_BITS / 8) & 0x7f, /* sleb128 */
    .h.cie.return_column = TCG_REG_RA,

    /* Total FDE size does not include the "len" member.  */
    .h.fde.len = sizeof(DebugFrame) - offsetof(DebugFrame, h.fde.cie_offset),

    .fde_def_cfa = {
        12, TCG_REG_SP,                 /* DW_CFA_def_cfa sp, ...  */
        (FRAME_SIZE & 0x7f) | 0x80,     /* ... uleb128 FRAME_SIZE */
        (FRAME_SIZE >> 7)
    },
    .fde_reg_ofs = {
        0x80 + 23, 11,                  /* DW_CFA_offset, s0, -88 */
        0x80 + 24, 10,                  /* DW_CFA_offset, s1, -80 */
        0x80 + 25, 9,                   /* DW_CFA_offset, s2, -72 */
        0x80 + 26, 8,                   /* DW_CFA_offset, s3, -64 */
        0x80 + 27, 7,                   /* DW_CFA_offset, s4, -56 */
        0x80 + 28, 6,                   /* DW_CFA_offset, s5, -48 */
        0x80 + 29, 5,                   /* DW_CFA_offset, s6, -40 */
        0x80 + 30, 4,                   /* DW_CFA_offset, s7, -32 */
        0x80 + 31, 3,                   /* DW_CFA_offset, s8, -24 */
        0x80 + 22, 2,                   /* DW_CFA_offset, s9, -16 */
        0x80 + 1 , 1,                   /* DW_CFA_offset, ra, -8 */
    }
};

void tcg_register_jit(TCGContext *s, void *buf, size_t buf_size)
{
    tcg_register_jit_int(s, buf, buf_size, &debug_frame, sizeof(debug_frame));
}
