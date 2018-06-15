/*
 * AArch64 SVE translation
 *
 * Copyright (c) 2018 Linaro, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg-op.h"
#include "tcg-op-gvec.h"
#include "tcg-gvec-desc.h"
#include "arm_ldst.h"
#include "translate.h"
#include "internals.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "translate-a64.h"

/*
 * Helpers for extracting complex instruction fields.
 */

/* See e.g. ASR (immediate, predicated).
 * Returns -1 for unallocated encoding; diagnose later.
 */
static int tszimm_esz(int x)
{
    x >>= 3;  /* discard imm3 */
    return 31 - clz32(x);
}

static int tszimm_shr(int x)
{
    return (16 << tszimm_esz(x)) - x;
}

/* See e.g. LSL (immediate, predicated).  */
static int tszimm_shl(int x)
{
    return x - (8 << tszimm_esz(x));
}

static inline int plus1(int x)
{
    return x + 1;
}

/* The SH bit is in bit 8.  Extract the low 8 and shift.  */
static inline int expand_imm_sh8s(int x)
{
    return (int8_t)x << (x & 0x100 ? 8 : 0);
}

/*
 * Include the generated decoder.
 */

#include "decode-sve.inc.c"

/*
 * Implement all of the translator functions referenced by the decoder.
 */

/* Return the offset info CPUARMState of the predicate vector register Pn.
 * Note for this purpose, FFR is P16.
 */
static inline int pred_full_reg_offset(DisasContext *s, int regno)
{
    return offsetof(CPUARMState, vfp.pregs[regno]);
}

/* Return the byte size of the whole predicate register, VL / 64.  */
static inline int pred_full_reg_size(DisasContext *s)
{
    return s->sve_len >> 3;
}

/* Round up the size of a register to a size allowed by
 * the tcg vector infrastructure.  Any operation which uses this
 * size may assume that the bits above pred_full_reg_size are zero,
 * and must leave them the same way.
 *
 * Note that this is not needed for the vector registers as they
 * are always properly sized for tcg vectors.
 */
static int size_for_gvec(int size)
{
    if (size <= 8) {
        return 8;
    } else {
        return QEMU_ALIGN_UP(size, 16);
    }
}

static int pred_gvec_reg_size(DisasContext *s)
{
    return size_for_gvec(pred_full_reg_size(s));
}

/* Invoke a vector expander on two Zregs.  */
static bool do_vector2_z(DisasContext *s, GVecGen2Fn *gvec_fn,
                         int esz, int rd, int rn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        gvec_fn(tcg_ctx, esz, vec_full_reg_offset(s, rd),
                vec_full_reg_offset(s, rn), vsz, vsz);
    }
    return true;
}

/* Invoke a vector expander on three Zregs.  */
static bool do_vector3_z(DisasContext *s, GVecGen3Fn *gvec_fn,
                         int esz, int rd, int rn, int rm)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        gvec_fn(tcg_ctx, esz, vec_full_reg_offset(s, rd),
                vec_full_reg_offset(s, rn),
                vec_full_reg_offset(s, rm), vsz, vsz);
    }
    return true;
}

/* Invoke a vector move on two Zregs.  */
static bool do_mov_z(DisasContext *s, int rd, int rn)
{
    return do_vector2_z(s, tcg_gen_gvec_mov, 0, rd, rn);
}

/* Initialize a Zreg with replications of a 64-bit immediate.  */
static void do_dupi_z(DisasContext *s, int rd, uint64_t word)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    tcg_gen_gvec_dup64i(tcg_ctx, vec_full_reg_offset(s, rd), vsz, vsz, word);
}

/* Invoke a vector expander on two Pregs.  */
static bool do_vector2_p(DisasContext *s, GVecGen2Fn *gvec_fn,
                         int esz, int rd, int rn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned psz = pred_gvec_reg_size(s);
        gvec_fn(tcg_ctx, esz, pred_full_reg_offset(s, rd),
                pred_full_reg_offset(s, rn), psz, psz);
    }
    return true;
}

/* Invoke a vector expander on three Pregs.  */
static bool do_vector3_p(DisasContext *s, GVecGen3Fn *gvec_fn,
                         int esz, int rd, int rn, int rm)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned psz = pred_gvec_reg_size(s);
        gvec_fn(tcg_ctx, esz, pred_full_reg_offset(s, rd),
                pred_full_reg_offset(s, rn),
                pred_full_reg_offset(s, rm), psz, psz);
    }
    return true;
}

/* Invoke a vector operation on four Pregs.  */
static bool do_vecop4_p(DisasContext *s, const GVecGen4 *gvec_op,
                        int rd, int rn, int rm, int rg)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned psz = pred_gvec_reg_size(s);
        tcg_gen_gvec_4(tcg_ctx, pred_full_reg_offset(s, rd),
                       pred_full_reg_offset(s, rn),
                       pred_full_reg_offset(s, rm),
                       pred_full_reg_offset(s, rg),
                       psz, psz, gvec_op);
    }
    return true;
}

/* Invoke a vector move on two Pregs.  */
static bool do_mov_p(DisasContext *s, int rd, int rn)
{
    return do_vector2_p(s, tcg_gen_gvec_mov, 0, rd, rn);
}

/* Set the cpu flags as per a return from an SVE helper.  */
static void do_pred_flags(DisasContext *s, TCGv_i32 t)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_i32(tcg_ctx, tcg_ctx->cpu_NF, t);
    tcg_gen_andi_i32(tcg_ctx, tcg_ctx->cpu_ZF, t, 2);
    tcg_gen_andi_i32(tcg_ctx, tcg_ctx->cpu_CF, t, 1);
    tcg_gen_movi_i32(tcg_ctx, tcg_ctx->cpu_VF, 0);
}

/* Subroutines computing the ARM PredTest psuedofunction.  */
static void do_predtest1(DisasContext *s, TCGv_i64 d, TCGv_i64 g)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    gen_helper_sve_predtest1(tcg_ctx, t, d, g);
    do_pred_flags(s, t);
    tcg_temp_free_i32(tcg_ctx, t);
}

static void do_predtest(DisasContext *s, int dofs, int gofs, int words)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr dptr = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr gptr = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i32 t;

    tcg_gen_addi_ptr(tcg_ctx, dptr, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, gptr, tcg_ctx->cpu_env, gofs);
    t = tcg_const_i32(tcg_ctx, words);

    gen_helper_sve_predtest(tcg_ctx, t, dptr, gptr, t);
    tcg_temp_free_ptr(tcg_ctx, dptr);
    tcg_temp_free_ptr(tcg_ctx, gptr);

    do_pred_flags(s, t);
    tcg_temp_free_i32(tcg_ctx, t);
}

/* For each element size, the bits within a predicate word that are active.  */
const uint64_t pred_esz_masks[4] = {
    0xffffffffffffffffull, 0x5555555555555555ull,
    0x1111111111111111ull, 0x0101010101010101ull
};

/*
 *** SVE Logical - Unpredicated Group
 */

static bool trans_AND_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_and, 0, a->rd, a->rn, a->rm);
}

static bool trans_ORR_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    if (a->rn == a->rm) { /* MOV */
        return do_mov_z(s, a->rd, a->rn);
    } else {
        return do_vector3_z(s, tcg_gen_gvec_or, 0, a->rd, a->rn, a->rm);
    }
}

static bool trans_EOR_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_xor, 0, a->rd, a->rn, a->rm);
}

static bool trans_BIC_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_andc, 0, a->rd, a->rn, a->rm);
}

/*
 *** SVE Integer Arithmetic - Unpredicated Group
 */

static bool trans_ADD_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_add, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_SUB_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_sub, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_SQADD_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_ssadd, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_SQSUB_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_sssub, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_UQADD_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_usadd, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_UQSUB_zzz(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_vector3_z(s, tcg_gen_gvec_ussub, a->esz, a->rd, a->rn, a->rm);
}

/*
 *** SVE Integer Arithmetic - Binary Predicated Group
 */

static bool do_zpzz_ool(DisasContext *s, arg_rprr_esz *a, gen_helper_gvec_4 *fn)
{
    unsigned vsz = vec_full_reg_size(s);
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, 0, fn);
    }
    return true;
}

#define DO_ZPZZ(NAME, name) \
static bool trans_##NAME##_zpzz(DisasContext *s, arg_rprr_esz *a,         \
                                uint32_t insn)                            \
{                                                                         \
    static gen_helper_gvec_4 * const fns[4] = {                           \
        gen_helper_sve_##name##_zpzz_b, gen_helper_sve_##name##_zpzz_h,   \
        gen_helper_sve_##name##_zpzz_s, gen_helper_sve_##name##_zpzz_d,   \
    };                                                                    \
    return do_zpzz_ool(s, a, fns[a->esz]);                                \
}

DO_ZPZZ(AND, and)
DO_ZPZZ(EOR, eor)
DO_ZPZZ(ORR, orr)
DO_ZPZZ(BIC, bic)

DO_ZPZZ(ADD, add)
DO_ZPZZ(SUB, sub)

DO_ZPZZ(SMAX, smax)
DO_ZPZZ(UMAX, umax)
DO_ZPZZ(SMIN, smin)
DO_ZPZZ(UMIN, umin)
DO_ZPZZ(SABD, sabd)
DO_ZPZZ(UABD, uabd)

DO_ZPZZ(MUL, mul)
DO_ZPZZ(SMULH, smulh)
DO_ZPZZ(UMULH, umulh)

DO_ZPZZ(ASR, asr)
DO_ZPZZ(LSR, lsr)
DO_ZPZZ(LSL, lsl)

static bool trans_SDIV_zpzz(DisasContext *s, arg_rprr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL, NULL, gen_helper_sve_sdiv_zpzz_s, gen_helper_sve_sdiv_zpzz_d
    };
    return do_zpzz_ool(s, a, fns[a->esz]);
}

static bool trans_UDIV_zpzz(DisasContext *s, arg_rprr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL, NULL, gen_helper_sve_udiv_zpzz_s, gen_helper_sve_udiv_zpzz_d
    };
    return do_zpzz_ool(s, a, fns[a->esz]);
}

#undef DO_ZPZZ

/*
 *** SVE Integer Arithmetic - Unary Predicated Group
 */

static bool do_zpz_ool(DisasContext *s, arg_rpr_esz *a, gen_helper_gvec_3 *fn)
{
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, 0, fn);
    }
    return true;
}

#define DO_ZPZ(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rpr_esz *a, uint32_t insn) \
{                                                                   \
    static gen_helper_gvec_3 * const fns[4] = {                     \
        gen_helper_sve_##name##_b, gen_helper_sve_##name##_h,       \
        gen_helper_sve_##name##_s, gen_helper_sve_##name##_d,       \
    };                                                              \
    return do_zpz_ool(s, a, fns[a->esz]);                           \
}

DO_ZPZ(CLS, cls)
DO_ZPZ(CLZ, clz)
DO_ZPZ(CNT_zpz, cnt_zpz)
DO_ZPZ(CNOT, cnot)
DO_ZPZ(NOT_zpz, not_zpz)
DO_ZPZ(ABS, abs)
DO_ZPZ(NEG, neg)

static bool trans_FABS(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_fabs_h,
        gen_helper_sve_fabs_s,
        gen_helper_sve_fabs_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_FNEG(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_fneg_h,
        gen_helper_sve_fneg_s,
        gen_helper_sve_fneg_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_SXTB(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_sxtb_h,
        gen_helper_sve_sxtb_s,
        gen_helper_sve_sxtb_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_UXTB(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_uxtb_h,
        gen_helper_sve_uxtb_s,
        gen_helper_sve_uxtb_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_SXTH(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL, NULL,
        gen_helper_sve_sxth_s,
        gen_helper_sve_sxth_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_UXTH(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL, NULL,
        gen_helper_sve_uxth_s,
        gen_helper_sve_uxth_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_SXTW(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    return do_zpz_ool(s, a, a->esz == 3 ? gen_helper_sve_sxtw_d : NULL);
}

static bool trans_UXTW(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    return do_zpz_ool(s, a, a->esz == 3 ? gen_helper_sve_uxtw_d : NULL);
}

#undef DO_ZPZ

/*
 *** SVE Integer Reduction Group
 */

typedef void gen_helper_gvec_reduc(TCGContext *, TCGv_i64, TCGv_ptr, TCGv_ptr, TCGv_i32);
static bool do_vpz_ool(DisasContext *s, arg_rpr_esz *a,
                       gen_helper_gvec_reduc *fn)
{
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr t_zn, t_pg;
    TCGv_i32 desc;
    TCGv_i64 temp;

    if (fn == NULL) {
        return false;
    }
    if (!sve_access_check(s)) {
        return true;
    }

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    desc = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, 0));
    temp = tcg_temp_new_i64(tcg_ctx);
    t_zn = tcg_temp_new_ptr(tcg_ctx);
    t_pg = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, t_zn, tcg_ctx->cpu_env, vec_full_reg_offset(s, a->rn));
    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));
    fn(tcg_ctx, temp, t_zn, t_pg, desc);
    tcg_temp_free_ptr(tcg_ctx, t_zn);
    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_i32(tcg_ctx, desc);

    write_fp_dreg(s, a->rd, temp);
    tcg_temp_free_i64(tcg_ctx, temp);
    return true;
}

#define DO_VPZ(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rpr_esz *a, uint32_t insn) \
{                                                                        \
    static gen_helper_gvec_reduc * const fns[4] = {                      \
        gen_helper_sve_##name##_b, gen_helper_sve_##name##_h,            \
        gen_helper_sve_##name##_s, gen_helper_sve_##name##_d,            \
    };                                                                   \
    return do_vpz_ool(s, a, fns[a->esz]);                                \
}

DO_VPZ(ORV, orv)
DO_VPZ(ANDV, andv)
DO_VPZ(EORV, eorv)

DO_VPZ(UADDV, uaddv)
DO_VPZ(SMAXV, smaxv)
DO_VPZ(UMAXV, umaxv)
DO_VPZ(SMINV, sminv)
DO_VPZ(UMINV, uminv)

static bool trans_SADDV(DisasContext *s, arg_rpr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_reduc * const fns[4] = {
        gen_helper_sve_saddv_b, gen_helper_sve_saddv_h,
        gen_helper_sve_saddv_s, NULL
    };
    return do_vpz_ool(s, a, fns[a->esz]);
}

#undef DO_VPZ

/*
 *** SVE Shift by Immediate - Predicated Group
 */

/* Store zero into every active element of Zd.  We will use this for two
 * and three-operand predicated instructions for which logic dictates a
 * zero result.
 */
static bool do_clr_zp(DisasContext *s, int rd, int pg, int esz)
{
    static gen_helper_gvec_2 * const fns[4] = {
        gen_helper_sve_clr_b, gen_helper_sve_clr_h,
        gen_helper_sve_clr_s, gen_helper_sve_clr_d,
    };
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, rd),
                           pred_full_reg_offset(s, pg),
                           vsz, vsz, 0, fns[esz]);
    }
    return true;
}

static bool do_zpzi_ool(DisasContext *s, arg_rpri_esz *a,
                        gen_helper_gvec_3 *fn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, a->imm, fn);
    }
    return true;
}

static bool trans_ASR_zpzi(DisasContext *s, arg_rpri_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_asr_zpzi_b, gen_helper_sve_asr_zpzi_h,
        gen_helper_sve_asr_zpzi_s, gen_helper_sve_asr_zpzi_d,
    };
    if (a->esz < 0) {
        /* Invalid tsz encoding -- see tszimm_esz. */
        return false;
    }
    /* Shift by element size is architecturally valid.  For
       arithmetic right-shift, it's the same as by one less. */
    a->imm = MIN(a->imm, (8 << a->esz) - 1);
    return do_zpzi_ool(s, a, fns[a->esz]);
}

static bool trans_LSR_zpzi(DisasContext *s, arg_rpri_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_lsr_zpzi_b, gen_helper_sve_lsr_zpzi_h,
        gen_helper_sve_lsr_zpzi_s, gen_helper_sve_lsr_zpzi_d,
    };
    if (a->esz < 0) {
        return false;
    }
    /* Shift by element size is architecturally valid.
       For logical shifts, it is a zeroing operation.  */
    if (a->imm >= (8 << a->esz)) {
        return do_clr_zp(s, a->rd, a->pg, a->esz);
    } else {
        return do_zpzi_ool(s, a, fns[a->esz]);
    }
}

static bool trans_LSL_zpzi(DisasContext *s, arg_rpri_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_lsl_zpzi_b, gen_helper_sve_lsl_zpzi_h,
        gen_helper_sve_lsl_zpzi_s, gen_helper_sve_lsl_zpzi_d,
    };
    if (a->esz < 0) {
        return false;
    }
    /* Shift by element size is architecturally valid.
       For logical shifts, it is a zeroing operation.  */
    if (a->imm >= (8 << a->esz)) {
        return do_clr_zp(s, a->rd, a->pg, a->esz);
    } else {
        return do_zpzi_ool(s, a, fns[a->esz]);
    }
}

static bool trans_ASRD(DisasContext *s, arg_rpri_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_asrd_b, gen_helper_sve_asrd_h,
        gen_helper_sve_asrd_s, gen_helper_sve_asrd_d,
    };
    if (a->esz < 0) {
        return false;
    }
    /* Shift by element size is architecturally valid.  For arithmetic
       right shift for division, it is a zeroing operation.  */
    if (a->imm >= (8 << a->esz)) {
        return do_clr_zp(s, a->rd, a->pg, a->esz);
    } else {
        return do_zpzi_ool(s, a, fns[a->esz]);
    }
}

/*
 *** SVE Bitwise Shift - Predicated Group
 */

#define DO_ZPZW(NAME, name) \
static bool trans_##NAME##_zpzw(DisasContext *s, arg_rprr_esz *a,         \
                                uint32_t insn)                            \
{                                                                         \
    static gen_helper_gvec_4 * const fns[3] = {                           \
        gen_helper_sve_##name##_zpzw_b, gen_helper_sve_##name##_zpzw_h,   \
        gen_helper_sve_##name##_zpzw_s,                                   \
    };                                                                    \
    if (a->esz < 0 || a->esz >= 3) {                                      \
        return false;                                                     \
    }                                                                     \
    return do_zpzz_ool(s, a, fns[a->esz]);                                \
}

DO_ZPZW(ASR, asr)
DO_ZPZW(LSR, lsr)
DO_ZPZW(LSL, lsl)

#undef DO_ZPZW

/*
 *** SVE Bitwise Shift - Unpredicated Group
 */

static bool do_shift_imm(DisasContext *s, arg_rri_esz *a, bool asr,
                         void (*gvec_fn)(TCGContext *, unsigned, uint32_t, uint32_t,
                                         int64_t, uint32_t, uint32_t))
{
    if (a->esz < 0) {
        /* Invalid tsz encoding -- see tszimm_esz. */
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        /* Shift by element size is architecturally valid.  For
           arithmetic right-shift, it's the same as by one less.
           Otherwise it is a zeroing operation.  */
        if (a->imm >= 8 << a->esz) {
            if (asr) {
                a->imm = (8 << a->esz) - 1;
            } else {
                do_dupi_z(s, a->rd, 0);
                return true;
            }
        }
        gvec_fn(tcg_ctx, a->esz, vec_full_reg_offset(s, a->rd),
                vec_full_reg_offset(s, a->rn), a->imm, vsz, vsz);
    }
    return true;
}

static bool trans_ASR_zzi(DisasContext *s, arg_rri_esz *a, uint32_t insn)
{
    return do_shift_imm(s, a, true, tcg_gen_gvec_sari);
}

static bool trans_LSR_zzi(DisasContext *s, arg_rri_esz *a, uint32_t insn)
{
    return do_shift_imm(s, a, false, tcg_gen_gvec_shri);
}

static bool trans_LSL_zzi(DisasContext *s, arg_rri_esz *a, uint32_t insn)
{
    return do_shift_imm(s, a, false, tcg_gen_gvec_shli);
}

static bool do_zzw_ool(DisasContext *s, arg_rrr_esz *a, gen_helper_gvec_3 *fn)
{
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fn);
    }
    return true;
}

#define DO_ZZW(NAME, name) \
static bool trans_##NAME##_zzw(DisasContext *s, arg_rrr_esz *a,           \
                               uint32_t insn)                             \
{                                                                         \
    static gen_helper_gvec_3 * const fns[4] = {                           \
        gen_helper_sve_##name##_zzw_b, gen_helper_sve_##name##_zzw_h,     \
        gen_helper_sve_##name##_zzw_s, NULL                               \
    };                                                                    \
    return do_zzw_ool(s, a, fns[a->esz]);                                 \
}

DO_ZZW(ASR, asr)
DO_ZZW(LSR, lsr)
DO_ZZW(LSL, lsl)

#undef DO_ZZW

/*
 *** SVE Integer Multiply-Add Group
 */

static bool do_zpzzz_ool(DisasContext *s, arg_rprrr_esz *a,
                         gen_helper_gvec_5 *fn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_5_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->ra),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, 0, fn);
    }
    return true;
}

#define DO_ZPZZZ(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rprrr_esz *a, uint32_t insn) \
{                                                                    \
    static gen_helper_gvec_5 * const fns[4] = {                      \
        gen_helper_sve_##name##_b, gen_helper_sve_##name##_h,        \
        gen_helper_sve_##name##_s, gen_helper_sve_##name##_d,        \
    };                                                               \
    return do_zpzzz_ool(s, a, fns[a->esz]);                          \
}

DO_ZPZZZ(MLA, mla)
DO_ZPZZZ(MLS, mls)

#undef DO_ZPZZZ

/*
 *** SVE Index Generation Group
 */

static void do_index(DisasContext *s, int esz, int rd,
                     TCGv_i64 start, TCGv_i64 incr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, 0));
    TCGv_ptr t_zd = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, t_zd, tcg_ctx->cpu_env, vec_full_reg_offset(s, rd));
    if (esz == 3) {
        gen_helper_sve_index_d(tcg_ctx, t_zd, start, incr, desc);
    } else {
        typedef void index_fn(TCGContext *, TCGv_ptr, TCGv_i32, TCGv_i32, TCGv_i32);
        static index_fn * const fns[3] = {
            gen_helper_sve_index_b,
            gen_helper_sve_index_h,
            gen_helper_sve_index_s,
        };
        TCGv_i32 s32 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 i32 = tcg_temp_new_i32(tcg_ctx);

        tcg_gen_extrl_i64_i32(tcg_ctx, s32, start);
        tcg_gen_extrl_i64_i32(tcg_ctx, i32, incr);
        fns[esz](tcg_ctx, t_zd, s32, i32, desc);

        tcg_temp_free_i32(tcg_ctx, s32);
        tcg_temp_free_i32(tcg_ctx, i32);
    }
    tcg_temp_free_ptr(tcg_ctx, t_zd);
    tcg_temp_free_i32(tcg_ctx, desc);
}

static bool trans_INDEX_ii(DisasContext *s, arg_INDEX_ii *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv_i64 start = tcg_const_i64(tcg_ctx, a->imm1);
        TCGv_i64 incr = tcg_const_i64(tcg_ctx, a->imm2);
        do_index(s, a->esz, a->rd, start, incr);
        tcg_temp_free_i64(tcg_ctx, start);
        tcg_temp_free_i64(tcg_ctx, incr);
    }
    return true;
}

static bool trans_INDEX_ir(DisasContext *s, arg_INDEX_ir *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv_i64 start = tcg_const_i64(tcg_ctx, a->imm);
        TCGv_i64 incr = cpu_reg(s, a->rm);
        do_index(s, a->esz, a->rd, start, incr);
        tcg_temp_free_i64(tcg_ctx, start);
    }
    return true;
}

static bool trans_INDEX_ri(DisasContext *s, arg_INDEX_ri *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv_i64 start = cpu_reg(s, a->rn);
        TCGv_i64 incr = tcg_const_i64(tcg_ctx, a->imm);
        do_index(s, a->esz, a->rd, start, incr);
        tcg_temp_free_i64(tcg_ctx, incr);
    }
    return true;
}

static bool trans_INDEX_rr(DisasContext *s, arg_INDEX_rr *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGv_i64 start = cpu_reg(s, a->rn);
        TCGv_i64 incr = cpu_reg(s, a->rm);
        do_index(s, a->esz, a->rd, start, incr);
    }
    return true;
}

/*
 *** SVE Stack Allocation Group
 */

static bool trans_ADDVL(DisasContext *s, arg_ADDVL *a, uint32_t insn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 rd = cpu_reg_sp(s, a->rd);
    TCGv_i64 rn = cpu_reg_sp(s, a->rn);
    tcg_gen_addi_i64(tcg_ctx, rd, rn, a->imm * vec_full_reg_size(s));
    return true;
}

static bool trans_ADDPL(DisasContext *s, arg_ADDPL *a, uint32_t insn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 rd = cpu_reg_sp(s, a->rd);
    TCGv_i64 rn = cpu_reg_sp(s, a->rn);
    tcg_gen_addi_i64(tcg_ctx, rd, rn, a->imm * pred_full_reg_size(s));
    return true;
}

static bool trans_RDVL(DisasContext *s, arg_RDVL *a, uint32_t insn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 reg = cpu_reg(s, a->rd);
    tcg_gen_movi_i64(tcg_ctx, reg, a->imm * vec_full_reg_size(s));
    return true;
}

/*
 *** SVE Compute Vector Address Group
 */

static bool do_adr(DisasContext *s, arg_rrri *a, gen_helper_gvec_3 *fn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, a->imm, fn);
    }
    return true;
}

static bool trans_ADR_p32(DisasContext *s, arg_rrri *a, uint32_t insn)
{
    return do_adr(s, a, gen_helper_sve_adr_p32);
}

static bool trans_ADR_p64(DisasContext *s, arg_rrri *a, uint32_t insn)
{
    return do_adr(s, a, gen_helper_sve_adr_p64);
}

static bool trans_ADR_s32(DisasContext *s, arg_rrri *a, uint32_t insn)
{
    return do_adr(s, a, gen_helper_sve_adr_s32);
}

static bool trans_ADR_u32(DisasContext *s, arg_rrri *a, uint32_t insn)
{
    return do_adr(s, a, gen_helper_sve_adr_u32);
}

/*
 *** SVE Integer Misc - Unpredicated Group
 */

static bool trans_FEXPA(DisasContext *s, arg_rr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_2 * const fns[4] = {
        NULL,
        gen_helper_sve_fexpa_h,
        gen_helper_sve_fexpa_s,
        gen_helper_sve_fexpa_d,
    };
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_FTSSEL(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_ftssel_h,
        gen_helper_sve_ftssel_s,
        gen_helper_sve_ftssel_d,
    };
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

/*
 *** SVE Predicate Logical Operations Group
 */

static bool do_pppp_flags(DisasContext *s, arg_rprr_s *a,
                          const GVecGen4 *gvec_op)
{
    if (!sve_access_check(s)) {
        return true;
    }

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned psz = pred_gvec_reg_size(s);
    int dofs = pred_full_reg_offset(s, a->rd);
    int nofs = pred_full_reg_offset(s, a->rn);
    int mofs = pred_full_reg_offset(s, a->rm);
    int gofs = pred_full_reg_offset(s, a->pg);

    if (psz == 8) {
        /* Do the operation and the flags generation in temps.  */
        TCGv_i64 pd = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 pn = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 pm = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 pg = tcg_temp_new_i64(tcg_ctx);

        tcg_gen_ld_i64(tcg_ctx, pn, tcg_ctx->cpu_env, nofs);
        tcg_gen_ld_i64(tcg_ctx, pm, tcg_ctx->cpu_env, mofs);
        tcg_gen_ld_i64(tcg_ctx, pg, tcg_ctx->cpu_env, gofs);

        gvec_op->fni8(tcg_ctx, pd, pn, pm, pg);
        tcg_gen_st_i64(tcg_ctx, pd, tcg_ctx->cpu_env, dofs);

        do_predtest1(s, pd, pg);

        tcg_temp_free_i64(tcg_ctx, pd);
        tcg_temp_free_i64(tcg_ctx, pn);
        tcg_temp_free_i64(tcg_ctx, pm);
        tcg_temp_free_i64(tcg_ctx, pg);
    } else {
        /* The operation and flags generation is large.  The computation
         * of the flags depends on the original contents of the guarding
         * predicate.  If the destination overwrites the guarding predicate,
         * then the easiest way to get this right is to save a copy.
          */
        int tofs = gofs;
        if (a->rd == a->pg) {
            tofs = offsetof(CPUARMState, vfp.preg_tmp);
            tcg_gen_gvec_mov(tcg_ctx, 0, tofs, gofs, psz, psz);
        }

        tcg_gen_gvec_4(tcg_ctx, dofs, nofs, mofs, gofs, psz, psz, gvec_op);
        do_predtest(s, dofs, tofs, psz / 8);
    }
    return true;
}

static void gen_and_pg_i64(TCGContext *s, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_and_i64(s, pd, pn, pm);
    tcg_gen_and_i64(s, pd, pd, pg);
}

static void gen_and_pg_vec(TCGContext *s, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_and_vec(s, vece, pd, pn, pm);
    tcg_gen_and_vec(s, vece, pd, pd, pg);
}

static bool trans_AND_pppp(DisasContext *s, arg_rprr_s *a, uint32_t insn)
{
    static const GVecGen4 op = {
        gen_and_pg_i64,
        NULL,
        gen_and_pg_vec,
        gen_helper_sve_and_pppp,
        0,
        0,
        0,
        TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else if (a->rn == a->rm) {
        if (a->pg == a->rn) {
            return do_mov_p(s, a->rd, a->rn);
        } else {
            return do_vector3_p(s, tcg_gen_gvec_and, 0, a->rd, a->rn, a->pg);
        }
    } else if (a->pg == a->rn || a->pg == a->rm) {
        return do_vector3_p(s, tcg_gen_gvec_and, 0, a->rd, a->rn, a->rm);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_bic_pg_i64(TCGContext *s, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_andc_i64(s, pd, pn, pm);
    tcg_gen_and_i64(s, pd, pd, pg);
}

static void gen_bic_pg_vec(TCGContext *s, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_andc_vec(s, vece, pd, pn, pm);
    tcg_gen_and_vec(s, vece, pd, pd, pg);
}

static bool trans_BIC_pppp(DisasContext *s, arg_rprr_s *a, uint32_t insn)
{
    static const GVecGen4 op = {
        gen_bic_pg_i64,
        NULL,
        gen_bic_pg_vec,
        gen_helper_sve_bic_pppp,
        0,
        0,
        0,
        TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else if (a->pg == a->rn) {
        return do_vector3_p(s, tcg_gen_gvec_andc, 0, a->rd, a->rn, a->rm);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_eor_pg_i64(TCGContext *s, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_xor_i64(s, pd, pn, pm);
    tcg_gen_and_i64(s, pd, pd, pg);
}

static void gen_eor_pg_vec(TCGContext *s, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_xor_vec(s, vece, pd, pn, pm);
    tcg_gen_and_vec(s, vece, pd, pd, pg);
}

static bool trans_EOR_pppp(DisasContext *s, arg_rprr_s *a, uint32_t insn)
{
    static const GVecGen4 op = {
        gen_eor_pg_i64,
        NULL,
        gen_eor_pg_vec,
        gen_helper_sve_eor_pppp,
        0,
        0,
        0,
        TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_sel_pg_i64(TCGContext *s, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_and_i64(s, pn, pn, pg);
    tcg_gen_andc_i64(s, pm, pm, pg);
    tcg_gen_or_i64(s, pd, pn, pm);
}

static void gen_sel_pg_vec(TCGContext *s, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_and_vec(s, vece, pn, pn, pg);
    tcg_gen_andc_vec(s, vece, pm, pm, pg);
    tcg_gen_or_vec(s, vece, pd, pn, pm);
}

static bool trans_SEL_pppp(DisasContext *s, arg_rprr_s *a, uint32_t insn)
{
    static const GVecGen4 op = {
        gen_sel_pg_i64,
        NULL,
        gen_sel_pg_vec,
        gen_helper_sve_sel_pppp,
        0,
        0,
        0,
        TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return false;
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_orr_pg_i64(TCGContext *s, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_or_i64(s, pd, pn, pm);
    tcg_gen_and_i64(s, pd, pd, pg);
}

static void gen_orr_pg_vec(TCGContext *s, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_or_vec(s, vece, pd, pn, pm);
    tcg_gen_and_vec(s, vece, pd, pd, pg);
}

static bool trans_ORR_pppp(DisasContext *s, arg_rprr_s *a, uint32_t insn)
{
    static const GVecGen4 op = {
        gen_orr_pg_i64,
        NULL,
        gen_orr_pg_vec,
        gen_helper_sve_orr_pppp,
        0,
        0,
        0,
        TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else if (a->pg == a->rn && a->rn == a->rm) {
        return do_mov_p(s, a->rd, a->rn);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_orn_pg_i64(TCGContext *s, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_orc_i64(s, pd, pn, pm);
    tcg_gen_and_i64(s, pd, pd, pg);
}

static void gen_orn_pg_vec(TCGContext *s, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_orc_vec(s, vece, pd, pn, pm);
    tcg_gen_and_vec(s, vece, pd, pd, pg);
}

static bool trans_ORN_pppp(DisasContext *s, arg_rprr_s *a, uint32_t insn)
{
    static const GVecGen4 op = {
        gen_orn_pg_i64,
        NULL,
        gen_orn_pg_vec,
        gen_helper_sve_orn_pppp,
        0,
        0,
        0,
        TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_nor_pg_i64(TCGContext *s, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_or_i64(s, pd, pn, pm);
    tcg_gen_andc_i64(s, pd, pg, pd);
}

static void gen_nor_pg_vec(TCGContext *s, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_or_vec(s, vece, pd, pn, pm);
    tcg_gen_andc_vec(s, vece, pd, pg, pd);
}

static bool trans_NOR_pppp(DisasContext *s, arg_rprr_s *a, uint32_t insn)
{
    static const GVecGen4 op = {
        gen_nor_pg_i64,
        NULL,
        gen_nor_pg_vec,
        gen_helper_sve_nor_pppp,
        0,
        0,
        0,
        TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_nand_pg_i64(TCGContext *s, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_and_i64(s, pd, pn, pm);
    tcg_gen_andc_i64(s, pd, pg, pd);
}

static void gen_nand_pg_vec(TCGContext *s, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_and_vec(s, vece, pd, pn, pm);
    tcg_gen_andc_vec(s, vece, pd, pg, pd);
}

static bool trans_NAND_pppp(DisasContext *s, arg_rprr_s *a, uint32_t insn)
{
    static const GVecGen4 op = {
        gen_nand_pg_i64,
        NULL,
        gen_nand_pg_vec,
        gen_helper_sve_nand_pppp,
        0,
        0,
        0,
        TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

/*
 *** SVE Predicate Misc Group
 */

static bool trans_PTEST(DisasContext *s, arg_PTEST *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        int nofs = pred_full_reg_offset(s, a->rn);
        int gofs = pred_full_reg_offset(s, a->pg);
        int words = DIV_ROUND_UP(pred_full_reg_size(s), 8);

        if (words == 1) {
            TCGv_i64 pn = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 pg = tcg_temp_new_i64(tcg_ctx);

            tcg_gen_ld_i64(tcg_ctx, pn, tcg_ctx->cpu_env, nofs);
            tcg_gen_ld_i64(tcg_ctx, pg, tcg_ctx->cpu_env, gofs);
            do_predtest1(s, pn, pg);

            tcg_temp_free_i64(tcg_ctx, pn);
            tcg_temp_free_i64(tcg_ctx, pg);
        } else {
            do_predtest(s, nofs, gofs, words);
        }
    }
    return true;
}

/* See the ARM pseudocode DecodePredCount.  */
static unsigned decode_pred_count(unsigned fullsz, int pattern, int esz)
{
    unsigned elements = fullsz >> esz;
    unsigned bound;

    switch (pattern) {
    case 0x0: /* POW2 */
        return pow2floor(elements);
    case 0x1: /* VL1 */
    case 0x2: /* VL2 */
    case 0x3: /* VL3 */
    case 0x4: /* VL4 */
    case 0x5: /* VL5 */
    case 0x6: /* VL6 */
    case 0x7: /* VL7 */
    case 0x8: /* VL8 */
        bound = pattern;
        break;
    case 0x9: /* VL16 */
    case 0xa: /* VL32 */
    case 0xb: /* VL64 */
    case 0xc: /* VL128 */
    case 0xd: /* VL256 */
        bound = 16 << (pattern - 9);
        break;
    case 0x1d: /* MUL4 */
        return elements - elements % 4;
    case 0x1e: /* MUL3 */
        return elements - elements % 3;
    case 0x1f: /* ALL */
        return elements;
    default:   /* #uimm5 */
        return 0;
    }
    return elements >= bound ? bound : 0;
}

/* This handles all of the predicate initialization instructions,
 * PTRUE, PFALSE, SETFFR.  For PFALSE, we will have set PAT == 32
 * so that decode_pred_count returns 0.  For SETFFR, we will have
 * set RD == 16 == FFR.
 */
static bool do_predset(DisasContext *s, int esz, int rd, int pat, bool setflag)
{
    if (!sve_access_check(s)) {
        return true;
    }

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned fullsz = vec_full_reg_size(s);
    unsigned ofs = pred_full_reg_offset(s, rd);
    unsigned numelem, setsz, i;
    uint64_t word, lastword;
    TCGv_i64 t;

    numelem = decode_pred_count(fullsz, pat, esz);

    /* Determine what we must store into each bit, and how many.  */
    if (numelem == 0) {
        lastword = word = 0;
        setsz = fullsz;
    } else {
        setsz = numelem << esz;
        lastword = word = pred_esz_masks[esz];
        if (setsz % 64) {
            lastword &= ~(-1ull << (setsz % 64));
        }
    }

    t = tcg_temp_new_i64(tcg_ctx);
    if (fullsz <= 64) {
        tcg_gen_movi_i64(tcg_ctx, t, lastword);
        tcg_gen_st_i64(tcg_ctx, t, tcg_ctx->cpu_env, ofs);
        goto done;
    }

    if (word == lastword) {
        unsigned maxsz = size_for_gvec(fullsz / 8);
        unsigned oprsz = size_for_gvec(setsz / 8);

        if (oprsz * 8 == setsz) {
            tcg_gen_gvec_dup64i(tcg_ctx, ofs, oprsz, maxsz, word);
            goto done;
        }
        if (oprsz * 8 == setsz + 8) {
            tcg_gen_gvec_dup64i(tcg_ctx, ofs, oprsz, maxsz, word);
            tcg_gen_movi_i64(tcg_ctx, t, 0);
            tcg_gen_st_i64(tcg_ctx, t, tcg_ctx->cpu_env, ofs + oprsz - 8);
            goto done;
        }
    }

    setsz /= 8;
    fullsz /= 8;

    tcg_gen_movi_i64(tcg_ctx, t, word);
    for (i = 0; i < setsz; i += 8) {
        tcg_gen_st_i64(tcg_ctx, t, tcg_ctx->cpu_env, ofs + i);
    }
    if (lastword != word) {
        tcg_gen_movi_i64(tcg_ctx, t, lastword);
        tcg_gen_st_i64(tcg_ctx, t, tcg_ctx->cpu_env, ofs + i);
        i += 8;
    }
    if (i < fullsz) {
        tcg_gen_movi_i64(tcg_ctx, t, 0);
        for (; i < fullsz; i += 8) {
            tcg_gen_st_i64(tcg_ctx, t, tcg_ctx->cpu_env, ofs + i);
        }
    }

 done:
    tcg_temp_free_i64(tcg_ctx, t);

    /* PTRUES */
    if (setflag) {
        tcg_gen_movi_i32(tcg_ctx, tcg_ctx->cpu_NF, -(word != 0));
        tcg_gen_movi_i32(tcg_ctx, tcg_ctx->cpu_CF, word == 0);
        tcg_gen_movi_i32(tcg_ctx, tcg_ctx->cpu_VF, 0);
        tcg_gen_mov_i32(tcg_ctx, tcg_ctx->cpu_ZF, tcg_ctx->cpu_NF);
    }
    return true;
}

static bool trans_PTRUE(DisasContext *s, arg_PTRUE *a, uint32_t insn)
{
    return do_predset(s, a->esz, a->rd, a->pat, a->s);
}

static bool trans_SETFFR(DisasContext *s, arg_SETFFR *a, uint32_t insn)
{
    /* Note pat == 31 is #all, to set all elements.  */
    return do_predset(s, 0, FFR_PRED_NUM, 31, false);
}

static bool trans_PFALSE(DisasContext *s, arg_PFALSE *a, uint32_t insn)
{
    /* Note pat == 32 is #unimp, to set no elements.  */
    return do_predset(s, 0, a->rd, 32, false);
}

static bool trans_RDFFR_p(DisasContext *s, arg_RDFFR_p *a, uint32_t insn)
{
    /* The path through do_pppp_flags is complicated enough to want to avoid
     * duplication.  Frob the arguments into the form of a predicated AND.
     */
    arg_rprr_s alt_a = {
        .rd = a->rd, .pg = a->pg, .s = a->s,
        .rn = FFR_PRED_NUM, .rm = FFR_PRED_NUM,
    };
    return trans_AND_pppp(s, &alt_a, insn);
}

static bool trans_RDFFR(DisasContext *s, arg_RDFFR *a, uint32_t insn)
{
    return do_mov_p(s, a->rd, FFR_PRED_NUM);
}

static bool trans_WRFFR(DisasContext *s, arg_WRFFR *a, uint32_t insn)
{
    return do_mov_p(s, FFR_PRED_NUM, a->rn);
}

static bool do_pfirst_pnext(DisasContext *s, arg_rr_esz *a,
                            void (*gen_fn)(TCGContext *, TCGv_i32, TCGv_ptr,
                                           TCGv_ptr, TCGv_i32))
{
    if (!sve_access_check(s)) {
        return true;
    }

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr t_pd = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_pg = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i32 t;
    unsigned desc;

    desc = DIV_ROUND_UP(pred_full_reg_size(s), 8);
    desc = deposit32(desc, SIMD_DATA_SHIFT, 2, a->esz);

    tcg_gen_addi_ptr(tcg_ctx, t_pd, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rd));
    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rn));
    t = tcg_const_i32(tcg_ctx, desc);

    gen_fn(tcg_ctx, t, t_pd, t_pg, t);
    tcg_temp_free_ptr(tcg_ctx, t_pd);
    tcg_temp_free_ptr(tcg_ctx, t_pg);

    do_pred_flags(s, t);
    tcg_temp_free_i32(tcg_ctx, t);
    return true;
}

static bool trans_PFIRST(DisasContext *s, arg_rr_esz *a, uint32_t insn)
{
    return do_pfirst_pnext(s, a, gen_helper_sve_pfirst);
}

static bool trans_PNEXT(DisasContext *s, arg_rr_esz *a, uint32_t insn)
{
    return do_pfirst_pnext(s, a, gen_helper_sve_pnext);
}

/*
 *** SVE Element Count Group
 */

/* Perform an inline saturating addition of a 32-bit value within
 * a 64-bit register.  The second operand is known to be positive,
 * which halves the comparisions we must perform to bound the result.
 */
static void do_sat_addsub_32(DisasContext *s, TCGv_i64 reg, TCGv_i64 val, bool u, bool d)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int64_t ibound;
    TCGv_i64 bound;
    TCGCond cond;

    /* Use normal 64-bit arithmetic to detect 32-bit overflow.  */
    if (u) {
        tcg_gen_ext32u_i64(tcg_ctx, reg, reg);
    } else {
        tcg_gen_ext32s_i64(tcg_ctx, reg, reg);
    }
    if (d) {
        tcg_gen_sub_i64(tcg_ctx, reg, reg, val);
        ibound = (u ? 0 : INT32_MIN);
        cond = TCG_COND_LT;
    } else {
        tcg_gen_add_i64(tcg_ctx, reg, reg, val);
        ibound = (u ? UINT32_MAX : INT32_MAX);
        cond = TCG_COND_GT;
    }
    bound = tcg_const_i64(tcg_ctx, ibound);
    tcg_gen_movcond_i64(tcg_ctx, cond, reg, reg, bound, bound, reg);
    tcg_temp_free_i64(tcg_ctx, bound);
}

/* Similarly with 64-bit values.  */
static void do_sat_addsub_64(DisasContext *s, TCGv_i64 reg, TCGv_i64 val, bool u, bool d)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2;

    if (u) {
        if (d) {
            tcg_gen_sub_i64(tcg_ctx, t0, reg, val);
            tcg_gen_movi_i64(tcg_ctx, t1, 0);
            tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, reg, reg, val, t1, t0);
        } else {
            tcg_gen_add_i64(tcg_ctx, t0, reg, val);
            tcg_gen_movi_i64(tcg_ctx, t1, -1);
            tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, reg, t0, reg, t1, t0);
        }
    } else {
        if (d) {
            /* Detect signed overflow for subtraction.  */
            tcg_gen_xor_i64(tcg_ctx, t0, reg, val);
            tcg_gen_sub_i64(tcg_ctx, t1, reg, val);
            tcg_gen_xor_i64(tcg_ctx, reg, reg, t0);
            tcg_gen_and_i64(tcg_ctx, t0, t0, reg);

            /* Bound the result.  */
            tcg_gen_movi_i64(tcg_ctx, reg, INT64_MIN);
            t2 = tcg_const_i64(tcg_ctx, 0);
            tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LT, reg, t0, t2, reg, t1);
        } else {
            /* Detect signed overflow for addition.  */
            tcg_gen_xor_i64(tcg_ctx, t0, reg, val);
            tcg_gen_add_i64(tcg_ctx, reg, reg, val);
            tcg_gen_xor_i64(tcg_ctx, t1, reg, val);
            tcg_gen_andc_i64(tcg_ctx, t0, t1, t0);

            /* Bound the result.  */
            tcg_gen_movi_i64(tcg_ctx, t1, INT64_MAX);
            t2 = tcg_const_i64(tcg_ctx, 0);
            tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LT, reg, t0, t2, t1, reg);
        }
        tcg_temp_free_i64(tcg_ctx, t2);
    }
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

/* Similarly with a vector and a scalar operand.  */
static void do_sat_addsub_vec(DisasContext *s, int esz, int rd, int rn,
                              TCGv_i64 val, bool u, bool d)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr dptr, nptr;
    TCGv_i32 t32, desc;
    TCGv_i64 t64;

    dptr = tcg_temp_new_ptr(tcg_ctx);
    nptr = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, dptr, tcg_ctx->cpu_env, vec_full_reg_offset(s, rd));
    tcg_gen_addi_ptr(tcg_ctx, nptr, tcg_ctx->cpu_env, vec_full_reg_offset(s, rn));
    desc = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, 0));

    switch (esz) {
    case MO_8:
        t32 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_extrl_i64_i32(tcg_ctx, t32, val);
        if (d) {
            tcg_gen_neg_i32(tcg_ctx, t32, t32);
        }
        if (u) {
            gen_helper_sve_uqaddi_b(tcg_ctx, dptr, nptr, t32, desc);
        } else {
            gen_helper_sve_sqaddi_b(tcg_ctx, dptr, nptr, t32, desc);
        }
        tcg_temp_free_i32(tcg_ctx, t32);
        break;

    case MO_16:
        t32 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_extrl_i64_i32(tcg_ctx, t32, val);
        if (d) {
            tcg_gen_neg_i32(tcg_ctx, t32, t32);
        }
        if (u) {
            gen_helper_sve_uqaddi_h(tcg_ctx, dptr, nptr, t32, desc);
        } else {
            gen_helper_sve_sqaddi_h(tcg_ctx, dptr, nptr, t32, desc);
        }
        tcg_temp_free_i32(tcg_ctx, t32);
        break;

    case MO_32:
        t64 = tcg_temp_new_i64(tcg_ctx);
        if (d) {
            tcg_gen_neg_i64(tcg_ctx, t64, val);
        } else {
            tcg_gen_mov_i64(tcg_ctx, t64, val);
        }
        if (u) {
            gen_helper_sve_uqaddi_s(tcg_ctx, dptr, nptr, t64, desc);
        } else {
            gen_helper_sve_sqaddi_s(tcg_ctx, dptr, nptr, t64, desc);
        }
        tcg_temp_free_i64(tcg_ctx, t64);
        break;

    case MO_64:
        if (u) {
            if (d) {
                gen_helper_sve_uqsubi_d(tcg_ctx, dptr, nptr, val, desc);
            } else {
                gen_helper_sve_uqaddi_d(tcg_ctx, dptr, nptr, val, desc);
            }
        } else if (d) {
            t64 = tcg_temp_new_i64(tcg_ctx);
            tcg_gen_neg_i64(tcg_ctx, t64, val);
            gen_helper_sve_sqaddi_d(tcg_ctx, dptr, nptr, t64, desc);
            tcg_temp_free_i64(tcg_ctx, t64);
        } else {
            gen_helper_sve_sqaddi_d(tcg_ctx, dptr, nptr, val, desc);
        }
        break;

    default:
        g_assert_not_reached();
    }

    tcg_temp_free_ptr(tcg_ctx, dptr);
    tcg_temp_free_ptr(tcg_ctx, nptr);
    tcg_temp_free_i32(tcg_ctx, desc);
}

static bool trans_CNT_r(DisasContext *s, arg_CNT_r *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned fullsz = vec_full_reg_size(s);
        unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
        tcg_gen_movi_i64(tcg_ctx, cpu_reg(s, a->rd), numelem * a->imm);
    }
    return true;
}

static bool trans_INCDEC_r(DisasContext *s, arg_incdec_cnt *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned fullsz = vec_full_reg_size(s);
        unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
        int inc = numelem * a->imm * (a->d ? -1 : 1);
        TCGv_i64 reg = cpu_reg(s, a->rd);

        tcg_gen_addi_i64(tcg_ctx, reg, reg, inc);
    }
    return true;
}

static bool trans_SINCDEC_r_32(DisasContext *s, arg_incdec_cnt *a,
                               uint32_t insn)
{
    if (!sve_access_check(s)) {
        return true;
    }

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned fullsz = vec_full_reg_size(s);
    unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
    int inc = numelem * a->imm;
    TCGv_i64 reg = cpu_reg(s, a->rd);

    /* Use normal 64-bit arithmetic to detect 32-bit overflow.  */
    if (inc == 0) {
        if (a->u) {
            tcg_gen_ext32u_i64(tcg_ctx, reg, reg);
        } else {
            tcg_gen_ext32s_i64(tcg_ctx, reg, reg);
        }
    } else {
        TCGv_i64 t = tcg_const_i64(tcg_ctx, inc);
        do_sat_addsub_32(s, reg, t, a->u, a->d);
        tcg_temp_free_i64(tcg_ctx, t);
    }
    return true;
}

static bool trans_SINCDEC_r_64(DisasContext *s, arg_incdec_cnt *a,
                               uint32_t insn)
{
    if (!sve_access_check(s)) {
        return true;
    }

    unsigned fullsz = vec_full_reg_size(s);
    unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
    int inc = numelem * a->imm;
    TCGv_i64 reg = cpu_reg(s, a->rd);

    if (inc != 0) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv_i64 t = tcg_const_i64(tcg_ctx, inc);
        do_sat_addsub_64(s, reg, t, a->u, a->d);
        tcg_temp_free_i64(tcg_ctx, t);
    }
    return true;
}

static bool trans_INCDEC_v(DisasContext *s, arg_incdec2_cnt *a, uint32_t insn)
{
    if (a->esz == 0) {
        return false;
    }

    unsigned fullsz = vec_full_reg_size(s);
    unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
    int inc = numelem * a->imm;

    if (inc != 0) {
        if (sve_access_check(s)) {
            TCGContext *tcg_ctx = s->uc->tcg_ctx;
            TCGv_i64 t = tcg_const_i64(tcg_ctx, a->d ? -inc : inc);
            tcg_gen_gvec_adds(tcg_ctx, a->esz, vec_full_reg_offset(s, a->rd),
                              vec_full_reg_offset(s, a->rn),
                              t, fullsz, fullsz);
            tcg_temp_free_i64(tcg_ctx, t);
        }
    } else {
        do_mov_z(s, a->rd, a->rn);
    }
    return true;
}

static bool trans_SINCDEC_v(DisasContext *s, arg_incdec2_cnt *a,
                            uint32_t insn)
{
    if (a->esz == 0) {
        return false;
    }

    unsigned fullsz = vec_full_reg_size(s);
    unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
    int inc = numelem * a->imm;

    if (inc != 0) {
        if (sve_access_check(s)) {
            TCGContext *tcg_ctx = s->uc->tcg_ctx;
            TCGv_i64 t = tcg_const_i64(tcg_ctx, inc);
            do_sat_addsub_vec(s, a->esz, a->rd, a->rn, t, a->u, a->d);
            tcg_temp_free_i64(tcg_ctx, t);
        }
    } else {
        do_mov_z(s, a->rd, a->rn);
    }
    return true;
}

/*
 *** SVE Bitwise Immediate Group
 */

static bool do_zz_dbm(DisasContext *s, arg_rr_dbm *a, GVecGen2iFn *gvec_fn)
{
    uint64_t imm;
    if (!logic_imm_decode_wmask(&imm, extract32(a->dbm, 12, 1),
                                extract32(a->dbm, 0, 6),
                                extract32(a->dbm, 6, 6))) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        gvec_fn(tcg_ctx, MO_64, vec_full_reg_offset(s, a->rd),
                vec_full_reg_offset(s, a->rn), imm, vsz, vsz);
    }
    return true;
}

static bool trans_AND_zzi(DisasContext *s, arg_rr_dbm *a, uint32_t insn)
{
    return do_zz_dbm(s, a, tcg_gen_gvec_andi);
}

static bool trans_ORR_zzi(DisasContext *s, arg_rr_dbm *a, uint32_t insn)
{
    return do_zz_dbm(s, a, tcg_gen_gvec_ori);
}

static bool trans_EOR_zzi(DisasContext *s, arg_rr_dbm *a, uint32_t insn)
{
    return do_zz_dbm(s, a, tcg_gen_gvec_xori);
}

static bool trans_DUPM(DisasContext *s, arg_DUPM *a, uint32_t insn)
{
    uint64_t imm;
    if (!logic_imm_decode_wmask(&imm, extract32(a->dbm, 12, 1),
                                extract32(a->dbm, 0, 6),
                                extract32(a->dbm, 6, 6))) {
        return false;
    }
    if (sve_access_check(s)) {
        do_dupi_z(s, a->rd, imm);
    }
    return true;
}

/*
 *** SVE Integer Wide Immediate - Predicated Group
 */

/* Implement all merging copies.  This is used for CPY (immediate),
 * FCPY, CPY (scalar), CPY (SIMD&FP scalar).
 */
static void do_cpy_m(DisasContext *s, int esz, int rd, int rn, int pg,
                     TCGv_i64 val)
{
    typedef void gen_cpy(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_ptr, TCGv_i64, TCGv_i32);
    static gen_cpy * const fns[4] = {
        gen_helper_sve_cpy_m_b, gen_helper_sve_cpy_m_h,
        gen_helper_sve_cpy_m_s, gen_helper_sve_cpy_m_d,
    };
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, 0));
    TCGv_ptr t_zd = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_zn = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_pg = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, t_zd, tcg_ctx->cpu_env, vec_full_reg_offset(s, rd));
    tcg_gen_addi_ptr(tcg_ctx, t_zn, tcg_ctx->cpu_env, vec_full_reg_offset(s, rn));
    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, pg));

    fns[esz](tcg_ctx, t_zd, t_zn, t_pg, val, desc);

    tcg_temp_free_ptr(tcg_ctx, t_zd);
    tcg_temp_free_ptr(tcg_ctx, t_zn);
    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_i32(tcg_ctx, desc);
}

static bool trans_FCPY(DisasContext *s, arg_FCPY *a, uint32_t insn)
{
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        /* Decode the VFP immediate.  */
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        uint64_t imm = vfp_expand_imm(a->esz, a->imm);
        TCGv_i64 t_imm = tcg_const_i64(tcg_ctx, imm);
        do_cpy_m(s, a->esz, a->rd, a->rn, a->pg, t_imm);
        tcg_temp_free_i64(tcg_ctx, t_imm);
    }
    return true;
}

static bool trans_CPY_m_i(DisasContext *s, arg_rpri_esz *a, uint32_t insn)
{
    if (a->esz == 0 && extract32(insn, 13, 1)) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv_i64 t_imm = tcg_const_i64(tcg_ctx, a->imm);
        do_cpy_m(s, a->esz, a->rd, a->rn, a->pg, t_imm);
        tcg_temp_free_i64(tcg_ctx, t_imm);
    }
    return true;
}

static bool trans_CPY_z_i(DisasContext *s, arg_CPY_z_i *a, uint32_t insn)
{
    static gen_helper_gvec_2i * const fns[4] = {
        gen_helper_sve_cpy_z_b, gen_helper_sve_cpy_z_h,
        gen_helper_sve_cpy_z_s, gen_helper_sve_cpy_z_d,
    };

    if (a->esz == 0 && extract32(insn, 13, 1)) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        TCGv_i64 t_imm = tcg_const_i64(tcg_ctx, a->imm);
        tcg_gen_gvec_2i_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                            pred_full_reg_offset(s, a->pg),
                            t_imm, vsz, vsz, 0, fns[a->esz]);
        tcg_temp_free_i64(tcg_ctx, t_imm);
    }
    return true;
}

/*
 *** SVE Permute Extract Group
 */

static bool trans_EXT(DisasContext *s, arg_EXT *a, uint32_t insn)
{
    if (!sve_access_check(s)) {
        return true;
    }

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    unsigned n_ofs = a->imm >= vsz ? 0 : a->imm;
    unsigned n_siz = vsz - n_ofs;
    unsigned d = vec_full_reg_offset(s, a->rd);
    unsigned n = vec_full_reg_offset(s, a->rn);
    unsigned m = vec_full_reg_offset(s, a->rm);

    /* Use host vector move insns if we have appropriate sizes
     * and no unfortunate overlap.
     */
    if (m != d
        && n_ofs == size_for_gvec(n_ofs)
        && n_siz == size_for_gvec(n_siz)
        && (d != n || n_siz <= n_ofs)) {
        tcg_gen_gvec_mov(tcg_ctx, 0, d, n + n_ofs, n_siz, n_siz);
        if (n_ofs != 0) {
            tcg_gen_gvec_mov(tcg_ctx, 0, d + n_siz, m, n_ofs, n_ofs);
        }
    } else {
        tcg_gen_gvec_3_ool(tcg_ctx, d, n, m, vsz, vsz, n_ofs, gen_helper_sve_ext);
    }
    return true;
}

/*
 *** SVE Permute - Unpredicated Group
 */

static bool trans_DUP_s(DisasContext *s, arg_DUP_s *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_dup_i64(tcg_ctx, a->esz, vec_full_reg_offset(s, a->rd),
                             vsz, vsz, cpu_reg_sp(s, a->rn));
    }
    return true;
}

static bool trans_DUP_x(DisasContext *s, arg_DUP_x *a, uint32_t insn)
{
    if ((a->imm & 0x1f) == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        unsigned dofs = vec_full_reg_offset(s, a->rd);
        unsigned esz, index;

        esz = ctz32(a->imm);
        index = a->imm >> (esz + 1);

        if ((index << esz) < vsz) {
            unsigned nofs = vec_reg_offset(s, a->rn, index, esz);
            tcg_gen_gvec_dup_mem(tcg_ctx, esz, dofs, nofs, vsz, vsz);
        } else {
            tcg_gen_gvec_dup64i(tcg_ctx, dofs, vsz, vsz, 0);
        }
    }
    return true;
}

static void do_insr_i64(DisasContext *s, arg_rrr_esz *a, TCGv_i64 val)
{
    typedef void gen_insr(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_i64, TCGv_i32);
    static gen_insr * const fns[4] = {
        gen_helper_sve_insr_b, gen_helper_sve_insr_h,
        gen_helper_sve_insr_s, gen_helper_sve_insr_d,
    };
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, 0));
    TCGv_ptr t_zd = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_zn = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, t_zd, tcg_ctx->cpu_env, vec_full_reg_offset(s, a->rd));
    tcg_gen_addi_ptr(tcg_ctx, t_zn, tcg_ctx->cpu_env, vec_full_reg_offset(s, a->rn));

    fns[a->esz](tcg_ctx, t_zd, t_zn, val, desc);

    tcg_temp_free_ptr(tcg_ctx, t_zd);
    tcg_temp_free_ptr(tcg_ctx, t_zn);
    tcg_temp_free_i32(tcg_ctx, desc);
}

static bool trans_INSR_f(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_ld_i64(tcg_ctx, t, tcg_ctx->cpu_env, vec_reg_offset(s, a->rm, 0, MO_64));
        do_insr_i64(s, a, t);
        tcg_temp_free_i64(tcg_ctx, t);
    }
    return true;
}

static bool trans_INSR_r(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        do_insr_i64(s, a, cpu_reg(s, a->rm));
    }
    return true;
}

static bool trans_REV_v(DisasContext *s, arg_rr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_2 * const fns[4] = {
        gen_helper_sve_rev_b, gen_helper_sve_rev_h,
        gen_helper_sve_rev_s, gen_helper_sve_rev_d
    };

    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_TBL(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_tbl_b, gen_helper_sve_tbl_h,
        gen_helper_sve_tbl_s, gen_helper_sve_tbl_d
    };

    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_UNPK(DisasContext *s, arg_UNPK *a, uint32_t insn)
{
    static gen_helper_gvec_2 * const fns[4][2] = {
        { NULL, NULL },
        { gen_helper_sve_sunpk_h, gen_helper_sve_uunpk_h },
        { gen_helper_sve_sunpk_s, gen_helper_sve_uunpk_s },
        { gen_helper_sve_sunpk_d, gen_helper_sve_uunpk_d },
    };

    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn)
                           + (a->h ? vsz / 2 : 0),
                           vsz, vsz, 0, fns[a->esz][a->u]);
    }
    return true;
}

/*
 *** SVE Permute - Predicates Group
 */

static bool do_perm_pred3(DisasContext *s, arg_rrr_esz *a, bool high_odd,
                          gen_helper_gvec_3 *fn)
{
    if (!sve_access_check(s)) {
        return true;
    }

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = pred_full_reg_size(s);

    /* Predicate sizes may be smaller and cannot use simd_desc.
       We cannot round up, as we do elsewhere, because we need
       the exact size for ZIP2 and REV.  We retain the style for
       the other helpers for consistency.  */
    TCGv_ptr t_d = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_n = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_m = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i32 t_desc;
    int desc;

    desc = vsz - 2;
    desc = deposit32(desc, SIMD_DATA_SHIFT, 2, a->esz);
    desc = deposit32(desc, SIMD_DATA_SHIFT + 2, 2, high_odd);

    tcg_gen_addi_ptr(tcg_ctx, t_d, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rd));
    tcg_gen_addi_ptr(tcg_ctx, t_n, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rn));
    tcg_gen_addi_ptr(tcg_ctx, t_m, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rm));
    t_desc = tcg_const_i32(tcg_ctx, desc);

    fn(tcg_ctx, t_d, t_n, t_m, t_desc);

    tcg_temp_free_ptr(tcg_ctx, t_d);
    tcg_temp_free_ptr(tcg_ctx, t_n);
    tcg_temp_free_ptr(tcg_ctx, t_m);
    tcg_temp_free_i32(tcg_ctx, t_desc);
    return true;
}

static bool do_perm_pred2(DisasContext *s, arg_rr_esz *a, bool high_odd,
                          gen_helper_gvec_2 *fn)
{
    if (!sve_access_check(s)) {
        return true;
    }

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = pred_full_reg_size(s);
    TCGv_ptr t_d = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_n = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i32 t_desc;
    int desc;

    tcg_gen_addi_ptr(tcg_ctx, t_d, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rd));
    tcg_gen_addi_ptr(tcg_ctx, t_n, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rn));

    /* Predicate sizes may be smaller and cannot use simd_desc.
       We cannot round up, as we do elsewhere, because we need
       the exact size for ZIP2 and REV.  We retain the style for
       the other helpers for consistency.  */

    desc = vsz - 2;
    desc = deposit32(desc, SIMD_DATA_SHIFT, 2, a->esz);
    desc = deposit32(desc, SIMD_DATA_SHIFT + 2, 2, high_odd);
    t_desc = tcg_const_i32(tcg_ctx, desc);

    fn(tcg_ctx, t_d, t_n, t_desc);

    tcg_temp_free_i32(tcg_ctx, t_desc);
    tcg_temp_free_ptr(tcg_ctx, t_d);
    tcg_temp_free_ptr(tcg_ctx, t_n);
    return true;
}

static bool trans_ZIP1_p(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_perm_pred3(s, a, 0, gen_helper_sve_zip_p);
}

static bool trans_ZIP2_p(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_perm_pred3(s, a, 1, gen_helper_sve_zip_p);
}

static bool trans_UZP1_p(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_perm_pred3(s, a, 0, gen_helper_sve_uzp_p);
}

static bool trans_UZP2_p(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_perm_pred3(s, a, 1, gen_helper_sve_uzp_p);
}

static bool trans_TRN1_p(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_perm_pred3(s, a, 0, gen_helper_sve_trn_p);
}

static bool trans_TRN2_p(DisasContext *s, arg_rrr_esz *a, uint32_t insn)
{
    return do_perm_pred3(s, a, 1, gen_helper_sve_trn_p);
}

static bool trans_REV_p(DisasContext *s, arg_rr_esz *a, uint32_t insn)
{
    return do_perm_pred2(s, a, 0, gen_helper_sve_rev_p);
}

static bool trans_PUNPKLO(DisasContext *s, arg_PUNPKLO *a, uint32_t insn)
{
    return do_perm_pred2(s, a, 0, gen_helper_sve_punpk_p);
}

static bool trans_PUNPKHI(DisasContext *s, arg_PUNPKHI *a, uint32_t insn)
{
    return do_perm_pred2(s, a, 1, gen_helper_sve_punpk_p);
}

/*
 *** SVE Memory - 32-bit Gather and Unsized Contiguous Group
 */

/* Subroutine loading a vector register at VOFS of LEN bytes.
 * The load should begin at the address Rn + IMM.
 */

static void do_ldr(DisasContext *s, uint32_t vofs, uint32_t len,
                   int rn, int imm)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint32_t len_align = QEMU_ALIGN_DOWN(len, 8);
    uint32_t len_remain = len % 8;
    uint32_t nparts = len / 8 + ctpop8(len_remain);
    int midx = get_mem_index(s);
    TCGv_i64 addr, t0, t1;

    addr = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);

    /* Note that unpredicated load/store of vector/predicate registers
     * are defined as a stream of bytes, which equates to little-endian
     * operations on larger quantities.  There is no nice way to force
     * a little-endian load for aarch64_be-linux-user out of line.
     *
     * Attempt to keep code expansion to a minimum by limiting the
     * amount of unrolling done.
     */
    if (nparts <= 4) {
        int i;

        for (i = 0; i < len_align; i += 8) {
            tcg_gen_addi_i64(tcg_ctx, addr, cpu_reg_sp(s, rn), imm + i);
            tcg_gen_qemu_ld_i64(s->uc, t0, addr, midx, MO_LEQ);
            tcg_gen_st_i64(tcg_ctx, t0, tcg_ctx->cpu_env, vofs + i);
        }
    } else {
        TCGLabel *loop = gen_new_label(tcg_ctx);
        TCGv_ptr tp, i = tcg_const_local_ptr(tcg_ctx, 0);

        gen_set_label(tcg_ctx, loop);

        /* Minimize the number of local temps that must be re-read from
         * the stack each iteration.  Instead, re-compute values other
         * than the loop counter.
         */
        tp = tcg_temp_new_ptr(tcg_ctx);
        tcg_gen_addi_ptr(tcg_ctx, tp, i, imm);
        tcg_gen_extu_ptr_i64(tcg_ctx, addr, tp);
        tcg_gen_add_i64(tcg_ctx, addr, addr, cpu_reg_sp(s, rn));

        tcg_gen_qemu_ld_i64(s->uc, t0, addr, midx, MO_LEQ);

        tcg_gen_add_ptr(tcg_ctx, tp, tcg_ctx->cpu_env, i);
        tcg_gen_addi_ptr(tcg_ctx, i, i, 8);
        tcg_gen_st_i64(tcg_ctx, t0, tp, vofs);
        tcg_temp_free_ptr(tcg_ctx, tp);

        tcg_gen_brcondi_ptr(tcg_ctx, TCG_COND_LTU, i, len_align, loop);
        tcg_temp_free_ptr(tcg_ctx, i);
    }

    /* Predicate register loads can be any multiple of 2.
     * Note that we still store the entire 64-bit unit into cpu_env.
     */
    if (len_remain) {
        tcg_gen_addi_i64(tcg_ctx, addr, cpu_reg_sp(s, rn), imm + len_align);

        switch (len_remain) {
        case 2:
        case 4:
        case 8:
            tcg_gen_qemu_ld_i64(s->uc, t0, addr, midx, MO_LE | ctz32(len_remain));
            break;

        case 6:
            t1 = tcg_temp_new_i64(tcg_ctx);
            tcg_gen_qemu_ld_i64(s->uc, t0, addr, midx, MO_LEUL);
            tcg_gen_addi_i64(tcg_ctx, addr, addr, 4);
            tcg_gen_qemu_ld_i64(s->uc, t1, addr, midx, MO_LEUW);
            tcg_gen_deposit_i64(tcg_ctx, t0, t0, t1, 32, 32);
            tcg_temp_free_i64(tcg_ctx, t1);
            break;

        default:
            g_assert_not_reached();
        }
        tcg_gen_st_i64(tcg_ctx, t0, tcg_ctx->cpu_env, vofs + len_align);
    }
    tcg_temp_free_i64(tcg_ctx, addr);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static bool trans_LDR_zri(DisasContext *s, arg_rri *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        int size = vec_full_reg_size(s);
        int off = vec_full_reg_offset(s, a->rd);
        do_ldr(s, off, size, a->rn, a->imm * size);
    }
    return true;
}

static bool trans_LDR_pri(DisasContext *s, arg_rri *a, uint32_t insn)
{
    if (sve_access_check(s)) {
        int size = pred_full_reg_size(s);
        int off = pred_full_reg_offset(s, a->rd);
        do_ldr(s, off, size, a->rn, a->imm * size);
    }
    return true;
}
