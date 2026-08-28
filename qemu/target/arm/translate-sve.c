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
#include "tcg/tcg-op.h"
#include "tcg/tcg-op-gvec.h"
#include "tcg/tcg-gvec-desc.h"
#include "qemu/log.h"
#include "arm_ldst.h"
#include "translate.h"
#include "internals.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "translate-a64.h"
#include "fpu/softfloat.h"


typedef void GVecGen2sFn(TCGContext *, unsigned, uint32_t, uint32_t,
                         TCGv_i64, uint32_t, uint32_t);

typedef void gen_helper_gvec_flags_3(TCGContext *, TCGv_i32, TCGv_ptr, TCGv_ptr,
                                     TCGv_ptr, TCGv_i32);
typedef void gen_helper_gvec_flags_4(TCGContext *, TCGv_i32, TCGv_ptr, TCGv_ptr,
                                     TCGv_ptr, TCGv_ptr, TCGv_i32);

typedef void gen_helper_gvec_mem(TCGContext *, TCGv_env, TCGv_ptr, TCGv_i64, TCGv_i32);
typedef void gen_helper_gvec_mem_scatter(TCGContext *, TCGv_env, TCGv_ptr, TCGv_ptr,
                                          TCGv_ptr, TCGv_i64, TCGv_i32);

static bool sve_nonstreaming_access_check(DisasContext *s)
{
    s->is_nonstreaming = true;
    return sve_access_check(s);
}

/*
 * Helpers for extracting complex instruction fields.
 */

/* See e.g. ASR (immediate, predicated).
 * Returns -1 for unallocated encoding; diagnose later.
 */
static int tszimm_esz(DisasContext *s, int x)
{
    x >>= 3;  /* discard imm3 */
    return 31 - clz32(x);
}

static int tszimm_shr(DisasContext *s, int x)
{
    /*
     * We won't use the tszimm_shr() value if tszimm_esz() returns -1; the
     * translator will reject the invalid tsz encoding before using imm.
     */
    int esz = tszimm_esz(s, x);

    if (esz < 0) {
        return esz;
    }
    return (16 << esz) - x;
}

/* See e.g. LSL (immediate, predicated).  */
static int tszimm_shl(DisasContext *s, int x)
{
    int esz = tszimm_esz(s, x);

    if (esz < 0) {
        return esz;
    }
    return x - (8 << esz);
}

static inline int plus1(DisasContext *s, int x)
{
    return x + 1;
}

/* The SH bit is in bit 8.  Extract the low 8 and shift.  */
static inline int expand_imm_sh8s(DisasContext *s, int x)
{
    return (int8_t)x << (x & 0x100 ? 8 : 0);
}

static inline int expand_imm_sh8u(DisasContext *s, int x)
{
    return (uint8_t)x << (x & 0x100 ? 8 : 0);
}

/* Convert a 2-bit memory size (msz) to a 4-bit data type (dtype)
 * with unsigned data.  C.f. SVE Memory Contiguous Load Group.
 */
static inline int msz_dtype(DisasContext *s, int msz)
{
    static const uint8_t dtype[4] = { 0, 5, 10, 15 };
    return dtype[msz];
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
    return (s->pstate_sm ? s->svl : s->sve_len) >> 3;
}

static inline int streaming_vec_reg_size(DisasContext *s)
{
    return s->svl;
}

static inline int streaming_pred_reg_size(DisasContext *s)
{
    return s->svl >> 3;
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
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
static void do_pred_flags(TCGContext *tcg_ctx, TCGv_i32 t)
{
    tcg_gen_mov_i32(tcg_ctx, tcg_ctx->cpu_NF, t);
    tcg_gen_andi_i32(tcg_ctx, tcg_ctx->cpu_ZF, t, 2);
    tcg_gen_andi_i32(tcg_ctx, tcg_ctx->cpu_CF, t, 1);
    tcg_gen_movi_i32(tcg_ctx, tcg_ctx->cpu_VF, 0);
}

/* Subroutines computing the ARM PredTest psuedofunction.  */
static void do_predtest1(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 g)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    gen_helper_sve_predtest1(tcg_ctx, t, d, g);
    do_pred_flags(tcg_ctx, t);
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

    do_pred_flags(tcg_ctx, t);
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

static bool trans_AND_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_and, 0, a->rd, a->rn, a->rm);
}

static bool trans_ORR_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_or, 0, a->rd, a->rn, a->rm);
}

static bool trans_EOR_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_xor, 0, a->rd, a->rn, a->rm);
}

static bool trans_BIC_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_andc, 0, a->rd, a->rn, a->rm);
}

static bool do_zzzz_ool(DisasContext *s, arg_rprrr_esz *a,
                        gen_helper_gvec_4 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, 0, fn);
    }
    return true;
}

static bool trans_EOR3(DisasContext *s, arg_rprrr_esz *a)
{
    return do_zzzz_ool(s, a, gen_helper_sve2_eor3);
}

static bool trans_BSL(DisasContext *s, arg_rprrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_bitsel(tcg_ctx, 0, vec_full_reg_offset(s, a->rd),
                            vec_full_reg_offset(s, a->ra),
                            vec_full_reg_offset(s, a->rn),
                            vec_full_reg_offset(s, a->rm), vsz, vsz);
    }
    return true;
}

static bool trans_BCAX(DisasContext *s, arg_rprrr_esz *a)
{
    return do_zzzz_ool(s, a, gen_helper_sve2_bcax);
}

static bool trans_BSL1N(DisasContext *s, arg_rprrr_esz *a)
{
    return do_zzzz_ool(s, a, gen_helper_sve2_bsl1n);
}

static bool trans_BSL2N(DisasContext *s, arg_rprrr_esz *a)
{
    return do_zzzz_ool(s, a, gen_helper_sve2_bsl2n);
}

static bool trans_NBSL(DisasContext *s, arg_rprrr_esz *a)
{
    return do_zzzz_ool(s, a, gen_helper_sve2_nbsl);
}

static bool trans_XAR(DisasContext *s, arg_rrri_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_xar_b,
        gen_helper_sve2_xar_h,
        gen_helper_sve2_xar_s,
        gen_helper_sve2_xar_d,
    };
    int esize;
    int shift;

    if (a->esz < 0) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        esize = 8 << a->esz;
        shift = a->imm & (esize - 1);
        if (shift == 0) {
            tcg_gen_gvec_xor(tcg_ctx, a->esz,
                             vec_full_reg_offset(s, a->rd),
                             vec_full_reg_offset(s, a->rn),
                             vec_full_reg_offset(s, a->rm), vsz, vsz);
        } else {
            tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                               vec_full_reg_offset(s, a->rn),
                               vec_full_reg_offset(s, a->rm),
                               vsz, vsz, shift, fns[a->esz]);
        }
    }
    return true;
}

static bool do_pmull(DisasContext *s, arg_rrr_esz *a, int sel)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_gvec_pmull_q, gen_helper_sve2_pmull_h,
        NULL,                    gen_helper_sve2_pmull_d,
    };

    if (!dc_isar_feature(aa64_sve2, s) || fns[a->esz] == NULL) {
        return false;
    }
    if (a->esz == 0) {
        if (!dc_isar_feature(aa64_sve2_pmull128, s)) {
            return false;
        }
        s->is_nonstreaming = true;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, sel, fns[a->esz]);
    }
    return true;
}

static bool trans_PMULLB(DisasContext *s, arg_rrr_esz *a)
{
    return do_pmull(s, a, 0);
}

static bool trans_PMULLT(DisasContext *s, arg_rrr_esz *a)
{
    return do_pmull(s, a, 1);
}

static bool trans_MUL_zzz(DisasContext *s, arg_rrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_mul(tcg_ctx, a->esz, vec_full_reg_offset(s, a->rd),
                         vec_full_reg_offset(s, a->rn),
                         vec_full_reg_offset(s, a->rm), vsz, vsz);
    }
    return true;
}

static bool do_mulh_zzz(DisasContext *s, arg_rrr_esz *a,
                        gen_helper_gvec_3 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_SMULH_zzz(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_smulh_zzz_b,
        gen_helper_sve2_smulh_zzz_h,
        gen_helper_sve2_smulh_zzz_s,
        gen_helper_sve2_smulh_zzz_d,
    };

    return do_mulh_zzz(s, a, fns);
}

static bool trans_UMULH_zzz(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_umulh_zzz_b,
        gen_helper_sve2_umulh_zzz_h,
        gen_helper_sve2_umulh_zzz_s,
        gen_helper_sve2_umulh_zzz_d,
    };

    return do_mulh_zzz(s, a, fns);
}

static bool trans_SQDMULH_zzz(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_sqdmulh_b,
        gen_helper_sve2_sqdmulh_h,
        gen_helper_sve2_sqdmulh_s,
        gen_helper_sve2_sqdmulh_d,
    };

    return do_mulh_zzz(s, a, fns);
}

static bool trans_SQRDMULH_zzz(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_sqrdmulh_b,
        gen_helper_sve2_sqrdmulh_h,
        gen_helper_sve2_sqrdmulh_s,
        gen_helper_sve2_sqrdmulh_d,
    };

    return do_mulh_zzz(s, a, fns);
}

static bool trans_PMUL_zzz(DisasContext *s, arg_rrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || a->esz != 0) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, gen_helper_gvec_pmul_b);
    }
    return true;
}

static bool do_mul_zzx(DisasContext *s, arg_rrx_esz *a,
                       gen_helper_gvec_3 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, a->index, fns[a->esz]);
    }
    return true;
}

static bool trans_MUL_zzx(DisasContext *s, arg_rrx_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_mul_idx_h,
        gen_helper_sve2_mul_idx_s,
        gen_helper_sve2_mul_idx_d,
    };

    return do_mul_zzx(s, a, fns);
}

static bool trans_SQDMULH_zzx(DisasContext *s, arg_rrx_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_sqdmulh_idx_h,
        gen_helper_sve2_sqdmulh_idx_s,
        gen_helper_sve2_sqdmulh_idx_d,
    };

    return do_mul_zzx(s, a, fns);
}

static bool trans_SQRDMULH_zzx(DisasContext *s, arg_rrx_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_sqrdmulh_idx_h,
        gen_helper_sve2_sqrdmulh_idx_s,
        gen_helper_sve2_sqrdmulh_idx_d,
    };

    return do_mul_zzx(s, a, fns);
}

static bool do_sqrdmla_zzx(DisasContext *s, arg_rrxr_esz *a,
                           gen_helper_gvec_4 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || fns[a->esz] == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, a->index, fns[a->esz]);
    }
    return true;
}

static bool trans_SQRDMLAH_zzxz(DisasContext *s, arg_rrxr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL,
        gen_helper_sve2_sqrdmlah_idx_h,
        gen_helper_sve2_sqrdmlah_idx_s,
        gen_helper_sve2_sqrdmlah_idx_d,
    };

    return do_sqrdmla_zzx(s, a, fns);
}

static bool trans_SQRDMLSH_zzxz(DisasContext *s, arg_rrxr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL,
        gen_helper_sve2_sqrdmlsh_idx_h,
        gen_helper_sve2_sqrdmlsh_idx_s,
        gen_helper_sve2_sqrdmlsh_idx_d,
    };

    return do_sqrdmla_zzx(s, a, fns);
}

static bool do_widen_mul_zzx(DisasContext *s, arg_rrx_esz *a,
                             gen_helper_gvec_3 * const fns[4], int top)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || fns[a->esz] == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, (a->index << 1) | top,
                           fns[a->esz]);
    }
    return true;
}

#define DO_WIDEN_MUL_ZZX(NAME, helper, TOP)                             \
static bool trans_##NAME(DisasContext *s, arg_rrx_esz *a)               \
{                                                                       \
    static gen_helper_gvec_3 * const fns[4] = {                         \
        NULL, NULL,                                                     \
        gen_helper_sve2_##helper##_s,                                   \
        gen_helper_sve2_##helper##_d,                                   \
    };                                                                  \
                                                                        \
    return do_widen_mul_zzx(s, a, fns, TOP);                            \
}

DO_WIDEN_MUL_ZZX(SMULLB_zzx, smull_idx, 0)
DO_WIDEN_MUL_ZZX(SMULLT_zzx, smull_idx, 1)
DO_WIDEN_MUL_ZZX(UMULLB_zzx, umull_idx, 0)
DO_WIDEN_MUL_ZZX(UMULLT_zzx, umull_idx, 1)
DO_WIDEN_MUL_ZZX(SQDMULLB_zzx, sqdmull_idx, 0)
DO_WIDEN_MUL_ZZX(SQDMULLT_zzx, sqdmull_idx, 1)

#undef DO_WIDEN_MUL_ZZX

static bool do_widen_acc_zzx(DisasContext *s, arg_rrx_esz *a,
                             gen_helper_gvec_4 * const fns[4], int top)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || fns[a->esz] == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->rd), vsz, vsz,
                           (a->index << 1) | top, fns[a->esz]);
    }
    return true;
}

#define DO_WIDEN_ACC_ZZX(NAME, helper, TOP)                             \
static bool trans_##NAME(DisasContext *s, arg_rrx_esz *a)               \
{                                                                       \
    static gen_helper_gvec_4 * const fns[4] = {                         \
        NULL, NULL,                                                     \
        gen_helper_sve2_##helper##_s,                                   \
        gen_helper_sve2_##helper##_d,                                   \
    };                                                                  \
                                                                        \
    return do_widen_acc_zzx(s, a, fns, TOP);                            \
}

DO_WIDEN_ACC_ZZX(SQDMLALB_zzxw, sqdmlal_idx, 0)
DO_WIDEN_ACC_ZZX(SQDMLALT_zzxw, sqdmlal_idx, 1)
DO_WIDEN_ACC_ZZX(SQDMLSLB_zzxw, sqdmlsl_idx, 0)
DO_WIDEN_ACC_ZZX(SQDMLSLT_zzxw, sqdmlsl_idx, 1)
DO_WIDEN_ACC_ZZX(SMLALB_zzxw, smlal_idx, 0)
DO_WIDEN_ACC_ZZX(SMLALT_zzxw, smlal_idx, 1)
DO_WIDEN_ACC_ZZX(UMLALB_zzxw, umlal_idx, 0)
DO_WIDEN_ACC_ZZX(UMLALT_zzxw, umlal_idx, 1)
DO_WIDEN_ACC_ZZX(SMLSLB_zzxw, smlsl_idx, 0)
DO_WIDEN_ACC_ZZX(SMLSLT_zzxw, smlsl_idx, 1)
DO_WIDEN_ACC_ZZX(UMLSLB_zzxw, umlsl_idx, 0)
DO_WIDEN_ACC_ZZX(UMLSLT_zzxw, umlsl_idx, 1)

#undef DO_WIDEN_ACC_ZZX

static bool do_widen_acc_zzzw(DisasContext *s, arg_rprrr_esz *a,
                              gen_helper_gvec_4 * const fns[4], int data)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || fns[a->esz] == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra), vsz, vsz,
                           data, fns[a->esz]);
    }
    return true;
}

#define DO_WIDEN_ACC_ZZZW(NAME, helper, DATA)                           \
static bool trans_##NAME(DisasContext *s, arg_rprrr_esz *a)             \
{                                                                       \
    static gen_helper_gvec_4 * const fns[4] = {                         \
        NULL,                                                           \
        gen_helper_sve2_##helper##_h,                                   \
        gen_helper_sve2_##helper##_s,                                   \
        gen_helper_sve2_##helper##_d,                                   \
    };                                                                  \
                                                                        \
    return do_widen_acc_zzzw(s, a, fns, DATA);                          \
}

DO_WIDEN_ACC_ZZZW(SQDMLALB_zzzw, sqdmlal_zzzw, 0)
DO_WIDEN_ACC_ZZZW(SQDMLALT_zzzw, sqdmlal_zzzw, 3)
DO_WIDEN_ACC_ZZZW(SQDMLALBT, sqdmlal_zzzw, 2)
DO_WIDEN_ACC_ZZZW(SQDMLSLB_zzzw, sqdmlsl_zzzw, 0)
DO_WIDEN_ACC_ZZZW(SQDMLSLT_zzzw, sqdmlsl_zzzw, 3)
DO_WIDEN_ACC_ZZZW(SQDMLSLBT, sqdmlsl_zzzw, 2)
DO_WIDEN_ACC_ZZZW(SMLALB_zzzw, smlal_zzzw, 0)
DO_WIDEN_ACC_ZZZW(SMLALT_zzzw, smlal_zzzw, 3)
DO_WIDEN_ACC_ZZZW(UMLALB_zzzw, umlal_zzzw, 0)
DO_WIDEN_ACC_ZZZW(UMLALT_zzzw, umlal_zzzw, 3)
DO_WIDEN_ACC_ZZZW(SMLSLB_zzzw, smlsl_zzzw, 0)
DO_WIDEN_ACC_ZZZW(SMLSLT_zzzw, smlsl_zzzw, 3)
DO_WIDEN_ACC_ZZZW(UMLSLB_zzzw, umlsl_zzzw, 0)
DO_WIDEN_ACC_ZZZW(UMLSLT_zzzw, umlsl_zzzw, 3)
DO_WIDEN_ACC_ZZZW(SABALB, sabal, 0)
DO_WIDEN_ACC_ZZZW(SABALT, sabal, 3)
DO_WIDEN_ACC_ZZZW(UABALB, uabal, 0)
DO_WIDEN_ACC_ZZZW(UABALT, uabal, 3)

#undef DO_WIDEN_ACC_ZZZW

static bool do_sqrdmla_zzzz(DisasContext *s, arg_rprrr_esz *a,
                            gen_helper_gvec_4 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_SQRDMLAH_zzzz(DisasContext *s, arg_rprrr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        gen_helper_sve2_sqrdmlah_b,
        gen_helper_sve2_sqrdmlah_h,
        gen_helper_sve2_sqrdmlah_s,
        gen_helper_sve2_sqrdmlah_d,
    };

    return do_sqrdmla_zzzz(s, a, fns);
}

static bool trans_SQRDMLSH_zzzz(DisasContext *s, arg_rprrr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        gen_helper_sve2_sqrdmlsh_b,
        gen_helper_sve2_sqrdmlsh_h,
        gen_helper_sve2_sqrdmlsh_s,
        gen_helper_sve2_sqrdmlsh_d,
    };

    return do_sqrdmla_zzzz(s, a, fns);
}

static bool do_sve2_zzzz_rot(DisasContext *s, arg_rprrr_rot_esz *a,
                             gen_helper_gvec_4 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || fns[a->esz] == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, a->rot, fns[a->esz]);
    }
    return true;
}

static bool trans_CMLA_zzzz(DisasContext *s, arg_rprrr_rot_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        gen_helper_sve2_cmla_zzzz_b,
        gen_helper_sve2_cmla_zzzz_h,
        gen_helper_sve2_cmla_zzzz_s,
        gen_helper_sve2_cmla_zzzz_d,
    };

    return do_sve2_zzzz_rot(s, a, fns);
}

static bool trans_CDOT_zzzz(DisasContext *s, arg_rprrr_rot_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL,
        NULL,
        gen_helper_sve2_cdot_zzzz_s,
        gen_helper_sve2_cdot_zzzz_d,
    };

    return do_sve2_zzzz_rot(s, a, fns);
}

static bool trans_SQRDCMLAH_zzzz(DisasContext *s, arg_rprrr_rot_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        gen_helper_sve2_sqrdcmlah_zzzz_b,
        gen_helper_sve2_sqrdcmlah_zzzz_h,
        gen_helper_sve2_sqrdcmlah_zzzz_s,
        gen_helper_sve2_sqrdcmlah_zzzz_d,
    };

    return do_sve2_zzzz_rot(s, a, fns);
}

static bool do_sve2_rrxr_rot(DisasContext *s, arg_disas_sve43 *a,
                             gen_helper_gvec_4 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || fn == NULL) {
        return false;
    }
    tcg_debug_assert(a->rd == a->ra);
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, (a->index << 2) | a->rot, fn);
    }
    return true;
}

static bool trans_CMLA_zzxz_h(DisasContext *s, arg_disas_sve43 *a)
{
    return do_sve2_rrxr_rot(s, a, gen_helper_sve2_cmla_idx_h);
}

static bool trans_CMLA_zzxz_s(DisasContext *s, arg_disas_sve43 *a)
{
    return do_sve2_rrxr_rot(s, a, gen_helper_sve2_cmla_idx_s);
}

static bool trans_SQRDCMLAH_zzxz_h(DisasContext *s, arg_disas_sve43 *a)
{
    return do_sve2_rrxr_rot(s, a, gen_helper_sve2_sqrdcmlah_idx_h);
}

static bool trans_SQRDCMLAH_zzxz_s(DisasContext *s, arg_disas_sve43 *a)
{
    return do_sve2_rrxr_rot(s, a, gen_helper_sve2_sqrdcmlah_idx_s);
}

static bool trans_CDOT_zzxw_s(DisasContext *s, arg_disas_sve43 *a)
{
    return do_sve2_rrxr_rot(s, a, gen_helper_sve2_cdot_idx_s);
}

static bool trans_CDOT_zzxw_d(DisasContext *s, arg_disas_sve43 *a)
{
    return do_sve2_rrxr_rot(s, a, gen_helper_sve2_cdot_idx_d);
}

static bool do_sve2_aba(DisasContext *s, arg_rrr_esz *a,
                        gen_helper_gvec_3 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_SABA(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_gvec_saba_b,
        gen_helper_gvec_saba_h,
        gen_helper_gvec_saba_s,
        gen_helper_gvec_saba_d,
    };

    return do_sve2_aba(s, a, fns);
}

static bool trans_UABA(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_gvec_uaba_b,
        gen_helper_gvec_uaba_h,
        gen_helper_gvec_uaba_s,
        gen_helper_gvec_uaba_d,
    };

    return do_sve2_aba(s, a, fns);
}

static bool do_widen_zzz(DisasContext *s, arg_rrr_esz *a,
                         gen_helper_gvec_3 * const fns[4], int data)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || fns[a->esz] == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, data, fns[a->esz]);
    }
    return true;
}

static bool trans_SADDLB(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_saddl_h,
        gen_helper_sve2_saddl_s,
        gen_helper_sve2_saddl_d,
    };

    return do_widen_zzz(s, a, fns, 0);
}

static bool trans_SADDLT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_saddl_h,
        gen_helper_sve2_saddl_s,
        gen_helper_sve2_saddl_d,
    };

    return do_widen_zzz(s, a, fns, 3);
}

static bool trans_UADDLB(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_uaddl_h,
        gen_helper_sve2_uaddl_s,
        gen_helper_sve2_uaddl_d,
    };

    return do_widen_zzz(s, a, fns, 0);
}

static bool trans_UADDLT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_uaddl_h,
        gen_helper_sve2_uaddl_s,
        gen_helper_sve2_uaddl_d,
    };

    return do_widen_zzz(s, a, fns, 3);
}

static bool trans_SSUBLB(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_ssubl_h,
        gen_helper_sve2_ssubl_s,
        gen_helper_sve2_ssubl_d,
    };

    return do_widen_zzz(s, a, fns, 0);
}

static bool trans_SSUBLT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_ssubl_h,
        gen_helper_sve2_ssubl_s,
        gen_helper_sve2_ssubl_d,
    };

    return do_widen_zzz(s, a, fns, 3);
}

static bool trans_USUBLB(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_usubl_h,
        gen_helper_sve2_usubl_s,
        gen_helper_sve2_usubl_d,
    };

    return do_widen_zzz(s, a, fns, 0);
}

static bool trans_USUBLT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_usubl_h,
        gen_helper_sve2_usubl_s,
        gen_helper_sve2_usubl_d,
    };

    return do_widen_zzz(s, a, fns, 3);
}

#define DO_WIDEN_ZZZ_TRANS(NAME, helper, DATA)                          \
static bool trans_##NAME(DisasContext *s, arg_rrr_esz *a)               \
{                                                                       \
    static gen_helper_gvec_3 * const fns[4] = {                         \
        NULL,                                                           \
        gen_helper_sve2_##helper##_h,                                   \
        gen_helper_sve2_##helper##_s,                                   \
        gen_helper_sve2_##helper##_d,                                   \
    };                                                                  \
                                                                        \
    return do_widen_zzz(s, a, fns, DATA);                               \
}

DO_WIDEN_ZZZ_TRANS(SADDLBT, saddl, 2)
DO_WIDEN_ZZZ_TRANS(SSUBLBT, ssubl, 2)
DO_WIDEN_ZZZ_TRANS(SSUBLTB, ssubl, 1)
DO_WIDEN_ZZZ_TRANS(SABDLB, sabdl, 0)
DO_WIDEN_ZZZ_TRANS(SABDLT, sabdl, 3)
DO_WIDEN_ZZZ_TRANS(UABDLB, uabdl, 0)
DO_WIDEN_ZZZ_TRANS(UABDLT, uabdl, 3)
DO_WIDEN_ZZZ_TRANS(SMULLB_zzz, smull_zzz, 0)
DO_WIDEN_ZZZ_TRANS(SMULLT_zzz, smull_zzz, 3)
DO_WIDEN_ZZZ_TRANS(UMULLB_zzz, umull_zzz, 0)
DO_WIDEN_ZZZ_TRANS(UMULLT_zzz, umull_zzz, 3)
DO_WIDEN_ZZZ_TRANS(SQDMULLB_zzz, sqdmull_zzz, 0)
DO_WIDEN_ZZZ_TRANS(SQDMULLT_zzz, sqdmull_zzz, 3)

#undef DO_WIDEN_ZZZ_TRANS

static bool trans_SADDWB(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_saddw_h,
        gen_helper_sve2_saddw_s,
        gen_helper_sve2_saddw_d,
    };

    return do_widen_zzz(s, a, fns, 0);
}

static bool trans_SADDWT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_saddw_h,
        gen_helper_sve2_saddw_s,
        gen_helper_sve2_saddw_d,
    };

    return do_widen_zzz(s, a, fns, 1);
}

static bool trans_UADDWB(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_uaddw_h,
        gen_helper_sve2_uaddw_s,
        gen_helper_sve2_uaddw_d,
    };

    return do_widen_zzz(s, a, fns, 0);
}

static bool trans_UADDWT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_uaddw_h,
        gen_helper_sve2_uaddw_s,
        gen_helper_sve2_uaddw_d,
    };

    return do_widen_zzz(s, a, fns, 1);
}

static bool trans_SSUBWB(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_ssubw_h,
        gen_helper_sve2_ssubw_s,
        gen_helper_sve2_ssubw_d,
    };

    return do_widen_zzz(s, a, fns, 0);
}

static bool trans_SSUBWT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_ssubw_h,
        gen_helper_sve2_ssubw_s,
        gen_helper_sve2_ssubw_d,
    };

    return do_widen_zzz(s, a, fns, 1);
}

static bool trans_USUBWB(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_usubw_h,
        gen_helper_sve2_usubw_s,
        gen_helper_sve2_usubw_d,
    };

    return do_widen_zzz(s, a, fns, 0);
}

static bool trans_USUBWT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve2_usubw_h,
        gen_helper_sve2_usubw_s,
        gen_helper_sve2_usubw_d,
    };

    return do_widen_zzz(s, a, fns, 1);
}

static bool do_shll(DisasContext *s, arg_rri_esz *a,
                    gen_helper_gvec_2 * const fns[3], int sel)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || a->esz < 0 || a->esz > 2) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn), vsz, vsz,
                           (a->imm << 1) | sel, fns[a->esz]);
    }
    return true;
}

static bool trans_SSHLLB(DisasContext *s, arg_rri_esz *a)
{
    static gen_helper_gvec_2 * const fns[3] = {
        gen_helper_sve2_sshll_h,
        gen_helper_sve2_sshll_s,
        gen_helper_sve2_sshll_d,
    };

    return do_shll(s, a, fns, 0);
}

static bool trans_SSHLLT(DisasContext *s, arg_rri_esz *a)
{
    static gen_helper_gvec_2 * const fns[3] = {
        gen_helper_sve2_sshll_h,
        gen_helper_sve2_sshll_s,
        gen_helper_sve2_sshll_d,
    };

    return do_shll(s, a, fns, 1);
}

static bool trans_USHLLB(DisasContext *s, arg_rri_esz *a)
{
    static gen_helper_gvec_2 * const fns[3] = {
        gen_helper_sve2_ushll_h,
        gen_helper_sve2_ushll_s,
        gen_helper_sve2_ushll_d,
    };

    return do_shll(s, a, fns, 0);
}

static bool trans_USHLLT(DisasContext *s, arg_rri_esz *a)
{
    static gen_helper_gvec_2 * const fns[3] = {
        gen_helper_sve2_ushll_h,
        gen_helper_sve2_ushll_s,
        gen_helper_sve2_ushll_d,
    };

    return do_shll(s, a, fns, 1);
}

static bool do_narrow_zzz(DisasContext *s, arg_rrr_esz *a,
                          gen_helper_gvec_3 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || fns[a->esz] == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

#define DO_SVE2_NARROW(NAME, name)                                      \
static bool trans_##NAME(DisasContext *s, arg_rrr_esz *a)               \
{                                                                       \
    static gen_helper_gvec_3 * const fns[4] = {                         \
        NULL,                                                           \
        gen_helper_sve2_##name##_h,                                     \
        gen_helper_sve2_##name##_s,                                     \
        gen_helper_sve2_##name##_d,                                     \
    };                                                                  \
                                                                        \
    return do_narrow_zzz(s, a, fns);                                    \
}

DO_SVE2_NARROW(ADDHNB, addhnb)
DO_SVE2_NARROW(ADDHNT, addhnt)
DO_SVE2_NARROW(RADDHNB, raddhnb)
DO_SVE2_NARROW(RADDHNT, raddhnt)
DO_SVE2_NARROW(SUBHNB, subhnb)
DO_SVE2_NARROW(SUBHNT, subhnt)
DO_SVE2_NARROW(RSUBHNB, rsubhnb)
DO_SVE2_NARROW(RSUBHNT, rsubhnt)

#undef DO_SVE2_NARROW

static bool do_xtn(DisasContext *s, arg_rri_esz *a,
                   gen_helper_gvec_2 * const fns[3])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) ||
        a->esz < 0 || a->esz > 2 || a->imm != 0) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

#define DO_XTN_TRANS(NAME, name)                                        \
static bool trans_##NAME(DisasContext *s, arg_rri_esz *a)               \
{                                                                       \
    static gen_helper_gvec_2 * const fns[3] = {                         \
        gen_helper_sve2_##name##_h,                                     \
        gen_helper_sve2_##name##_s,                                     \
        gen_helper_sve2_##name##_d,                                     \
    };                                                                  \
                                                                        \
    return do_xtn(s, a, fns);                                           \
}

DO_XTN_TRANS(SQXTNB, sqxtnb)
DO_XTN_TRANS(SQXTNT, sqxtnt)
DO_XTN_TRANS(UQXTNB, uqxtnb)
DO_XTN_TRANS(UQXTNT, uqxtnt)
DO_XTN_TRANS(SQXTUNB, sqxtunb)
DO_XTN_TRANS(SQXTUNT, sqxtunt)

#undef DO_XTN_TRANS

static bool do_shr_narrow(DisasContext *s, arg_rri_esz *a,
                          gen_helper_gvec_2 * const fns[3])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || a->esz < 0 || a->esz > 2) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vsz, vsz, a->imm, fns[a->esz]);
    }
    return true;
}

#define DO_SHR_NARROW_TRANS(NAME, name)                                 \
static bool trans_##NAME(DisasContext *s, arg_rri_esz *a)               \
{                                                                       \
    static gen_helper_gvec_2 * const fns[3] = {                         \
        gen_helper_sve2_##name##_h,                                     \
        gen_helper_sve2_##name##_s,                                     \
        gen_helper_sve2_##name##_d,                                     \
    };                                                                  \
                                                                        \
    return do_shr_narrow(s, a, fns);                                    \
}

DO_SHR_NARROW_TRANS(SQSHRUNB, sqshrunb)
DO_SHR_NARROW_TRANS(SQSHRUNT, sqshrunt)
DO_SHR_NARROW_TRANS(SQRSHRUNB, sqrshrunb)
DO_SHR_NARROW_TRANS(SQRSHRUNT, sqrshrunt)
DO_SHR_NARROW_TRANS(SHRNB, shrnb)
DO_SHR_NARROW_TRANS(SHRNT, shrnt)
DO_SHR_NARROW_TRANS(RSHRNB, rshrnb)
DO_SHR_NARROW_TRANS(RSHRNT, rshrnt)
DO_SHR_NARROW_TRANS(SQSHRNB, sqshrnb)
DO_SHR_NARROW_TRANS(SQSHRNT, sqshrnt)
DO_SHR_NARROW_TRANS(SQRSHRNB, sqrshrnb)
DO_SHR_NARROW_TRANS(SQRSHRNT, sqrshrnt)
DO_SHR_NARROW_TRANS(UQSHRNB, uqshrnb)
DO_SHR_NARROW_TRANS(UQSHRNT, uqshrnt)
DO_SHR_NARROW_TRANS(UQRSHRNB, uqrshrnb)
DO_SHR_NARROW_TRANS(UQRSHRNT, uqrshrnt)

#undef DO_SHR_NARROW_TRANS

static bool do_sra_zzi(DisasContext *s, arg_rri_esz *a,
                       gen_helper_gvec_2 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || a->esz < 0 || a->esz > 3) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vsz, vsz, a->imm, fns[a->esz]);
    }
    return true;
}

#define DO_SRA_ZZI_TRANS(NAME, name)                                    \
static bool trans_##NAME(DisasContext *s, arg_rri_esz *a)               \
{                                                                       \
    static gen_helper_gvec_2 * const fns[4] = {                         \
        gen_helper_sve2_##name##_b,                                     \
        gen_helper_sve2_##name##_h,                                     \
        gen_helper_sve2_##name##_s,                                     \
        gen_helper_sve2_##name##_d,                                     \
    };                                                                  \
                                                                        \
    return do_sra_zzi(s, a, fns);                                      \
}

DO_SRA_ZZI_TRANS(SSRA, ssra)
DO_SRA_ZZI_TRANS(USRA, usra)
DO_SRA_ZZI_TRANS(SRSRA, srsra)
DO_SRA_ZZI_TRANS(URSRA, ursra)

#undef DO_SRA_ZZI_TRANS

static bool do_shift_insert_zzi(DisasContext *s, arg_rri_esz *a,
                                gen_helper_gvec_2 * const fns[4],
                                bool insert_left)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || a->esz < 0 || a->esz > 3) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned bits = 8u << a->esz;
        unsigned vsz = vec_full_reg_size(s);
        uint32_t rd_ofs = vec_full_reg_offset(s, a->rd);
        uint32_t rn_ofs = vec_full_reg_offset(s, a->rn);

        if (insert_left && a->imm == 0) {
            tcg_gen_gvec_mov(tcg_ctx, a->esz, rd_ofs, rn_ofs, vsz, vsz);
        } else if (!insert_left && a->imm == bits) {
            return true;
        } else {
            tcg_gen_gvec_2_ool(tcg_ctx, rd_ofs, rn_ofs, vsz, vsz,
                               a->imm, fns[a->esz]);
        }
    }
    return true;
}

#define DO_SHIFT_INSERT_TRANS(NAME, name, LEFT)                         \
static bool trans_##NAME(DisasContext *s, arg_rri_esz *a)               \
{                                                                       \
    static gen_helper_gvec_2 * const fns[4] = {                         \
        gen_helper_sve2_##name##_b,                                     \
        gen_helper_sve2_##name##_h,                                     \
        gen_helper_sve2_##name##_s,                                     \
        gen_helper_sve2_##name##_d,                                     \
    };                                                                  \
                                                                        \
    return do_shift_insert_zzi(s, a, fns, LEFT);                       \
}

DO_SHIFT_INSERT_TRANS(SRI, sri, false)
DO_SHIFT_INSERT_TRANS(SLI, sli, true)

#undef DO_SHIFT_INSERT_TRANS

static bool do_eoril(DisasContext *s, arg_rrr_esz *a, int data)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_eoril_b,
        gen_helper_sve2_eoril_h,
        gen_helper_sve2_eoril_s,
        gen_helper_sve2_eoril_d,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, data, fns[a->esz]);
    }
    return true;
}

static bool trans_EORBT(DisasContext *s, arg_rrr_esz *a)
{
    return do_eoril(s, a, 2);
}

static bool trans_EORTB(DisasContext *s, arg_rrr_esz *a)
{
    return do_eoril(s, a, 1);
}

static bool do_bitperm(DisasContext *s, arg_rrr_esz *a,
                       gen_helper_gvec_3 * const fns[4])
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2_bitperm, s)) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_BEXT(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_bext_b,
        gen_helper_sve2_bext_h,
        gen_helper_sve2_bext_s,
        gen_helper_sve2_bext_d,
    };

    return do_bitperm(s, a, fns);
}

static bool trans_BDEP(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_bdep_b,
        gen_helper_sve2_bdep_h,
        gen_helper_sve2_bdep_s,
        gen_helper_sve2_bdep_d,
    };

    return do_bitperm(s, a, fns);
}

static bool trans_BGRP(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_bgrp_b,
        gen_helper_sve2_bgrp_h,
        gen_helper_sve2_bgrp_s,
        gen_helper_sve2_bgrp_d,
    };

    return do_bitperm(s, a, fns);
}

static bool do_cadd(DisasContext *s, arg_rrr_esz *a,
                    gen_helper_gvec_3 * const fns[4], int data)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, data, fns[a->esz]);
    }
    return true;
}

static bool trans_CADD_rot90(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_cadd_b,
        gen_helper_sve2_cadd_h,
        gen_helper_sve2_cadd_s,
        gen_helper_sve2_cadd_d,
    };

    return do_cadd(s, a, fns, 0);
}

static bool trans_CADD_rot270(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_cadd_b,
        gen_helper_sve2_cadd_h,
        gen_helper_sve2_cadd_s,
        gen_helper_sve2_cadd_d,
    };

    return do_cadd(s, a, fns, 1);
}

static bool trans_SQCADD_rot90(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_sqcadd_b,
        gen_helper_sve2_sqcadd_h,
        gen_helper_sve2_sqcadd_s,
        gen_helper_sve2_sqcadd_d,
    };

    return do_cadd(s, a, fns, 0);
}

static bool trans_SQCADD_rot270(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_sqcadd_b,
        gen_helper_sve2_sqcadd_h,
        gen_helper_sve2_sqcadd_s,
        gen_helper_sve2_sqcadd_d,
    };

    return do_cadd(s, a, fns, 1);
}

static bool do_adcl(DisasContext *s, arg_rprrr_esz *a, int sel)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_4 * const fns[2] = {
        gen_helper_sve2_adcl_s,
        gen_helper_sve2_adcl_d,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        int data = (a->esz & 2) | sel;

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, data, fns[a->esz & 1]);
    }
    return true;
}

static bool trans_ADCLB(DisasContext *s, arg_rprrr_esz *a)
{
    return do_adcl(s, a, 0);
}

static bool trans_ADCLT(DisasContext *s, arg_rprrr_esz *a)
{
    return do_adcl(s, a, 1);
}

/*
 *** SVE Integer Arithmetic - Unpredicated Group
 */

static bool trans_ADD_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_add, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_SUB_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_sub, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_SQADD_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_ssadd, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_SQSUB_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_sssub, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_UQADD_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_usadd, a->esz, a->rd, a->rn, a->rm);
}

static bool trans_UQSUB_zzz(DisasContext *s, arg_rrr_esz *a)
{
    return do_vector3_z(s, tcg_gen_gvec_ussub, a->esz, a->rd, a->rn, a->rm);
}

/*
 *** SVE Integer Arithmetic - Binary Predicated Group
 */

static bool do_zpzz_ool(DisasContext *s, arg_rprr_esz *a, gen_helper_gvec_4 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, 0, fn);
    }
    return true;
}

/* Select active elememnts from Zn and inactive elements from Zm,
 * storing the result in Zd.
 */
static void do_sel_z(DisasContext *s, int rd, int rn, int rm, int pg, int esz)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_4 * const fns[4] = {
        gen_helper_sve_sel_zpzz_b, gen_helper_sve_sel_zpzz_h,
        gen_helper_sve_sel_zpzz_s, gen_helper_sve_sel_zpzz_d
    };
    unsigned vsz = vec_full_reg_size(s);
    tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, rd),
                       vec_full_reg_offset(s, rn),
                       vec_full_reg_offset(s, rm),
                       pred_full_reg_offset(s, pg),
                       vsz, vsz, 0, fns[esz]);
}

#define DO_ZPZZ(NAME, name) \
static bool trans_##NAME##_zpzz(DisasContext *s, arg_rprr_esz *a)         \
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

static bool trans_SADALP_zpzz(DisasContext *s, arg_rprr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL,
        gen_helper_sve2_sadalp_zpzz_h,
        gen_helper_sve2_sadalp_zpzz_s,
        gen_helper_sve2_sadalp_zpzz_d,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpzz_ool(s, a, fns[a->esz]);
}

static bool trans_UADALP_zpzz(DisasContext *s, arg_rprr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL,
        gen_helper_sve2_uadalp_zpzz_h,
        gen_helper_sve2_uadalp_zpzz_s,
        gen_helper_sve2_uadalp_zpzz_d,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpzz_ool(s, a, fns[a->esz]);
}

#define DO_ZPZZ_SVE2(NAME, name)                                        \
static bool trans_##NAME(DisasContext *s, arg_rprr_esz *a)              \
{                                                                       \
    static gen_helper_gvec_4 * const fns[4] = {                         \
        gen_helper_sve2_##name##_zpzz_b,                                \
        gen_helper_sve2_##name##_zpzz_h,                                \
        gen_helper_sve2_##name##_zpzz_s,                                \
        gen_helper_sve2_##name##_zpzz_d,                                \
    };                                                                  \
                                                                        \
    if (!dc_isar_feature(aa64_sve2, s)) {                               \
        return false;                                                   \
    }                                                                   \
    return do_zpzz_ool(s, a, fns[a->esz]);                              \
}

DO_ZPZZ_SVE2(SHADD, shadd)
DO_ZPZZ_SVE2(UHADD, uhadd)
DO_ZPZZ_SVE2(SHSUB, shsub)
DO_ZPZZ_SVE2(UHSUB, uhsub)
DO_ZPZZ_SVE2(SRHADD, srhadd)
DO_ZPZZ_SVE2(URHADD, urhadd)
DO_ZPZZ_SVE2(ADDP, addp)
DO_ZPZZ_SVE2(SMAXP, smaxp)
DO_ZPZZ_SVE2(UMAXP, umaxp)
DO_ZPZZ_SVE2(SMINP, sminp)
DO_ZPZZ_SVE2(UMINP, uminp)
DO_ZPZZ_SVE2(SRSHL, srshl)
DO_ZPZZ_SVE2(URSHL, urshl)
DO_ZPZZ_SVE2(SQSHL, sqshl)
DO_ZPZZ_SVE2(UQSHL, uqshl)
DO_ZPZZ_SVE2(SQRSHL, sqrshl)
DO_ZPZZ_SVE2(UQRSHL, uqrshl)
DO_ZPZZ_SVE2(SQADD_zpzz, sqadd)
DO_ZPZZ_SVE2(UQADD_zpzz, uqadd)
DO_ZPZZ_SVE2(SQSUB_zpzz, sqsub)
DO_ZPZZ_SVE2(UQSUB_zpzz, uqsub)
DO_ZPZZ_SVE2(SUQADD, suqadd)
DO_ZPZZ_SVE2(USQADD, usqadd)

DO_ZPZZ(MUL, mul)
DO_ZPZZ(SMULH, smulh)
DO_ZPZZ(UMULH, umulh)

DO_ZPZZ(ASR, asr)
DO_ZPZZ(LSR, lsr)
DO_ZPZZ(LSL, lsl)

static bool trans_SDIV_zpzz(DisasContext *s, arg_rprr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL, NULL, gen_helper_sve_sdiv_zpzz_s, gen_helper_sve_sdiv_zpzz_d
    };
    return do_zpzz_ool(s, a, fns[a->esz]);
}

static bool trans_UDIV_zpzz(DisasContext *s, arg_rprr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL, NULL, gen_helper_sve_udiv_zpzz_s, gen_helper_sve_udiv_zpzz_d
    };
    return do_zpzz_ool(s, a, fns[a->esz]);
}

static bool trans_SEL_zpzz(DisasContext *s, arg_rprr_esz *a)
{
    if (sve_access_check(s)) {
        do_sel_z(s, a->rd, a->rn, a->rm, a->pg, a->esz);
    }
    return true;
}

#undef DO_ZPZZ
#undef DO_ZPZZ_SVE2

/*
 *** SVE Integer Arithmetic - Unary Predicated Group
 */

static bool do_zpz_ool(DisasContext *s, arg_rpr_esz *a, gen_helper_gvec_3 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, 0, fn);
    }
    return true;
}

#define DO_ZPZ(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rpr_esz *a)           \
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

static bool trans_SQABS(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_sqabs_b,
        gen_helper_sve2_sqabs_h,
        gen_helper_sve2_sqabs_s,
        gen_helper_sve2_sqabs_d,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_SQNEG(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_sqneg_b,
        gen_helper_sve2_sqneg_h,
        gen_helper_sve2_sqneg_s,
        gen_helper_sve2_sqneg_d,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_URECPE(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_ool(s, a, a->esz == 2 ? gen_helper_sve2_urecpe_s : NULL);
}

static bool trans_URSQRTE(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_ool(s, a, a->esz == 2 ? gen_helper_sve2_ursqrte_s : NULL);
}

static bool trans_FABS(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_fabs_h,
        gen_helper_sve_fabs_s,
        gen_helper_sve_fabs_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_FNEG(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_fneg_h,
        gen_helper_sve_fneg_s,
        gen_helper_sve_fneg_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_SXTB(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_sxtb_h,
        gen_helper_sve_sxtb_s,
        gen_helper_sve_sxtb_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_UXTB(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_uxtb_h,
        gen_helper_sve_uxtb_s,
        gen_helper_sve_uxtb_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_SXTH(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL, NULL,
        gen_helper_sve_sxth_s,
        gen_helper_sve_sxth_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_UXTH(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL, NULL,
        gen_helper_sve_uxth_s,
        gen_helper_sve_uxth_d
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_SXTW(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ool(s, a, a->esz == 3 ? gen_helper_sve_sxtw_d : NULL);
}

static bool trans_UXTW(DisasContext *s, arg_rpr_esz *a)
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
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
static bool trans_##NAME(DisasContext *s, arg_rpr_esz *a)                \
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

static bool trans_SADDV(DisasContext *s, arg_rpr_esz *a)
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_2 * const fns[4] = {
        gen_helper_sve_clr_b, gen_helper_sve_clr_h,
        gen_helper_sve_clr_s, gen_helper_sve_clr_d,
    };
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, rd),
                           pred_full_reg_offset(s, pg),
                           vsz, vsz, 0, fns[esz]);
    }
    return true;
}

/* Copy Zn into Zd, storing zeros into inactive elements.  */
static void do_movz_zpz(DisasContext *s, int rd, int rn, int pg, int esz)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_movz_b, gen_helper_sve_movz_h,
        gen_helper_sve_movz_s, gen_helper_sve_movz_d,
    };
    unsigned vsz = vec_full_reg_size(s);
    tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, rd),
                       vec_full_reg_offset(s, rn),
                       pred_full_reg_offset(s, pg),
                       vsz, vsz, 0, fns[esz]);
}

static bool do_zpzi_ool(DisasContext *s, arg_rpri_esz *a,
                        gen_helper_gvec_3 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, a->imm, fn);
    }
    return true;
}

static bool trans_ASR_zpzi(DisasContext *s, arg_rpri_esz *a)
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

static bool trans_LSR_zpzi(DisasContext *s, arg_rpri_esz *a)
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

static bool trans_LSL_zpzi(DisasContext *s, arg_rpri_esz *a)
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

static bool trans_ASRD(DisasContext *s, arg_rpri_esz *a)
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
static bool trans_##NAME##_zpzw(DisasContext *s, arg_rprr_esz *a)         \
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz < 0) {
        /* Invalid tsz encoding -- see tszimm_esz. */
        return false;
    }
    if (sve_access_check(s)) {
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

static bool trans_ASR_zzi(DisasContext *s, arg_rri_esz *a)
{
    return do_shift_imm(s, a, true, tcg_gen_gvec_sari);
}

static bool trans_LSR_zzi(DisasContext *s, arg_rri_esz *a)
{
    return do_shift_imm(s, a, false, tcg_gen_gvec_shri);
}

static bool trans_LSL_zzi(DisasContext *s, arg_rri_esz *a)
{
    return do_shift_imm(s, a, false, tcg_gen_gvec_shli);
}

static bool do_zzw_ool(DisasContext *s, arg_rrr_esz *a, gen_helper_gvec_3 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fn);
    }
    return true;
}

#define DO_ZZW(NAME, name) \
static bool trans_##NAME##_zzw(DisasContext *s, arg_rrr_esz *a)           \
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
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
static bool trans_##NAME(DisasContext *s, arg_rprrr_esz *a)          \
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

static bool trans_INDEX_ii(DisasContext *s, arg_INDEX_ii *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 start = tcg_const_i64(tcg_ctx, a->imm1);
        TCGv_i64 incr = tcg_const_i64(tcg_ctx, a->imm2);
        do_index(s, a->esz, a->rd, start, incr);
        tcg_temp_free_i64(tcg_ctx, start);
        tcg_temp_free_i64(tcg_ctx, incr);
    }
    return true;
}

static bool trans_INDEX_ir(DisasContext *s, arg_INDEX_ir *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 start = tcg_const_i64(tcg_ctx, a->imm);
        TCGv_i64 incr = cpu_reg(s, a->rm);
        do_index(s, a->esz, a->rd, start, incr);
        tcg_temp_free_i64(tcg_ctx, start);
    }
    return true;
}

static bool trans_INDEX_ri(DisasContext *s, arg_INDEX_ri *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 start = cpu_reg(s, a->rn);
        TCGv_i64 incr = tcg_const_i64(tcg_ctx, a->imm);
        do_index(s, a->esz, a->rd, start, incr);
        tcg_temp_free_i64(tcg_ctx, incr);
    }
    return true;
}

static bool trans_INDEX_rr(DisasContext *s, arg_INDEX_rr *a)
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

static bool trans_ADDVL(DisasContext *s, arg_ADDVL *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 rd = cpu_reg_sp(s, a->rd);
        TCGv_i64 rn = cpu_reg_sp(s, a->rn);
        tcg_gen_addi_i64(tcg_ctx, rd, rn, a->imm * vec_full_reg_size(s));
    }
    return true;
}

static bool trans_ADDSVL(DisasContext *s, arg_ADDSVL *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (sme_enabled_check(s)) {
        TCGv_i64 rd = cpu_reg_sp(s, a->rd);
        TCGv_i64 rn = cpu_reg_sp(s, a->rn);

        tcg_gen_addi_i64(tcg_ctx, rd, rn,
                         a->imm * streaming_vec_reg_size(s));
    }
    return true;
}

static bool trans_ADDPL(DisasContext *s, arg_ADDPL *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 rd = cpu_reg_sp(s, a->rd);
        TCGv_i64 rn = cpu_reg_sp(s, a->rn);
        tcg_gen_addi_i64(tcg_ctx, rd, rn, a->imm * pred_full_reg_size(s));
    }
    return true;
}

static bool trans_ADDSPL(DisasContext *s, arg_ADDSPL *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (sme_enabled_check(s)) {
        TCGv_i64 rd = cpu_reg_sp(s, a->rd);
        TCGv_i64 rn = cpu_reg_sp(s, a->rn);

        tcg_gen_addi_i64(tcg_ctx, rd, rn,
                         a->imm * streaming_pred_reg_size(s));
    }
    return true;
}

static bool trans_RDVL(DisasContext *s, arg_RDVL *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 reg = cpu_reg(s, a->rd);
        tcg_gen_movi_i64(tcg_ctx, reg, a->imm * vec_full_reg_size(s));
    }
    return true;
}

static bool trans_RDSVL(DisasContext *s, arg_RDSVL *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (sme_enabled_check(s)) {
        TCGv_i64 reg = cpu_reg(s, a->rd);

        tcg_gen_movi_i64(tcg_ctx, reg,
                         a->imm * streaming_vec_reg_size(s));
    }
    return true;
}

/*
 *** SVE Compute Vector Address Group
 */

static bool do_adr(DisasContext *s, arg_rrri *a, gen_helper_gvec_3 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, a->imm, fn);
    }
    return true;
}

static bool trans_ADR_p32(DisasContext *s, arg_rrri *a)
{
    return do_adr(s, a, gen_helper_sve_adr_p32);
}

static bool trans_ADR_p64(DisasContext *s, arg_rrri *a)
{
    return do_adr(s, a, gen_helper_sve_adr_p64);
}

static bool trans_ADR_s32(DisasContext *s, arg_rrri *a)
{
    return do_adr(s, a, gen_helper_sve_adr_s32);
}

static bool trans_ADR_u32(DisasContext *s, arg_rrri *a)
{
    return do_adr(s, a, gen_helper_sve_adr_u32);
}

/*
 *** SVE Integer Misc - Unpredicated Group
 */

static bool trans_FEXPA(DisasContext *s, arg_rr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_2 * const fns[4] = {
        NULL,
        gen_helper_sve_fexpa_h,
        gen_helper_sve_fexpa_s,
        gen_helper_sve_fexpa_d,
    };
    if (a->esz == 0) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_FTSSEL(DisasContext *s, arg_rrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_ftssel_h,
        gen_helper_sve_ftssel_s,
        gen_helper_sve_ftssel_d,
    };
    if (a->esz == 0) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

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

        do_predtest1(tcg_ctx, pd, pg);

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

static void gen_and_pg_i64(TCGContext *tcg_ctx, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_and_i64(tcg_ctx, pd, pn, pm);
    tcg_gen_and_i64(tcg_ctx, pd, pd, pg);
}

static void gen_and_pg_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_and_vec(tcg_ctx, vece, pd, pn, pm);
    tcg_gen_and_vec(tcg_ctx, vece, pd, pd, pg);
}

static bool trans_AND_pppp(DisasContext *s, arg_rprr_s *a)
{
    static const GVecGen4 op = {
        .fni8 = gen_and_pg_i64,
        .fniv = gen_and_pg_vec,
        .fno = gen_helper_sve_and_pppp,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
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

static void gen_bic_pg_i64(TCGContext *tcg_ctx, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_andc_i64(tcg_ctx, pd, pn, pm);
    tcg_gen_and_i64(tcg_ctx, pd, pd, pg);
}

static void gen_bic_pg_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_andc_vec(tcg_ctx, vece, pd, pn, pm);
    tcg_gen_and_vec(tcg_ctx, vece, pd, pd, pg);
}

static bool trans_BIC_pppp(DisasContext *s, arg_rprr_s *a)
{
    static const GVecGen4 op = {
        .fni8 = gen_bic_pg_i64,
        .fniv = gen_bic_pg_vec,
        .fno = gen_helper_sve_bic_pppp,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else if (a->pg == a->rn) {
        return do_vector3_p(s, tcg_gen_gvec_andc, 0, a->rd, a->rn, a->rm);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_eor_pg_i64(TCGContext *tcg_ctx, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_xor_i64(tcg_ctx, pd, pn, pm);
    tcg_gen_and_i64(tcg_ctx, pd, pd, pg);
}

static void gen_eor_pg_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_xor_vec(tcg_ctx, vece, pd, pn, pm);
    tcg_gen_and_vec(tcg_ctx, vece, pd, pd, pg);
}

static bool trans_EOR_pppp(DisasContext *s, arg_rprr_s *a)
{
    static const GVecGen4 op = {
        .fni8 = gen_eor_pg_i64,
        .fniv = gen_eor_pg_vec,
        .fno = gen_helper_sve_eor_pppp,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_sel_pg_i64(TCGContext *tcg_ctx, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_and_i64(tcg_ctx, pn, pn, pg);
    tcg_gen_andc_i64(tcg_ctx, pm, pm, pg);
    tcg_gen_or_i64(tcg_ctx, pd, pn, pm);
}

static void gen_sel_pg_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_and_vec(tcg_ctx, vece, pn, pn, pg);
    tcg_gen_andc_vec(tcg_ctx, vece, pm, pm, pg);
    tcg_gen_or_vec(tcg_ctx, vece, pd, pn, pm);
}

static bool trans_SEL_pppp(DisasContext *s, arg_rprr_s *a)
{
    static const GVecGen4 op = {
        .fni8 = gen_sel_pg_i64,
        .fniv = gen_sel_pg_vec,
        .fno = gen_helper_sve_sel_pppp,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return false;
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_orr_pg_i64(TCGContext *tcg_ctx, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_or_i64(tcg_ctx, pd, pn, pm);
    tcg_gen_and_i64(tcg_ctx, pd, pd, pg);
}

static void gen_orr_pg_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_or_vec(tcg_ctx, vece, pd, pn, pm);
    tcg_gen_and_vec(tcg_ctx, vece, pd, pd, pg);
}

static bool trans_ORR_pppp(DisasContext *s, arg_rprr_s *a)
{
    static const GVecGen4 op = {
        .fni8 = gen_orr_pg_i64,
        .fniv = gen_orr_pg_vec,
        .fno = gen_helper_sve_orr_pppp,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else if (a->pg == a->rn && a->rn == a->rm) {
        return do_mov_p(s, a->rd, a->rn);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_orn_pg_i64(TCGContext *tcg_ctx, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_orc_i64(tcg_ctx, pd, pn, pm);
    tcg_gen_and_i64(tcg_ctx, pd, pd, pg);
}

static void gen_orn_pg_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_orc_vec(tcg_ctx, vece, pd, pn, pm);
    tcg_gen_and_vec(tcg_ctx, vece, pd, pd, pg);
}

static bool trans_ORN_pppp(DisasContext *s, arg_rprr_s *a)
{
    static const GVecGen4 op = {
        .fni8 = gen_orn_pg_i64,
        .fniv = gen_orn_pg_vec,
        .fno = gen_helper_sve_orn_pppp,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_nor_pg_i64(TCGContext *tcg_ctx, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_or_i64(tcg_ctx, pd, pn, pm);
    tcg_gen_andc_i64(tcg_ctx, pd, pg, pd);
}

static void gen_nor_pg_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_or_vec(tcg_ctx, vece, pd, pn, pm);
    tcg_gen_andc_vec(tcg_ctx, vece, pd, pg, pd);
}

static bool trans_NOR_pppp(DisasContext *s, arg_rprr_s *a)
{
    static const GVecGen4 op = {
        .fni8 = gen_nor_pg_i64,
        .fniv = gen_nor_pg_vec,
        .fno = gen_helper_sve_nor_pppp,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };
    if (a->s) {
        return do_pppp_flags(s, a, &op);
    } else {
        return do_vecop4_p(s, &op, a->rd, a->rn, a->rm, a->pg);
    }
}

static void gen_nand_pg_i64(TCGContext *tcg_ctx, TCGv_i64 pd, TCGv_i64 pn, TCGv_i64 pm, TCGv_i64 pg)
{
    tcg_gen_and_i64(tcg_ctx, pd, pn, pm);
    tcg_gen_andc_i64(tcg_ctx, pd, pg, pd);
}

static void gen_nand_pg_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec pd, TCGv_vec pn,
                           TCGv_vec pm, TCGv_vec pg)
{
    tcg_gen_and_vec(tcg_ctx, vece, pd, pn, pm);
    tcg_gen_andc_vec(tcg_ctx, vece, pd, pg, pd);
}

static bool trans_NAND_pppp(DisasContext *s, arg_rprr_s *a)
{
    static const GVecGen4 op = {
        .fni8 = gen_nand_pg_i64,
        .fniv = gen_nand_pg_vec,
        .fno = gen_helper_sve_nand_pppp,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
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

static bool trans_PTEST(DisasContext *s, arg_PTEST *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        int nofs = pred_full_reg_offset(s, a->rn);
        int gofs = pred_full_reg_offset(s, a->pg);
        int words = DIV_ROUND_UP(pred_full_reg_size(s), 8);

        if (words == 1) {
            TCGv_i64 pn = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 pg = tcg_temp_new_i64(tcg_ctx);

            tcg_gen_ld_i64(tcg_ctx, pn, tcg_ctx->cpu_env, nofs);
            tcg_gen_ld_i64(tcg_ctx, pg, tcg_ctx->cpu_env, gofs);
            do_predtest1(tcg_ctx, pn, pg);

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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

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
            lastword &= MAKE_64BIT_MASK(0, setsz % 64);
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
    }

    setsz /= 8;
    fullsz /= 8;

    tcg_gen_movi_i64(tcg_ctx, t, word);
    for (i = 0; i < QEMU_ALIGN_DOWN(setsz, 8); i += 8) {
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

static bool trans_PTRUE(DisasContext *s, arg_PTRUE *a)
{
    return do_predset(s, a->esz, a->rd, a->pat, a->s);
}

static bool trans_SETFFR(DisasContext *s, arg_SETFFR *a)
{
    /* Note pat == 31 is #all, to set all elements.  */
    s->is_nonstreaming = true;
    return do_predset(s, 0, FFR_PRED_NUM, 31, false);
}

static bool trans_PFALSE(DisasContext *s, arg_PFALSE *a)
{
    /* Note pat == 32 is #unimp, to set no elements.  */
    return do_predset(s, 0, a->rd, 32, false);
}

static bool trans_RDFFR_p(DisasContext *s, arg_RDFFR_p *a)
{
    /* The path through do_pppp_flags is complicated enough to want to avoid
     * duplication.  Frob the arguments into the form of a predicated AND.
     */
    arg_rprr_s alt_a = {
        .rd = a->rd, .pg = a->pg, .s = a->s,
        .rn = FFR_PRED_NUM, .rm = FFR_PRED_NUM,
    };
    s->is_nonstreaming = true;
    return trans_AND_pppp(s, &alt_a);
}

static bool trans_RDFFR(DisasContext *s, arg_RDFFR *a)
{
    s->is_nonstreaming = true;
    return do_mov_p(s, a->rd, FFR_PRED_NUM);
}

static bool trans_WRFFR(DisasContext *s, arg_WRFFR *a)
{
    s->is_nonstreaming = true;
    return do_mov_p(s, FFR_PRED_NUM, a->rn);
}

static bool do_pfirst_pnext(DisasContext *s, arg_rr_esz *a,
                            void (*gen_fn)(TCGContext *, TCGv_i32, TCGv_ptr,
                                           TCGv_ptr, TCGv_i32))
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

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

    do_pred_flags(tcg_ctx, t);
    tcg_temp_free_i32(tcg_ctx, t);
    return true;
}

static bool trans_PFIRST(DisasContext *s, arg_rr_esz *a)
{
    return do_pfirst_pnext(s, a, gen_helper_sve_pfirst);
}

static bool trans_PNEXT(DisasContext *s, arg_rr_esz *a)
{
    return do_pfirst_pnext(s, a, gen_helper_sve_pnext);
}

static bool trans_PSEL(DisasContext *s, arg_PSEL *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int vl = vec_full_reg_size(s);
    int pl = pred_gvec_reg_size(s);
    int elements = vl >> a->esz;
    TCGv_i64 tmp, didx, dbit;
    TCGv_ptr ptr;

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (!sve_access_check(s)) {
        return true;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    dbit = tcg_temp_new_i64(tcg_ctx);
    didx = tcg_temp_new_i64(tcg_ctx);
    ptr = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_i64(tcg_ctx, tmp, cpu_reg(s, a->rv), a->imm);
    if (is_power_of_2(elements)) {
        tcg_gen_andi_i64(tcg_ctx, tmp, tmp, elements - 1);
    } else {
        tcg_gen_remu_i64(tcg_ctx, tmp, tmp,
                         tcg_constant_i64(tcg_ctx, elements));
    }

    tcg_gen_shli_i64(tcg_ctx, tmp, tmp, a->esz);
    tcg_gen_andi_i64(tcg_ctx, dbit, tmp, 7);
    tcg_gen_shri_i64(tcg_ctx, didx, tmp, 3);
#ifdef HOST_WORDS_BIGENDIAN
    tcg_gen_xori_i64(tcg_ctx, didx, didx, 7);
#endif

    tcg_gen_trunc_i64_ptr(tcg_ctx, ptr, didx);
    tcg_gen_add_ptr(tcg_ctx, ptr, ptr, tcg_ctx->cpu_env);
    tcg_gen_ld8u_i64(tcg_ctx, tmp, ptr, pred_full_reg_offset(s, a->pm));

    tcg_gen_shr_i64(tcg_ctx, tmp, tmp, dbit);
    tcg_gen_andi_i64(tcg_ctx, tmp, tmp, 1);
    tcg_gen_neg_i64(tcg_ctx, tmp, tmp);

    tcg_gen_gvec_ands(tcg_ctx, MO_64, pred_full_reg_offset(s, a->pd),
                      pred_full_reg_offset(s, a->pn), tmp, pl, pl);

    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, dbit);
    tcg_temp_free_i64(tcg_ctx, didx);
    tcg_temp_free_ptr(tcg_ctx, ptr);
    return true;
}

/*
 *** SVE Element Count Group
 */

/* Perform an inline saturating addition of a 32-bit value within
 * a 64-bit register.  The second operand is known to be positive,
 * which halves the comparisions we must perform to bound the result.
 */
static void do_sat_addsub_32(TCGContext *tcg_ctx, TCGv_i64 reg, TCGv_i64 val, bool u, bool d)
{
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
static void do_sat_addsub_64(TCGContext *tcg_ctx, TCGv_i64 reg, TCGv_i64 val, bool u, bool d)
{
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
            tcg_gen_xor_i64(tcg_ctx, reg, reg, t1);
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

static bool trans_CNT_r(DisasContext *s, arg_CNT_r *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned fullsz = vec_full_reg_size(s);
        unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
        tcg_gen_movi_i64(tcg_ctx, cpu_reg(s, a->rd), numelem * a->imm);
    }
    return true;
}

static bool trans_INCDEC_r(DisasContext *s, arg_incdec_cnt *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned fullsz = vec_full_reg_size(s);
        unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
        int inc = numelem * a->imm * (a->d ? -1 : 1);
        TCGv_i64 reg = cpu_reg(s, a->rd);

        tcg_gen_addi_i64(tcg_ctx, reg, reg, inc);
    }
    return true;
}

static bool trans_SINCDEC_r_32(DisasContext *s, arg_incdec_cnt *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

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
        do_sat_addsub_32(tcg_ctx, reg, t, a->u, a->d);
        tcg_temp_free_i64(tcg_ctx, t);
    }
    return true;
}

static bool trans_SINCDEC_r_64(DisasContext *s, arg_incdec_cnt *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

    unsigned fullsz = vec_full_reg_size(s);
    unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
    int inc = numelem * a->imm;
    TCGv_i64 reg = cpu_reg(s, a->rd);

    if (inc != 0) {
        TCGv_i64 t = tcg_const_i64(tcg_ctx, inc);
        do_sat_addsub_64(tcg_ctx, reg, t, a->u, a->d);
        tcg_temp_free_i64(tcg_ctx, t);
    }
    return true;
}

static bool trans_INCDEC_v(DisasContext *s, arg_incdec2_cnt *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0) {
        return false;
    }

    unsigned fullsz = vec_full_reg_size(s);
    unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
    int inc = numelem * a->imm;

    if (inc != 0) {
        if (sve_access_check(s)) {
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

static bool trans_SINCDEC_v(DisasContext *s, arg_incdec2_cnt *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0) {
        return false;
    }

    unsigned fullsz = vec_full_reg_size(s);
    unsigned numelem = decode_pred_count(fullsz, a->pat, a->esz);
    int inc = numelem * a->imm;

    if (inc != 0) {
        if (sve_access_check(s)) {
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint64_t imm;
    if (!logic_imm_decode_wmask(&imm, extract32(a->dbm, 12, 1),
                                extract32(a->dbm, 0, 6),
                                extract32(a->dbm, 6, 6))) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        gvec_fn(tcg_ctx, MO_64, vec_full_reg_offset(s, a->rd),
                vec_full_reg_offset(s, a->rn), imm, vsz, vsz);
    }
    return true;
}

static bool trans_AND_zzi(DisasContext *s, arg_rr_dbm *a)
{
    return do_zz_dbm(s, a, tcg_gen_gvec_andi);
}

static bool trans_ORR_zzi(DisasContext *s, arg_rr_dbm *a)
{
    return do_zz_dbm(s, a, tcg_gen_gvec_ori);
}

static bool trans_EOR_zzi(DisasContext *s, arg_rr_dbm *a)
{
    return do_zz_dbm(s, a, tcg_gen_gvec_xori);
}

static bool trans_DUPM(DisasContext *s, arg_DUPM *a)
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    typedef void gen_cpy(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_ptr, TCGv_i64, TCGv_i32);
    static gen_cpy * const fns[4] = {
        gen_helper_sve_cpy_m_b, gen_helper_sve_cpy_m_h,
        gen_helper_sve_cpy_m_s, gen_helper_sve_cpy_m_d,
    };
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

static bool trans_FCPY(DisasContext *s, arg_FCPY *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        /* Decode the VFP immediate.  */
        uint64_t imm = vfp_expand_imm(a->esz, a->imm);
        TCGv_i64 t_imm = tcg_const_i64(tcg_ctx, imm);
        do_cpy_m(s, a->esz, a->rd, a->rn, a->pg, t_imm);
        tcg_temp_free_i64(tcg_ctx, t_imm);
    }
    return true;
}

static bool trans_CPY_m_i(DisasContext *s, arg_rpri_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0 && extract32(s->insn, 13, 1)) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGv_i64 t_imm = tcg_const_i64(tcg_ctx, a->imm);
        do_cpy_m(s, a->esz, a->rd, a->rn, a->pg, t_imm);
        tcg_temp_free_i64(tcg_ctx, t_imm);
    }
    return true;
}

static bool trans_CPY_z_i(DisasContext *s, arg_CPY_z_i *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_2i * const fns[4] = {
        gen_helper_sve_cpy_z_b, gen_helper_sve_cpy_z_h,
        gen_helper_sve_cpy_z_s, gen_helper_sve_cpy_z_d,
    };

    if (a->esz == 0 && extract32(s->insn, 13, 1)) {
        return false;
    }
    if (sve_access_check(s)) {
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

static bool do_ext(DisasContext *s, int rd, int rn, int rm, int imm)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

    unsigned vsz = vec_full_reg_size(s);
    unsigned n_ofs = imm >= vsz ? 0 : imm;
    unsigned n_siz = vsz - n_ofs;
    unsigned d = vec_full_reg_offset(s, rd);
    unsigned n = vec_full_reg_offset(s, rn);
    unsigned m = vec_full_reg_offset(s, rm);

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

static bool trans_EXT(DisasContext *s, arg_EXT *a)
{
    return do_ext(s, a->rd, a->rn, a->rm, a->imm);
}

static bool trans_EXT_sve2(DisasContext *s, arg_EXT_sve2 *a)
{
    return do_ext(s, a->rd, a->rn, (a->rn + 1) % 32, a->imm);
}

/*
 *** SVE Permute - Unpredicated Group
 */

static bool trans_DUP_s(DisasContext *s, arg_DUP_s *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_dup_i64(tcg_ctx, a->esz, vec_full_reg_offset(s, a->rd),
                             vsz, vsz, cpu_reg_sp(s, a->rn));
    }
    return true;
}

static bool trans_DUP_x(DisasContext *s, arg_DUP_x *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if ((a->imm & 0x1f) == 0) {
        return false;
    }
    if (sve_access_check(s)) {
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    typedef void gen_insr(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_i64, TCGv_i32);
    static gen_insr * const fns[4] = {
        gen_helper_sve_insr_b, gen_helper_sve_insr_h,
        gen_helper_sve_insr_s, gen_helper_sve_insr_d,
    };
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

static bool trans_INSR_f(DisasContext *s, arg_rrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_ld_i64(tcg_ctx, t, tcg_ctx->cpu_env, vec_reg_offset(s, a->rm, 0, MO_64));
        do_insr_i64(s, a, t);
        tcg_temp_free_i64(tcg_ctx, t);
    }
    return true;
}

static bool trans_INSR_r(DisasContext *s, arg_rrr_esz *a)
{
    if (sve_access_check(s)) {
        do_insr_i64(s, a, cpu_reg(s, a->rm));
    }
    return true;
}

static bool trans_REV_v(DisasContext *s, arg_rr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_2 * const fns[4] = {
        gen_helper_sve_rev_b, gen_helper_sve_rev_h,
        gen_helper_sve_rev_s, gen_helper_sve_rev_d
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_TBL(DisasContext *s, arg_rrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_tbl_b, gen_helper_sve_tbl_h,
        gen_helper_sve_tbl_s, gen_helper_sve_tbl_d
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_TBL_sve2(DisasContext *s, arg_rrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_4 * const fns[4] = {
        gen_helper_sve2_tbl_b, gen_helper_sve2_tbl_h,
        gen_helper_sve2_tbl_s, gen_helper_sve2_tbl_d
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, (a->rn + 1) % 32),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_TBX(DisasContext *s, arg_rrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve2_tbx_b, gen_helper_sve2_tbx_h,
        gen_helper_sve2_tbx_s, gen_helper_sve2_tbx_d
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, fns[a->esz]);
    }
    return true;
}

static bool trans_UNPK(DisasContext *s, arg_UNPK *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

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

static bool trans_ZIP1_p(DisasContext *s, arg_rrr_esz *a)
{
    return do_perm_pred3(s, a, 0, gen_helper_sve_zip_p);
}

static bool trans_ZIP2_p(DisasContext *s, arg_rrr_esz *a)
{
    return do_perm_pred3(s, a, 1, gen_helper_sve_zip_p);
}

static bool trans_UZP1_p(DisasContext *s, arg_rrr_esz *a)
{
    return do_perm_pred3(s, a, 0, gen_helper_sve_uzp_p);
}

static bool trans_UZP2_p(DisasContext *s, arg_rrr_esz *a)
{
    return do_perm_pred3(s, a, 1, gen_helper_sve_uzp_p);
}

static bool trans_TRN1_p(DisasContext *s, arg_rrr_esz *a)
{
    return do_perm_pred3(s, a, 0, gen_helper_sve_trn_p);
}

static bool trans_TRN2_p(DisasContext *s, arg_rrr_esz *a)
{
    return do_perm_pred3(s, a, 1, gen_helper_sve_trn_p);
}

static bool trans_REV_p(DisasContext *s, arg_rr_esz *a)
{
    return do_perm_pred2(s, a, 0, gen_helper_sve_rev_p);
}

static bool trans_PUNPKLO(DisasContext *s, arg_PUNPKLO *a)
{
    return do_perm_pred2(s, a, 0, gen_helper_sve_punpk_p);
}

static bool trans_PUNPKHI(DisasContext *s, arg_PUNPKHI *a)
{
    return do_perm_pred2(s, a, 1, gen_helper_sve_punpk_p);
}

/*
 *** SVE Permute - Interleaving Group
 */

static bool do_zip(DisasContext *s, arg_rrr_esz *a, bool high)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_zip_b, gen_helper_sve_zip_h,
        gen_helper_sve_zip_s, gen_helper_sve_zip_d,
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, high ? vsz / 2 : 0, fns[a->esz]);
    }
    return true;
}

static bool do_zzz_data_ool(DisasContext *s, arg_rrr_esz *a, int data,
                            gen_helper_gvec_3 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, data, fn);
    }
    return true;
}

static bool trans_ZIP1_z(DisasContext *s, arg_rrr_esz *a)
{
    return do_zip(s, a, false);
}

static bool trans_ZIP2_z(DisasContext *s, arg_rrr_esz *a)
{
    return do_zip(s, a, true);
}

static bool do_interleave_q(DisasContext *s, arg_rrr_esz *a,
                            gen_helper_gvec_3 *fn, int data)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_f64mm, s)) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        if (vsz < 32) {
            unallocated_encoding(s);
        } else {
            tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                               vec_full_reg_offset(s, a->rn),
                               vec_full_reg_offset(s, a->rm),
                               vsz, vsz, data, fn);
        }
    }
    return true;
}

static bool trans_ZIP1_q(DisasContext *s, arg_rrr_esz *a)
{
    return do_interleave_q(s, a, gen_helper_sve2_zip_q, 0);
}

static bool trans_ZIP2_q(DisasContext *s, arg_rrr_esz *a)
{
    return do_interleave_q(s, a, gen_helper_sve2_zip_q,
                           QEMU_ALIGN_DOWN(vec_full_reg_size(s), 32) / 2);
}

static gen_helper_gvec_3 * const uzp_fns[4] = {
    gen_helper_sve_uzp_b, gen_helper_sve_uzp_h,
    gen_helper_sve_uzp_s, gen_helper_sve_uzp_d,
};

static bool trans_UZP1_z(DisasContext *s, arg_rrr_esz *a)
{
    return do_zzz_data_ool(s, a, 0, uzp_fns[a->esz]);
}

static bool trans_UZP2_z(DisasContext *s, arg_rrr_esz *a)
{
    return do_zzz_data_ool(s, a, 1 << a->esz, uzp_fns[a->esz]);
}

static bool trans_UZP1_q(DisasContext *s, arg_rrr_esz *a)
{
    return do_interleave_q(s, a, gen_helper_sve2_uzp_q, 0);
}

static bool trans_UZP2_q(DisasContext *s, arg_rrr_esz *a)
{
    return do_interleave_q(s, a, gen_helper_sve2_uzp_q, 16);
}

static gen_helper_gvec_3 * const trn_fns[4] = {
    gen_helper_sve_trn_b, gen_helper_sve_trn_h,
    gen_helper_sve_trn_s, gen_helper_sve_trn_d,
};

static bool trans_TRN1_z(DisasContext *s, arg_rrr_esz *a)
{
    return do_zzz_data_ool(s, a, 0, trn_fns[a->esz]);
}

static bool trans_TRN2_z(DisasContext *s, arg_rrr_esz *a)
{
    return do_zzz_data_ool(s, a, 1 << a->esz, trn_fns[a->esz]);
}

static bool trans_TRN1_q(DisasContext *s, arg_rrr_esz *a)
{
    return do_interleave_q(s, a, gen_helper_sve2_trn_q, 0);
}

static bool trans_TRN2_q(DisasContext *s, arg_rrr_esz *a)
{
    return do_interleave_q(s, a, gen_helper_sve2_trn_q, 16);
}

/*
 *** SVE Permute Vector - Predicated Group
 */

static bool trans_COMPACT(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL, NULL, gen_helper_sve_compact_s, gen_helper_sve_compact_d
    };
    s->is_nonstreaming = true;
    return do_zpz_ool(s, a, fns[a->esz]);
}

/* Call the helper that computes the ARM LastActiveElement pseudocode
 * function, scaled by the element size.  This includes the not found
 * indication; e.g. not found for esz=3 is -8.
 */
static void find_last_active(DisasContext *s, TCGv_i32 ret, int esz, int pg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    /* Predicate sizes may be smaller and cannot use simd_desc.  We cannot
     * round up, as we do elsewhere, because we need the exact size.
     */
    TCGv_ptr t_p = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i32 t_desc;
    unsigned vsz = pred_full_reg_size(s);
    unsigned desc;

    desc = vsz - 2;
    desc = deposit32(desc, SIMD_DATA_SHIFT, 2, esz);

    tcg_gen_addi_ptr(tcg_ctx, t_p, tcg_ctx->cpu_env, pred_full_reg_offset(s, pg));
    t_desc = tcg_const_i32(tcg_ctx, desc);

    gen_helper_sve_last_active_element(tcg_ctx, ret, t_p, t_desc);

    tcg_temp_free_i32(tcg_ctx, t_desc);
    tcg_temp_free_ptr(tcg_ctx, t_p);
}

/* Increment LAST to the offset of the next element in the vector,
 * wrapping around to 0.
 */
static void incr_last_active(DisasContext *s, TCGv_i32 last, int esz)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);

    tcg_gen_addi_i32(tcg_ctx, last, last, 1 << esz);
    if (is_power_of_2(vsz)) {
        tcg_gen_andi_i32(tcg_ctx, last, last, vsz - 1);
    } else {
        TCGv_i32 max = tcg_const_i32(tcg_ctx, vsz);
        TCGv_i32 zero = tcg_const_i32(tcg_ctx, 0);
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_GEU, last, last, max, zero, last);
        tcg_temp_free_i32(tcg_ctx, max);
        tcg_temp_free_i32(tcg_ctx, zero);
    }
}

/* If LAST < 0, set LAST to the offset of the last element in the vector.  */
static void wrap_last_active(DisasContext *s, TCGv_i32 last, int esz)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);

    if (is_power_of_2(vsz)) {
        tcg_gen_andi_i32(tcg_ctx, last, last, vsz - 1);
    } else {
        TCGv_i32 max = tcg_const_i32(tcg_ctx, vsz - (1 << esz));
        TCGv_i32 zero = tcg_const_i32(tcg_ctx, 0);
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LT, last, last, zero, max, last);
        tcg_temp_free_i32(tcg_ctx, max);
        tcg_temp_free_i32(tcg_ctx, zero);
    }
}

/* Load an unsigned element of ESZ from BASE+OFS.  */
static TCGv_i64 load_esz(TCGContext *tcg_ctx, TCGv_ptr base, int ofs, int esz)
{
    TCGv_i64 r = tcg_temp_new_i64(tcg_ctx);

    switch (esz) {
    case 0:
        tcg_gen_ld8u_i64(tcg_ctx, r, base, ofs);
        break;
    case 1:
        tcg_gen_ld16u_i64(tcg_ctx, r, base, ofs);
        break;
    case 2:
        tcg_gen_ld32u_i64(tcg_ctx, r, base, ofs);
        break;
    case 3:
        tcg_gen_ld_i64(tcg_ctx, r, base, ofs);
        break;
    default:
        g_assert_not_reached();
    }
    return r;
}

/* Load an unsigned element of ESZ from RM[LAST].  */
static TCGv_i64 load_last_active(DisasContext *s, TCGv_i32 last,
                                 int rm, int esz)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr p = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i64 r;

    /* Convert offset into vector into offset into ENV.
     * The final adjustment for the vector register base
     * is added via constant offset to the load.
     */
#ifdef HOST_WORDS_BIGENDIAN
    /* Adjust for element ordering.  See vec_reg_offset.  */
    if (esz < 3) {
        tcg_gen_xori_i32(tcg_ctx, last, last, 8 - (1 << esz));
    }
#endif
    tcg_gen_ext_i32_ptr(tcg_ctx, p, last);
    tcg_gen_add_ptr(tcg_ctx, p, p, tcg_ctx->cpu_env);

    r = load_esz(tcg_ctx, p, vec_full_reg_offset(s, rm), esz);
    tcg_temp_free_ptr(tcg_ctx, p);

    return r;
}

/* Compute CLAST for a Zreg.  */
static bool do_clast_vector(DisasContext *s, arg_rprr_esz *a, bool before)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 last;
    TCGLabel *over;
    TCGv_i64 ele;
    unsigned vsz, esz = a->esz;

    if (!sve_access_check(s)) {
        return true;
    }

    last = tcg_temp_local_new_i32(tcg_ctx);
    over = gen_new_label(tcg_ctx);

    find_last_active(s, last, esz, a->pg);

    /* There is of course no movcond for a 2048-bit vector,
     * so we must branch over the actual store.
     */
    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_LT, last, 0, over);

    if (!before) {
        incr_last_active(s, last, esz);
    }

    ele = load_last_active(s, last, a->rm, esz);
    tcg_temp_free_i32(tcg_ctx, last);

    vsz = vec_full_reg_size(s);
    tcg_gen_gvec_dup_i64(tcg_ctx, esz, vec_full_reg_offset(s, a->rd), vsz, vsz, ele);
    tcg_temp_free_i64(tcg_ctx, ele);

    /* If this insn used MOVPRFX, we may need a second move.  */
    if (a->rd != a->rn) {
        TCGLabel *done = gen_new_label(tcg_ctx);
        tcg_gen_br(tcg_ctx, done);

        gen_set_label(tcg_ctx, over);
        do_mov_z(s, a->rd, a->rn);

        gen_set_label(tcg_ctx, done);
    } else {
        gen_set_label(tcg_ctx, over);
    }
    return true;
}

static bool trans_CLASTA_z(DisasContext *s, arg_rprr_esz *a)
{
    return do_clast_vector(s, a, false);
}

static bool trans_CLASTB_z(DisasContext *s, arg_rprr_esz *a)
{
    return do_clast_vector(s, a, true);
}

/* Compute CLAST for a scalar.  */
static void do_clast_scalar(DisasContext *s, int esz, int pg, int rm,
                            bool before, TCGv_i64 reg_val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 last = tcg_temp_new_i32(tcg_ctx);
    TCGv_i64 ele, cmp, zero;

    find_last_active(s, last, esz, pg);

    /* Extend the original value of last prior to incrementing.  */
    cmp = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_ext_i32_i64(tcg_ctx, cmp, last);

    if (!before) {
        incr_last_active(s, last, esz);
    }

    /* The conceit here is that while last < 0 indicates not found, after
     * adjusting for cpu_env->vfp.zregs[rm], it is still a valid address
     * from which we can load garbage.  We then discard the garbage with
     * a conditional move.
     */
    ele = load_last_active(s, last, rm, esz);
    tcg_temp_free_i32(tcg_ctx, last);

    zero = tcg_const_i64(tcg_ctx, 0);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_GE, reg_val, cmp, zero, ele, reg_val);

    tcg_temp_free_i64(tcg_ctx, zero);
    tcg_temp_free_i64(tcg_ctx, cmp);
    tcg_temp_free_i64(tcg_ctx, ele);
}

/* Compute CLAST for a Vreg.  */
static bool do_clast_fp(DisasContext *s, arg_rpr_esz *a, bool before)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        int esz = a->esz;
        int ofs = vec_reg_offset(s, a->rd, 0, esz);
        TCGv_i64 reg = load_esz(tcg_ctx, tcg_ctx->cpu_env, ofs, esz);

        do_clast_scalar(s, esz, a->pg, a->rn, before, reg);
        write_fp_dreg(s, a->rd, reg);
        tcg_temp_free_i64(tcg_ctx, reg);
    }
    return true;
}

static bool trans_CLASTA_v(DisasContext *s, arg_rpr_esz *a)
{
    return do_clast_fp(s, a, false);
}

static bool trans_CLASTB_v(DisasContext *s, arg_rpr_esz *a)
{
    return do_clast_fp(s, a, true);
}

/* Compute CLAST for a Xreg.  */
static bool do_clast_general(DisasContext *s, arg_rpr_esz *a, bool before)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 reg;

    if (!sve_access_check(s)) {
        return true;
    }

    reg = cpu_reg(s, a->rd);
    switch (a->esz) {
    case 0:
        tcg_gen_ext8u_i64(tcg_ctx, reg, reg);
        break;
    case 1:
        tcg_gen_ext16u_i64(tcg_ctx, reg, reg);
        break;
    case 2:
        tcg_gen_ext32u_i64(tcg_ctx, reg, reg);
        break;
    case 3:
        break;
    default:
        g_assert_not_reached();
    }

    do_clast_scalar(s, a->esz, a->pg, a->rn, before, reg);
    return true;
}

static bool trans_CLASTA_r(DisasContext *s, arg_rpr_esz *a)
{
    return do_clast_general(s, a, false);
}

static bool trans_CLASTB_r(DisasContext *s, arg_rpr_esz *a)
{
    return do_clast_general(s, a, true);
}

/* Compute LAST for a scalar.  */
static TCGv_i64 do_last_scalar(DisasContext *s, int esz,
                               int pg, int rm, bool before)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 last = tcg_temp_new_i32(tcg_ctx);
    TCGv_i64 ret;

    find_last_active(s, last, esz, pg);
    if (before) {
        wrap_last_active(s, last, esz);
    } else {
        incr_last_active(s, last, esz);
    }

    ret = load_last_active(s, last, rm, esz);
    tcg_temp_free_i32(tcg_ctx, last);
    return ret;
}

/* Compute LAST for a Vreg.  */
static bool do_last_fp(DisasContext *s, arg_rpr_esz *a, bool before)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 val = do_last_scalar(s, a->esz, a->pg, a->rn, before);
        write_fp_dreg(s, a->rd, val);
        tcg_temp_free_i64(tcg_ctx, val);
    }
    return true;
}

static bool trans_LASTA_v(DisasContext *s, arg_rpr_esz *a)
{
    return do_last_fp(s, a, false);
}

static bool trans_LASTB_v(DisasContext *s, arg_rpr_esz *a)
{
    return do_last_fp(s, a, true);
}

/* Compute LAST for a Xreg.  */
static bool do_last_general(DisasContext *s, arg_rpr_esz *a, bool before)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 val = do_last_scalar(s, a->esz, a->pg, a->rn, before);
        tcg_gen_mov_i64(tcg_ctx, cpu_reg(s, a->rd), val);
        tcg_temp_free_i64(tcg_ctx, val);
    }
    return true;
}

static bool trans_LASTA_r(DisasContext *s, arg_rpr_esz *a)
{
    return do_last_general(s, a, false);
}

static bool trans_LASTB_r(DisasContext *s, arg_rpr_esz *a)
{
    return do_last_general(s, a, true);
}

static bool trans_CPY_m_r(DisasContext *s, arg_rpr_esz *a)
{
    if (sve_access_check(s)) {
        do_cpy_m(s, a->esz, a->rd, a->rd, a->pg, cpu_reg_sp(s, a->rn));
    }
    return true;
}

static bool trans_CPY_m_v(DisasContext *s, arg_rpr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        int ofs = vec_reg_offset(s, a->rn, 0, a->esz);
        TCGv_i64 t = load_esz(tcg_ctx, tcg_ctx->cpu_env, ofs, a->esz);
        do_cpy_m(s, a->esz, a->rd, a->rd, a->pg, t);
        tcg_temp_free_i64(tcg_ctx, t);
    }
    return true;
}

static bool trans_REVB(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        gen_helper_sve_revb_h,
        gen_helper_sve_revb_s,
        gen_helper_sve_revb_d,
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_REVH(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        NULL,
        NULL,
        gen_helper_sve_revh_s,
        gen_helper_sve_revh_d,
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_REVW(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ool(s, a, a->esz == 3 ? gen_helper_sve_revw_d : NULL);
}

static bool trans_RBIT(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3 * const fns[4] = {
        gen_helper_sve_rbit_b,
        gen_helper_sve_rbit_h,
        gen_helper_sve_rbit_s,
        gen_helper_sve_rbit_d,
    };
    return do_zpz_ool(s, a, fns[a->esz]);
}

static bool trans_SPLICE(DisasContext *s, arg_rprr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, a->esz, gen_helper_sve_splice);
    }
    return true;
}

static bool trans_SPLICE_sve2(DisasContext *s, arg_rpr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, (a->rn + 1) % 32),
                           pred_full_reg_offset(s, a->pg),
                           vsz, vsz, a->esz, gen_helper_sve_splice);
    }
    return true;
}

/*
 *** SVE Integer Compare - Vectors Group
 */

static bool do_ppzz_flags(DisasContext *s, arg_rprr_esz *a,
                          gen_helper_gvec_flags_4 *gen_fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr pd, zn, zm, pg;
    unsigned vsz;
    TCGv_i32 t;

    if (gen_fn == NULL) {
        return false;
    }
    if (!sve_access_check(s)) {
        return true;
    }

    vsz = vec_full_reg_size(s);
    t = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, 0));
    pd = tcg_temp_new_ptr(tcg_ctx);
    zn = tcg_temp_new_ptr(tcg_ctx);
    zm = tcg_temp_new_ptr(tcg_ctx);
    pg = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, pd, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rd));
    tcg_gen_addi_ptr(tcg_ctx, zn, tcg_ctx->cpu_env, vec_full_reg_offset(s, a->rn));
    tcg_gen_addi_ptr(tcg_ctx, zm, tcg_ctx->cpu_env, vec_full_reg_offset(s, a->rm));
    tcg_gen_addi_ptr(tcg_ctx, pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));

    gen_fn(tcg_ctx, t, pd, zn, zm, pg, t);

    tcg_temp_free_ptr(tcg_ctx, pd);
    tcg_temp_free_ptr(tcg_ctx, zn);
    tcg_temp_free_ptr(tcg_ctx, zm);
    tcg_temp_free_ptr(tcg_ctx, pg);

    do_pred_flags(tcg_ctx, t);

    tcg_temp_free_i32(tcg_ctx, t);
    return true;
}

#define DO_PPZZ(NAME, name) \
static bool trans_##NAME##_ppzz(DisasContext *s, arg_rprr_esz *a)         \
{                                                                         \
    static gen_helper_gvec_flags_4 * const fns[4] = {                     \
        gen_helper_sve_##name##_ppzz_b, gen_helper_sve_##name##_ppzz_h,   \
        gen_helper_sve_##name##_ppzz_s, gen_helper_sve_##name##_ppzz_d,   \
    };                                                                    \
    return do_ppzz_flags(s, a, fns[a->esz]);                              \
}

DO_PPZZ(CMPEQ, cmpeq)
DO_PPZZ(CMPNE, cmpne)
DO_PPZZ(CMPGT, cmpgt)
DO_PPZZ(CMPGE, cmpge)
DO_PPZZ(CMPHI, cmphi)
DO_PPZZ(CMPHS, cmphs)

#undef DO_PPZZ

#define DO_PPZW(NAME, name) \
static bool trans_##NAME##_ppzw(DisasContext *s, arg_rprr_esz *a)         \
{                                                                         \
    static gen_helper_gvec_flags_4 * const fns[4] = {                     \
        gen_helper_sve_##name##_ppzw_b, gen_helper_sve_##name##_ppzw_h,   \
        gen_helper_sve_##name##_ppzw_s, NULL                              \
    };                                                                    \
    return do_ppzz_flags(s, a, fns[a->esz]);                              \
}

DO_PPZW(CMPEQ, cmpeq)
DO_PPZW(CMPNE, cmpne)
DO_PPZW(CMPGT, cmpgt)
DO_PPZW(CMPGE, cmpge)
DO_PPZW(CMPHI, cmphi)
DO_PPZW(CMPHS, cmphs)
DO_PPZW(CMPLT, cmplt)
DO_PPZW(CMPLE, cmple)
DO_PPZW(CMPLO, cmplo)
DO_PPZW(CMPLS, cmpls)

#undef DO_PPZW

static bool trans_MATCH(DisasContext *s, arg_rprr_esz *a)
{
    static gen_helper_gvec_flags_4 * const fns[4] = {
        gen_helper_sve2_match_ppzz_b,
        gen_helper_sve2_match_ppzz_h,
        NULL,
        NULL,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    s->is_nonstreaming = true;
    return do_ppzz_flags(s, a, fns[a->esz]);
}

static bool trans_NMATCH(DisasContext *s, arg_rprr_esz *a)
{
    static gen_helper_gvec_flags_4 * const fns[4] = {
        gen_helper_sve2_nmatch_ppzz_b,
        gen_helper_sve2_nmatch_ppzz_h,
        NULL,
        NULL,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    s->is_nonstreaming = true;
    return do_ppzz_flags(s, a, fns[a->esz]);
}

static bool trans_HISTCNT(DisasContext *s, arg_rprr_esz *a)
{
    static gen_helper_gvec_4 * const fns[4] = {
        NULL,
        NULL,
        gen_helper_sve2_histcnt_s,
        gen_helper_sve2_histcnt_d,
    };

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    s->is_nonstreaming = true;
    return do_zpzz_ool(s, a, fns[a->esz]);
}

static bool trans_HISTSEG(DisasContext *s, arg_rrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s) || a->esz != 0) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, 0, gen_helper_sve2_histseg);
    }
    return true;
}

static bool trans_AESMC(DisasContext *s, arg_rri *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2_aes, s)) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rd),
                           vsz, vsz, a->imm, gen_helper_crypto_sve_aesmc);
    }
    return true;
}

static bool do_sve2_crypto_zzz(DisasContext *s, arg_rrr_esz *a,
                               gen_helper_gvec_3 *fn, int data, bool feature)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!feature || a->esz != 0) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vsz, vsz, data, fn);
    }
    return true;
}

static bool trans_AESE(DisasContext *s, arg_rrr_esz *a)
{
    return do_sve2_crypto_zzz(s, a, gen_helper_crypto_sve_aese, 0,
                              dc_isar_feature(aa64_sve2_aes, s));
}

static bool trans_AESD(DisasContext *s, arg_rrr_esz *a)
{
    return do_sve2_crypto_zzz(s, a, gen_helper_crypto_sve_aese, 1,
                              dc_isar_feature(aa64_sve2_aes, s));
}

static bool trans_SM4E(DisasContext *s, arg_rrr_esz *a)
{
    return do_sve2_crypto_zzz(s, a, gen_helper_crypto_sve_sm4e, 0,
                              dc_isar_feature(aa64_sve2_sm4, s));
}

static bool trans_SM4EKEY(DisasContext *s, arg_rrr_esz *a)
{
    return do_sve2_crypto_zzz(s, a, gen_helper_crypto_sve_sm4ekey, 0,
                              dc_isar_feature(aa64_sve2_sm4, s));
}

static bool trans_RAX1(DisasContext *s, arg_rrr_esz *a)
{
    return do_sve2_crypto_zzz(s, a, gen_helper_crypto_rax1, 0,
                              dc_isar_feature(aa64_sve2_sha3, s));
}

/*
 *** SVE Integer Compare - Immediate Groups
 */

static bool do_ppzi_flags(DisasContext *s, arg_rpri_esz *a,
                          gen_helper_gvec_flags_3 *gen_fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr pd, zn, pg;
    unsigned vsz;
    TCGv_i32 t;

    if (gen_fn == NULL) {
        return false;
    }
    if (!sve_access_check(s)) {
        return true;
    }

    vsz = vec_full_reg_size(s);
    t = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, a->imm));
    pd = tcg_temp_new_ptr(tcg_ctx);
    zn = tcg_temp_new_ptr(tcg_ctx);
    pg = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, pd, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rd));
    tcg_gen_addi_ptr(tcg_ctx, zn, tcg_ctx->cpu_env, vec_full_reg_offset(s, a->rn));
    tcg_gen_addi_ptr(tcg_ctx, pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));

    gen_fn(tcg_ctx, t, pd, zn, pg, t);

    tcg_temp_free_ptr(tcg_ctx, pd);
    tcg_temp_free_ptr(tcg_ctx, zn);
    tcg_temp_free_ptr(tcg_ctx, pg);

    do_pred_flags(tcg_ctx, t);

    tcg_temp_free_i32(tcg_ctx, t);
    return true;
}

#define DO_PPZI(NAME, name) \
static bool trans_##NAME##_ppzi(DisasContext *s, arg_rpri_esz *a)         \
{                                                                         \
    static gen_helper_gvec_flags_3 * const fns[4] = {                     \
        gen_helper_sve_##name##_ppzi_b, gen_helper_sve_##name##_ppzi_h,   \
        gen_helper_sve_##name##_ppzi_s, gen_helper_sve_##name##_ppzi_d,   \
    };                                                                    \
    return do_ppzi_flags(s, a, fns[a->esz]);                              \
}

DO_PPZI(CMPEQ, cmpeq)
DO_PPZI(CMPNE, cmpne)
DO_PPZI(CMPGT, cmpgt)
DO_PPZI(CMPGE, cmpge)
DO_PPZI(CMPHI, cmphi)
DO_PPZI(CMPHS, cmphs)
DO_PPZI(CMPLT, cmplt)
DO_PPZI(CMPLE, cmple)
DO_PPZI(CMPLO, cmplo)
DO_PPZI(CMPLS, cmpls)

#undef DO_PPZI

/*
 *** SVE Partition Break Group
 */

static bool do_brk3(DisasContext *s, arg_rprr_s *a,
                    gen_helper_gvec_4 *fn, gen_helper_gvec_flags_4 *fn_s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

    unsigned vsz = pred_full_reg_size(s);

    /* Predicate sizes may be smaller and cannot use simd_desc.  */
    TCGv_ptr d = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr n = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr m = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr g = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i32 t = tcg_const_i32(tcg_ctx, vsz - 2);

    tcg_gen_addi_ptr(tcg_ctx, d, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rd));
    tcg_gen_addi_ptr(tcg_ctx, n, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rn));
    tcg_gen_addi_ptr(tcg_ctx, m, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rm));
    tcg_gen_addi_ptr(tcg_ctx, g, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));

    if (a->s) {
        fn_s(tcg_ctx, t, d, n, m, g, t);
        do_pred_flags(tcg_ctx, t);
    } else {
        fn(tcg_ctx, d, n, m, g, t);
    }
    tcg_temp_free_ptr(tcg_ctx, d);
    tcg_temp_free_ptr(tcg_ctx, n);
    tcg_temp_free_ptr(tcg_ctx, m);
    tcg_temp_free_ptr(tcg_ctx, g);
    tcg_temp_free_i32(tcg_ctx, t);
    return true;
}

static bool do_brk2(DisasContext *s, arg_rpr_s *a,
                    gen_helper_gvec_3 *fn, gen_helper_gvec_flags_3 *fn_s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

    unsigned vsz = pred_full_reg_size(s);

    /* Predicate sizes may be smaller and cannot use simd_desc.  */
    TCGv_ptr d = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr n = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr g = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i32 t = tcg_const_i32(tcg_ctx, vsz - 2);

    tcg_gen_addi_ptr(tcg_ctx, d, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rd));
    tcg_gen_addi_ptr(tcg_ctx, n, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rn));
    tcg_gen_addi_ptr(tcg_ctx, g, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));

    if (a->s) {
        fn_s(tcg_ctx, t, d, n, g, t);
        do_pred_flags(tcg_ctx, t);
    } else {
        fn(tcg_ctx, d, n, g, t);
    }
    tcg_temp_free_ptr(tcg_ctx, d);
    tcg_temp_free_ptr(tcg_ctx, n);
    tcg_temp_free_ptr(tcg_ctx, g);
    tcg_temp_free_i32(tcg_ctx, t);
    return true;
}

static bool trans_BRKPA(DisasContext *s, arg_rprr_s *a)
{
    return do_brk3(s, a, gen_helper_sve_brkpa, gen_helper_sve_brkpas);
}

static bool trans_BRKPB(DisasContext *s, arg_rprr_s *a)
{
    return do_brk3(s, a, gen_helper_sve_brkpb, gen_helper_sve_brkpbs);
}

static bool trans_BRKA_m(DisasContext *s, arg_rpr_s *a)
{
    return do_brk2(s, a, gen_helper_sve_brka_m, gen_helper_sve_brkas_m);
}

static bool trans_BRKB_m(DisasContext *s, arg_rpr_s *a)
{
    return do_brk2(s, a, gen_helper_sve_brkb_m, gen_helper_sve_brkbs_m);
}

static bool trans_BRKA_z(DisasContext *s, arg_rpr_s *a)
{
    return do_brk2(s, a, gen_helper_sve_brka_z, gen_helper_sve_brkas_z);
}

static bool trans_BRKB_z(DisasContext *s, arg_rpr_s *a)
{
    return do_brk2(s, a, gen_helper_sve_brkb_z, gen_helper_sve_brkbs_z);
}

static bool trans_BRKN(DisasContext *s, arg_rpr_s *a)
{
    return do_brk2(s, a, gen_helper_sve_brkn, gen_helper_sve_brkns);
}

/*
 *** SVE Predicate Count Group
 */

static void do_cntp(DisasContext *s, TCGv_i64 val, int esz, int pn, int pg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned psz = pred_full_reg_size(s);

    if (psz <= 8) {
        uint64_t psz_mask;

        tcg_gen_ld_i64(tcg_ctx, val, tcg_ctx->cpu_env, pred_full_reg_offset(s, pn));
        if (pn != pg) {
            TCGv_i64 g = tcg_temp_new_i64(tcg_ctx);
            tcg_gen_ld_i64(tcg_ctx, g, tcg_ctx->cpu_env, pred_full_reg_offset(s, pg));
            tcg_gen_and_i64(tcg_ctx, val, val, g);
            tcg_temp_free_i64(tcg_ctx, g);
        }

        /* Reduce the pred_esz_masks value simply to reduce the
         * size of the code generated here.
         */
        psz_mask = MAKE_64BIT_MASK(0, psz * 8);
        tcg_gen_andi_i64(tcg_ctx, val, val, pred_esz_masks[esz] & psz_mask);

        tcg_gen_ctpop_i64(tcg_ctx, val, val);
    } else {
        TCGv_ptr t_pn = tcg_temp_new_ptr(tcg_ctx);
        TCGv_ptr t_pg = tcg_temp_new_ptr(tcg_ctx);
        unsigned desc;
        TCGv_i32 t_desc;

        desc = psz - 2;
        desc = deposit32(desc, SIMD_DATA_SHIFT, 2, esz);

        tcg_gen_addi_ptr(tcg_ctx, t_pn, tcg_ctx->cpu_env, pred_full_reg_offset(s, pn));
        tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, pg));
        t_desc = tcg_const_i32(tcg_ctx, desc);

        gen_helper_sve_cntp(tcg_ctx, val, t_pn, t_pg, t_desc);
        tcg_temp_free_ptr(tcg_ctx, t_pn);
        tcg_temp_free_ptr(tcg_ctx, t_pg);
        tcg_temp_free_i32(tcg_ctx, t_desc);
    }
}

static bool trans_CNTP(DisasContext *s, arg_CNTP *a)
{
    if (sve_access_check(s)) {
        do_cntp(s, cpu_reg(s, a->rd), a->esz, a->rn, a->pg);
    }
    return true;
}

static bool trans_INCDECP_r(DisasContext *s, arg_incdec_pred *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 reg = cpu_reg(s, a->rd);
        TCGv_i64 val = tcg_temp_new_i64(tcg_ctx);

        do_cntp(s, val, a->esz, a->pg, a->pg);
        if (a->d) {
            tcg_gen_sub_i64(tcg_ctx, reg, reg, val);
        } else {
            tcg_gen_add_i64(tcg_ctx, reg, reg, val);
        }
        tcg_temp_free_i64(tcg_ctx, val);
    }
    return true;
}

static bool trans_INCDECP_z(DisasContext *s, arg_incdec2_pred *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_i64 val = tcg_temp_new_i64(tcg_ctx);
        GVecGen2sFn *gvec_fn = a->d ? tcg_gen_gvec_subs : tcg_gen_gvec_adds;

        do_cntp(s, val, a->esz, a->pg, a->pg);
        gvec_fn(tcg_ctx, a->esz, vec_full_reg_offset(s, a->rd),
                vec_full_reg_offset(s, a->rn), val, vsz, vsz);
    }
    return true;
}

static bool trans_SINCDECP_r_32(DisasContext *s, arg_incdec_pred *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 reg = cpu_reg(s, a->rd);
        TCGv_i64 val = tcg_temp_new_i64(tcg_ctx);

        do_cntp(s, val, a->esz, a->pg, a->pg);
        do_sat_addsub_32(tcg_ctx, reg, val, a->u, a->d);
    }
    return true;
}

static bool trans_SINCDECP_r_64(DisasContext *s, arg_incdec_pred *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 reg = cpu_reg(s, a->rd);
        TCGv_i64 val = tcg_temp_new_i64(tcg_ctx);

        do_cntp(s, val, a->esz, a->pg, a->pg);
        do_sat_addsub_64(tcg_ctx, reg, val, a->u, a->d);
    }
    return true;
}

static bool trans_SINCDECP_z(DisasContext *s, arg_incdec2_pred *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGv_i64 val = tcg_temp_new_i64(tcg_ctx);
        do_cntp(s, val, a->esz, a->pg, a->pg);
        do_sat_addsub_vec(s, a->esz, a->rd, a->rn, val, a->u, a->d);
    }
    return true;
}

/*
 *** SVE Integer Compare Scalars Group
 */

static bool trans_CTERM(DisasContext *s, arg_CTERM *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

    TCGCond cond = (a->ne ? TCG_COND_NE : TCG_COND_EQ);
    TCGv_i64 rn = read_cpu_reg(s, a->rn, a->sf);
    TCGv_i64 rm = read_cpu_reg(s, a->rm, a->sf);
    TCGv_i64 cmp = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_setcond_i64(tcg_ctx, cond, cmp, rn, rm);
    tcg_gen_extrl_i64_i32(tcg_ctx, tcg_ctx->cpu_NF, cmp);
    tcg_temp_free_i64(tcg_ctx, cmp);

    /* VF = !NF & !CF.  */
    tcg_gen_xori_i32(tcg_ctx, tcg_ctx->cpu_VF, tcg_ctx->cpu_NF, 1);
    tcg_gen_andc_i32(tcg_ctx, tcg_ctx->cpu_VF, tcg_ctx->cpu_VF, tcg_ctx->cpu_CF);

    /* Both NF and VF actually look at bit 31.  */
    tcg_gen_neg_i32(tcg_ctx, tcg_ctx->cpu_NF, tcg_ctx->cpu_NF);
    tcg_gen_neg_i32(tcg_ctx, tcg_ctx->cpu_VF, tcg_ctx->cpu_VF);
    return true;
}

static bool trans_WHILE(DisasContext *s, arg_WHILE *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 op0, op1, t0, t1, tmax;
    TCGv_i32 t2, t3;
    TCGv_ptr ptr;
    unsigned desc, vsz = vec_full_reg_size(s);
    TCGCond cond;

    if (!sve_access_check(s)) {
        return true;
    }

    op0 = read_cpu_reg(s, a->rn, 1);
    op1 = read_cpu_reg(s, a->rm, 1);

    if (!a->sf) {
        if (a->u) {
            tcg_gen_ext32u_i64(tcg_ctx, op0, op0);
            tcg_gen_ext32u_i64(tcg_ctx, op1, op1);
        } else {
            tcg_gen_ext32s_i64(tcg_ctx, op0, op0);
            tcg_gen_ext32s_i64(tcg_ctx, op1, op1);
        }
    }

    /* For the helper, compress the different conditions into a computation
     * of how many iterations for which the condition is true.
     */
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_sub_i64(tcg_ctx, t0, op1, op0);

    tmax = tcg_const_i64(tcg_ctx, vsz >> a->esz);
    if (a->eq) {
        /* Equality means one more iteration.  */
        tcg_gen_addi_i64(tcg_ctx, t0, t0, 1);

        /* If op1 is max (un)signed integer (and the only time the addition
         * above could overflow), then we produce an all-true predicate by
         * setting the count to the vector length.  This is because the
         * pseudocode is described as an increment + compare loop, and the
         * max integer would always compare true.
         */
        tcg_gen_movi_i64(tcg_ctx, t1, (a->sf
                              ? (a->u ? UINT64_MAX : INT64_MAX)
                              : (a->u ? UINT32_MAX : INT32_MAX)));
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, op1, t1, tmax, t0);
    }

    /* Bound to the maximum.  */
    tcg_gen_umin_i64(tcg_ctx, t0, t0, tmax);
    tcg_temp_free_i64(tcg_ctx, tmax);

    /* Set the count to zero if the condition is false.  */
    cond = (a->u
            ? (a->eq ? TCG_COND_LEU : TCG_COND_LTU)
            : (a->eq ? TCG_COND_LE : TCG_COND_LT));
    tcg_gen_movi_i64(tcg_ctx, t1, 0);
    tcg_gen_movcond_i64(tcg_ctx, cond, t0, op0, op1, t0, t1);
    tcg_temp_free_i64(tcg_ctx, t1);

    /* Since we're bounded, pass as a 32-bit type.  */
    t2 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_extrl_i64_i32(tcg_ctx, t2, t0);
    tcg_temp_free_i64(tcg_ctx, t0);

    /* Scale elements to bits.  */
    tcg_gen_shli_i32(tcg_ctx, t2, t2, a->esz);

    desc = (vsz / 8) - 2;
    desc = deposit32(desc, SIMD_DATA_SHIFT, 2, a->esz);
    t3 = tcg_const_i32(tcg_ctx, desc);

    ptr = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, ptr, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->rd));

    gen_helper_sve_while(tcg_ctx, t2, ptr, t2, t3);
    do_pred_flags(tcg_ctx, t2);

    tcg_temp_free_ptr(tcg_ctx, ptr);
    tcg_temp_free_i32(tcg_ctx, t2);
    tcg_temp_free_i32(tcg_ctx, t3);
    return true;
}

/*
 *** SVE Integer Wide Immediate - Unpredicated Group
 */

static bool trans_FDUP(DisasContext *s, arg_FDUP *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        int dofs = vec_full_reg_offset(s, a->rd);
        uint64_t imm;

        /* Decode the VFP immediate.  */
        imm = vfp_expand_imm(a->esz, a->imm);
        imm = dup_const(a->esz, imm);

        tcg_gen_gvec_dup64i(tcg_ctx, dofs, vsz, vsz, imm);
    }
    return true;
}

static bool trans_DUP_i(DisasContext *s, arg_DUP_i *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0 && extract32(s->insn, 13, 1)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        int dofs = vec_full_reg_offset(s, a->rd);

        tcg_gen_gvec_dup64i(tcg_ctx, dofs, vsz, vsz, dup_const(a->esz, a->imm));
    }
    return true;
}

static bool trans_ADD_zzi(DisasContext *s, arg_rri_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0 && extract32(s->insn, 13, 1)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_addi(tcg_ctx, a->esz, vec_full_reg_offset(s, a->rd),
                          vec_full_reg_offset(s, a->rn), a->imm, vsz, vsz);
    }
    return true;
}

static bool trans_SUB_zzi(DisasContext *s, arg_rri_esz *a)
{
    a->imm = -a->imm;
    return trans_ADD_zzi(s, a);
}

static bool trans_SUBR_zzi(DisasContext *s, arg_rri_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static const TCGOpcode vecop_list[] = { INDEX_op_sub_vec, 0 };
    static const GVecGen2s op[4] = {
        { .fni8 = tcg_gen_vec_sub8_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_sve_subri_b,
          .opt_opc = vecop_list,
          .vece = MO_8,
          .scalar_first = true },
        { .fni8 = tcg_gen_vec_sub16_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_sve_subri_h,
          .opt_opc = vecop_list,
          .vece = MO_16,
          .scalar_first = true },
        { .fni4 = tcg_gen_sub_i32,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_sve_subri_s,
          .opt_opc = vecop_list,
          .vece = MO_32,
          .scalar_first = true },
        { .fni8 = tcg_gen_sub_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_sve_subri_d,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64,
          .scalar_first = true }
    };

    if (a->esz == 0 && extract32(s->insn, 13, 1)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_i64 c = tcg_const_i64(tcg_ctx, a->imm);
        tcg_gen_gvec_2s(tcg_ctx, vec_full_reg_offset(s, a->rd),
                        vec_full_reg_offset(s, a->rn),
                        vsz, vsz, c, &op[a->esz]);
        tcg_temp_free_i64(tcg_ctx, c);
    }
    return true;
}

static bool trans_MUL_zzi(DisasContext *s, arg_rri_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_muli(tcg_ctx, a->esz, vec_full_reg_offset(s, a->rd),
                          vec_full_reg_offset(s, a->rn), a->imm, vsz, vsz);
    }
    return true;
}

static bool do_zzi_sat(DisasContext *s, arg_rri_esz *a, bool u, bool d)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->esz == 0 && extract32(s->insn, 13, 1)) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGv_i64 val = tcg_const_i64(tcg_ctx, a->imm);
        do_sat_addsub_vec(s, a->esz, a->rd, a->rn, val, u, d);
        tcg_temp_free_i64(tcg_ctx, val);
    }
    return true;
}

static bool trans_SQADD_zzi(DisasContext *s, arg_rri_esz *a)
{
    return do_zzi_sat(s, a, false, false);
}

static bool trans_UQADD_zzi(DisasContext *s, arg_rri_esz *a)
{
    return do_zzi_sat(s, a, true, false);
}

static bool trans_SQSUB_zzi(DisasContext *s, arg_rri_esz *a)
{
    return do_zzi_sat(s, a, false, true);
}

static bool trans_UQSUB_zzi(DisasContext *s, arg_rri_esz *a)
{
    return do_zzi_sat(s, a, true, true);
}

static bool do_zzi_ool(DisasContext *s, arg_rri_esz *a, gen_helper_gvec_2i *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_i64 c = tcg_const_i64(tcg_ctx, a->imm);

        tcg_gen_gvec_2i_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                            vec_full_reg_offset(s, a->rn),
                            c, vsz, vsz, 0, fn);
        tcg_temp_free_i64(tcg_ctx, c);
    }
    return true;
}

#define DO_ZZI(NAME, name) \
static bool trans_##NAME##_zzi(DisasContext *s, arg_rri_esz *a)         \
{                                                                       \
    static gen_helper_gvec_2i * const fns[4] = {                        \
        gen_helper_sve_##name##i_b, gen_helper_sve_##name##i_h,         \
        gen_helper_sve_##name##i_s, gen_helper_sve_##name##i_d,         \
    };                                                                  \
    return do_zzi_ool(s, a, fns[a->esz]);                               \
}

DO_ZZI(SMAX, smax)
DO_ZZI(UMAX, umax)
DO_ZZI(SMIN, smin)
DO_ZZI(UMIN, umin)

#undef DO_ZZI

static bool trans_DOT_zzz(DisasContext *s, arg_DOT_zzz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_4 * const fns[2][2] = {
        { gen_helper_gvec_sdot_b, gen_helper_gvec_sdot_h },
        { gen_helper_gvec_udot_b, gen_helper_gvec_udot_h }
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, 0, fns[a->u][a->sz]);
    }
    return true;
}

static bool trans_DOT_zzx(DisasContext *s, arg_DOT_zzx *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_4 * const fns[2][2] = {
        { gen_helper_gvec_sdot_idx_b, gen_helper_gvec_sdot_idx_h },
        { gen_helper_gvec_udot_idx_b, gen_helper_gvec_udot_idx_h }
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, a->index, fns[a->u][a->sz]);
    }
    return true;
}

static bool trans_USDOT_zzzz(DisasContext *s, arg_rprrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_i8mm, s) || a->esz != 2) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, 0, gen_helper_gvec_usdot_b);
    }
    return true;
}

static bool do_i8mm_dot_zzxw(DisasContext *s, arg_rrxr_esz *a,
                             gen_helper_gvec_4 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_i8mm, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, a->index, fn);
    }
    return true;
}

static bool trans_USDOT_zzxw_s(DisasContext *s, arg_rrxr_esz *a)
{
    return do_i8mm_dot_zzxw(s, a, gen_helper_gvec_usdot_idx_b);
}

static bool trans_SUDOT_zzxw_s(DisasContext *s, arg_rrxr_esz *a)
{
    return do_i8mm_dot_zzxw(s, a, gen_helper_gvec_sudot_idx_b);
}

static bool do_i8mm_mmla(DisasContext *s, arg_rprrr_esz *a,
                         gen_helper_gvec_4 *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_i8mm, s)) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, 0, fn);
    }
    return true;
}

static bool trans_SMMLA(DisasContext *s, arg_rprrr_esz *a)
{
    return do_i8mm_mmla(s, a, gen_helper_gvec_smmla_b);
}

static bool trans_USMMLA(DisasContext *s, arg_rprrr_esz *a)
{
    return do_i8mm_mmla(s, a, gen_helper_gvec_usmmla_b);
}

static bool trans_UMMLA(DisasContext *s, arg_rprrr_esz *a)
{
    return do_i8mm_mmla(s, a, gen_helper_gvec_ummla_b);
}

static bool trans_BFDOT_zzzz(DisasContext *s, arg_rprrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_bf16, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, 0, gen_helper_gvec_bfdot);
    }
    return true;
}

static bool trans_BFDOT_zzxz(DisasContext *s, arg_rrxr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_bf16, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, a->index, gen_helper_gvec_bfdot_idx);
    }
    return true;
}

static bool trans_BFMMLA(DisasContext *s, arg_rprrr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_bf16, s)) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           vsz, vsz, 0, gen_helper_gvec_bfmmla);
    }
    return true;
}

static bool do_FMMLA(DisasContext *s, arg_rprrr_esz *a,
                     gen_helper_gvec_4_ptr *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, false);

        tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra), status,
                           vsz, vsz, 0, fn);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

static bool trans_FMMLA_s(DisasContext *s, arg_rprrr_esz *a)
{
    if (!dc_isar_feature(aa64_sve_f32mm, s)) {
        return false;
    }
    return do_FMMLA(s, a, gen_helper_fmmla_s);
}

static bool trans_FMMLA_d(DisasContext *s, arg_rprrr_esz *a)
{
    if (!dc_isar_feature(aa64_sve_f64mm, s)) {
        return false;
    }
    return do_FMMLA(s, a, gen_helper_fmmla_d);
}

static bool do_BFMLAL_zzzw(DisasContext *s, arg_rprrr_esz *a, bool sel)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_bf16, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, false);

        tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra), status,
                           vsz, vsz, sel, gen_helper_gvec_bfmlal);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

static bool trans_BFMLALB_zzzw(DisasContext *s, arg_BFMLALB_zzzw *a)
{
    return do_BFMLAL_zzzw(s, a, false);
}

static bool trans_BFMLALT_zzzw(DisasContext *s, arg_BFMLALT_zzzw *a)
{
    return do_BFMLAL_zzzw(s, a, true);
}

static bool do_BFMLAL_zzxw(DisasContext *s, arg_rrxr_esz *a, bool sel)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_bf16, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, false);

        tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra), status,
                           vsz, vsz, (a->index << 1) | sel,
                           gen_helper_gvec_bfmlal_idx);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

static bool trans_BFMLALB_zzxw(DisasContext *s, arg_BFMLALB_zzxw *a)
{
    return do_BFMLAL_zzxw(s, a, false);
}

static bool trans_BFMLALT_zzxw(DisasContext *s, arg_BFMLALT_zzxw *a)
{
    return do_BFMLAL_zzxw(s, a, true);
}

static bool do_FMLAL_zzzw(DisasContext *s, arg_rprrr_esz *a,
                          bool sub, bool sel)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           tcg_ctx->cpu_env, vsz, vsz,
                           (sel << 1) | sub,
                           gen_helper_sve2_fmlal_zzzw_s);
    }
    return true;
}

static bool trans_FMLALB_zzzw(DisasContext *s, arg_FMLALB_zzzw *a)
{
    return do_FMLAL_zzzw(s, a, false, false);
}

static bool trans_FMLALT_zzzw(DisasContext *s, arg_FMLALT_zzzw *a)
{
    return do_FMLAL_zzzw(s, a, false, true);
}

static bool trans_FMLSLB_zzzw(DisasContext *s, arg_FMLSLB_zzzw *a)
{
    return do_FMLAL_zzzw(s, a, true, false);
}

static bool trans_FMLSLT_zzzw(DisasContext *s, arg_FMLSLT_zzzw *a)
{
    return do_FMLAL_zzzw(s, a, true, true);
}

static bool do_FMLAL_zzxw(DisasContext *s, arg_rrxr_esz *a,
                          bool sub, bool sel)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);

        tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           tcg_ctx->cpu_env, vsz, vsz,
                           (a->index << 2) | (sel << 1) | sub,
                           gen_helper_sve2_fmlal_zzxw_s);
    }
    return true;
}

static bool trans_FMLALB_zzxw(DisasContext *s, arg_FMLALB_zzxw *a)
{
    return do_FMLAL_zzxw(s, a, false, false);
}

static bool trans_FMLALT_zzxw(DisasContext *s, arg_FMLALT_zzxw *a)
{
    return do_FMLAL_zzxw(s, a, false, true);
}

static bool trans_FMLSLB_zzxw(DisasContext *s, arg_FMLSLB_zzxw *a)
{
    return do_FMLAL_zzxw(s, a, true, false);
}

static bool trans_FMLSLT_zzxw(DisasContext *s, arg_FMLSLT_zzxw *a)
{
    return do_FMLAL_zzxw(s, a, true, true);
}


/*
 *** SVE Floating Point Multiply-Add Indexed Group
 */

static bool trans_FMLA_zzxz(DisasContext *s, arg_FMLA_zzxz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_4_ptr * const fns[3] = {
        gen_helper_gvec_fmla_idx_h,
        gen_helper_gvec_fmla_idx_s,
        gen_helper_gvec_fmla_idx_d,
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
        tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           vec_full_reg_offset(s, a->ra),
                           status, vsz, vsz, (a->index << 1) | a->sub,
                           fns[a->esz - 1]);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

/*
 *** SVE Floating Point Multiply Indexed Group
 */

static bool trans_FMUL_zzx(DisasContext *s, arg_FMUL_zzx *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3_ptr * const fns[3] = {
        gen_helper_gvec_fmul_idx_h,
        gen_helper_gvec_fmul_idx_s,
        gen_helper_gvec_fmul_idx_d,
    };

    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
        tcg_gen_gvec_3_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           status, vsz, vsz, a->index, fns[a->esz - 1]);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

/*
 *** SVE Floating Point Fast Reduction Group
 */

typedef void gen_helper_fp_reduce(TCGContext *, TCGv_i64, TCGv_ptr, TCGv_ptr,
                                  TCGv_ptr, TCGv_i32);

static void do_reduce(DisasContext *s, arg_rpr_esz *a,
                      gen_helper_fp_reduce *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    unsigned p2vsz = pow2ceil(vsz);
    TCGv_i32 t_desc = tcg_const_i32(tcg_ctx, simd_desc(vsz, p2vsz, 0));
    TCGv_ptr t_zn, t_pg, status;
    TCGv_i64 temp;

    temp = tcg_temp_new_i64(tcg_ctx);
    t_zn = tcg_temp_new_ptr(tcg_ctx);
    t_pg = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, t_zn, tcg_ctx->cpu_env, vec_full_reg_offset(s, a->rn));
    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));
    status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);

    fn(tcg_ctx, temp, t_zn, t_pg, status, t_desc);
    tcg_temp_free_ptr(tcg_ctx, t_zn);
    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_ptr(tcg_ctx, status);
    tcg_temp_free_i32(tcg_ctx, t_desc);

    write_fp_dreg(s, a->rd, temp);
    tcg_temp_free_i64(tcg_ctx, temp);
}

#define DO_VPZ(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rpr_esz *a)                \
{                                                                        \
    static gen_helper_fp_reduce * const fns[3] = {                       \
        gen_helper_sve_##name##_h,                                       \
        gen_helper_sve_##name##_s,                                       \
        gen_helper_sve_##name##_d,                                       \
    };                                                                   \
    if (a->esz == 0) {                                                   \
        return false;                                                    \
    }                                                                    \
    if (sve_access_check(s)) {                                           \
        do_reduce(s, a, fns[a->esz - 1]);                                \
    }                                                                    \
    return true;                                                         \
}

DO_VPZ(FADDV, faddv)
DO_VPZ(FMINNMV, fminnmv)
DO_VPZ(FMAXNMV, fmaxnmv)
DO_VPZ(FMINV, fminv)
DO_VPZ(FMAXV, fmaxv)

/*
 *** SVE Floating Point Unary Operations - Unpredicated Group
 */

static void do_zz_fp(DisasContext *s, arg_rr_esz *a, gen_helper_gvec_2_ptr *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);

    tcg_gen_gvec_2_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                       vec_full_reg_offset(s, a->rn),
                       status, vsz, vsz, 0, fn);
    tcg_temp_free_ptr(tcg_ctx, status);
}

static bool trans_FRECPE(DisasContext *s, arg_rr_esz *a)
{
    static gen_helper_gvec_2_ptr * const fns[3] = {
        gen_helper_gvec_frecpe_h,
        gen_helper_gvec_frecpe_s,
        gen_helper_gvec_frecpe_d,
    };
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        do_zz_fp(s, a, fns[a->esz - 1]);
    }
    return true;
}

static bool trans_FRSQRTE(DisasContext *s, arg_rr_esz *a)
{
    static gen_helper_gvec_2_ptr * const fns[3] = {
        gen_helper_gvec_frsqrte_h,
        gen_helper_gvec_frsqrte_s,
        gen_helper_gvec_frsqrte_d,
    };
    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        do_zz_fp(s, a, fns[a->esz - 1]);
    }
    return true;
}

/*
 *** SVE Floating Point Compare with Zero Group
 */

static void do_ppz_fp(DisasContext *s, arg_rpr_esz *a,
                      gen_helper_gvec_3_ptr *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);

    tcg_gen_gvec_3_ptr(tcg_ctx, pred_full_reg_offset(s, a->rd),
                       vec_full_reg_offset(s, a->rn),
                       pred_full_reg_offset(s, a->pg),
                       status, vsz, vsz, 0, fn);
    tcg_temp_free_ptr(tcg_ctx, status);
}

#define DO_PPZ(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rpr_esz *a)         \
{                                                                 \
    static gen_helper_gvec_3_ptr * const fns[3] = {               \
        gen_helper_sve_##name##_h,                                \
        gen_helper_sve_##name##_s,                                \
        gen_helper_sve_##name##_d,                                \
    };                                                            \
    if (a->esz == 0) {                                            \
        return false;                                             \
    }                                                             \
    if (sve_access_check(s)) {                                    \
        do_ppz_fp(s, a, fns[a->esz - 1]);                         \
    }                                                             \
    return true;                                                  \
}

DO_PPZ(FCMGE_ppz0, fcmge0)
DO_PPZ(FCMGT_ppz0, fcmgt0)
DO_PPZ(FCMLE_ppz0, fcmle0)
DO_PPZ(FCMLT_ppz0, fcmlt0)
DO_PPZ(FCMEQ_ppz0, fcmeq0)
DO_PPZ(FCMNE_ppz0, fcmne0)

#undef DO_PPZ

/*
 *** SVE floating-point trig multiply-add coefficient
 */

static bool trans_FTMAD(DisasContext *s, arg_FTMAD *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3_ptr * const fns[3] = {
        gen_helper_sve_ftmad_h,
        gen_helper_sve_ftmad_s,
        gen_helper_sve_ftmad_d,
    };

    if (a->esz == 0) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
        tcg_gen_gvec_3_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           status, vsz, vsz, a->imm, fns[a->esz - 1]);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

/*
 *** SVE Floating Point Accumulating Reduction Group
 */

static bool trans_FADDA(DisasContext *s, arg_rprr_esz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    typedef void fadda_fn(TCGContext *, TCGv_i64, TCGv_i64, TCGv_ptr,
                          TCGv_ptr, TCGv_ptr, TCGv_i32);
    static fadda_fn * const fns[3] = {
        gen_helper_sve_fadda_h,
        gen_helper_sve_fadda_s,
        gen_helper_sve_fadda_d,
    };
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr t_rm, t_pg, t_fpst;
    TCGv_i64 t_val;
    TCGv_i32 t_desc;

    if (a->esz == 0) {
        return false;
    }
    if (!sve_nonstreaming_access_check(s)) {
        return true;
    }

    t_val = load_esz(tcg_ctx, tcg_ctx->cpu_env, vec_reg_offset(s, a->rn, 0, a->esz), a->esz);
    t_rm = tcg_temp_new_ptr(tcg_ctx);
    t_pg = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, t_rm, tcg_ctx->cpu_env, vec_full_reg_offset(s, a->rm));
    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));
    t_fpst = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
    t_desc = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, 0));

    fns[a->esz - 1](tcg_ctx,t_val, t_val, t_rm, t_pg, t_fpst, t_desc);

    tcg_temp_free_i32(tcg_ctx, t_desc);
    tcg_temp_free_ptr(tcg_ctx, t_fpst);
    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_ptr(tcg_ctx, t_rm);

    write_fp_dreg(s, a->rd, t_val);
    tcg_temp_free_i64(tcg_ctx, t_val);
    return true;
}

/*
 *** SVE Floating Point Arithmetic - Unpredicated Group
 */

static bool do_zzz_fp(DisasContext *s, arg_rrr_esz *a,
                      gen_helper_gvec_3_ptr *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
        tcg_gen_gvec_3_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           status, vsz, vsz, 0, fn);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}


#define DO_FP3(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rrr_esz *a)           \
{                                                                   \
    static gen_helper_gvec_3_ptr * const fns[4] = {                 \
        NULL, gen_helper_gvec_##name##_h,                           \
        gen_helper_gvec_##name##_s, gen_helper_gvec_##name##_d      \
    };                                                              \
    return do_zzz_fp(s, a, fns[a->esz]);                            \
}

DO_FP3(FADD_zzz, fadd)
DO_FP3(FSUB_zzz, fsub)
DO_FP3(FMUL_zzz, fmul)
DO_FP3(FRECPS, recps)
DO_FP3(FRSQRTS, rsqrts)

#undef DO_FP3

static bool trans_FTSMUL(DisasContext *s, arg_rrr_esz *a)
{
    static gen_helper_gvec_3_ptr * const fns[4] = {
        NULL, gen_helper_gvec_ftsmul_h,
        gen_helper_gvec_ftsmul_s, gen_helper_gvec_ftsmul_d,
    };

    if (fns[a->esz] == NULL) {
        return false;
    }
    s->is_nonstreaming = true;
    return do_zzz_fp(s, a, fns[a->esz]);
}

/*
 *** SVE Floating Point Arithmetic - Predicated Group
 */

static bool do_zpzz_fp(DisasContext *s, arg_rprr_esz *a,
                       gen_helper_gvec_4_ptr *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
        tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           pred_full_reg_offset(s, a->pg),
                           status, vsz, vsz, 0, fn);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

#define DO_FP3(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rprr_esz *a)          \
{                                                                   \
    static gen_helper_gvec_4_ptr * const fns[4] = {                 \
        NULL, gen_helper_sve_##name##_h,                            \
        gen_helper_sve_##name##_s, gen_helper_sve_##name##_d        \
    };                                                              \
    return do_zpzz_fp(s, a, fns[a->esz]);                           \
}

DO_FP3(FADD_zpzz, fadd)
DO_FP3(FSUB_zpzz, fsub)
DO_FP3(FMUL_zpzz, fmul)
DO_FP3(FMIN_zpzz, fmin)
DO_FP3(FMAX_zpzz, fmax)
DO_FP3(FMINNM_zpzz, fminnum)
DO_FP3(FMAXNM_zpzz, fmaxnum)
DO_FP3(FABD, fabd)
DO_FP3(FSCALE, fscalbn)
DO_FP3(FDIV, fdiv)
DO_FP3(FMULX, fmulx)

#undef DO_FP3

#define DO_SVE2_FP_PAIR(NAME, name)                                    \
static bool trans_##NAME(DisasContext *s, arg_rprr_esz *a)             \
{                                                                      \
    static gen_helper_gvec_4_ptr * const fns[4] = {                    \
        NULL, gen_helper_sve2_##name##_h,                              \
        gen_helper_sve2_##name##_s, gen_helper_sve2_##name##_d         \
    };                                                                 \
    if (!dc_isar_feature(aa64_sve2, s)) {                              \
        return false;                                                  \
    }                                                                  \
    return do_zpzz_fp(s, a, fns[a->esz]);                              \
}

DO_SVE2_FP_PAIR(FADDP, faddp_zpzz)
DO_SVE2_FP_PAIR(FMAXNMP, fmaxnmp_zpzz)
DO_SVE2_FP_PAIR(FMINNMP, fminnmp_zpzz)
DO_SVE2_FP_PAIR(FMAXP, fmaxp_zpzz)
DO_SVE2_FP_PAIR(FMINP, fminp_zpzz)

#undef DO_SVE2_FP_PAIR

typedef void gen_helper_sve_fp2scalar(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_ptr,
                                      TCGv_i64, TCGv_ptr, TCGv_i32);

static void do_fp_scalar(DisasContext *s, int zd, int zn, int pg, bool is_fp16,
                         TCGv_i64 scalar, gen_helper_sve_fp2scalar *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr t_zd, t_zn, t_pg, status;
    TCGv_i32 desc;

    t_zd = tcg_temp_new_ptr(tcg_ctx);
    t_zn = tcg_temp_new_ptr(tcg_ctx);
    t_pg = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, t_zd, tcg_ctx->cpu_env, vec_full_reg_offset(s, zd));
    tcg_gen_addi_ptr(tcg_ctx, t_zn, tcg_ctx->cpu_env, vec_full_reg_offset(s, zn));
    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, pg));

    status = get_fpstatus_ptr(tcg_ctx, is_fp16);
    desc = tcg_const_i32(tcg_ctx, simd_desc(vsz, vsz, 0));
    fn(tcg_ctx, t_zd, t_zn, t_pg, scalar, status, desc);

    tcg_temp_free_i32(tcg_ctx, desc);
    tcg_temp_free_ptr(tcg_ctx, status);
    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_ptr(tcg_ctx, t_zn);
    tcg_temp_free_ptr(tcg_ctx, t_zd);
}

static void do_fp_imm(DisasContext *s, arg_rpri_esz *a, uint64_t imm,
                      gen_helper_sve_fp2scalar *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 temp = tcg_const_i64(tcg_ctx, imm);
    do_fp_scalar(s, a->rd, a->rn, a->pg, a->esz == MO_16, temp, fn);
    tcg_temp_free_i64(tcg_ctx, temp);
}

#define DO_FP_IMM(NAME, name, const0, const1) \
static bool trans_##NAME##_zpzi(DisasContext *s, arg_rpri_esz *a)         \
{                                                                         \
    static gen_helper_sve_fp2scalar * const fns[3] = {                    \
        gen_helper_sve_##name##_h,                                        \
        gen_helper_sve_##name##_s,                                        \
        gen_helper_sve_##name##_d                                         \
    };                                                                    \
    static uint64_t const val[3][2] = {                                   \
        { float16_##const0, float16_##const1 },                           \
        { float32_##const0, float32_##const1 },                           \
        { float64_##const0, float64_##const1 },                           \
    };                                                                    \
    if (a->esz == 0) {                                                    \
        return false;                                                     \
    }                                                                     \
    if (sve_access_check(s)) {                                            \
        do_fp_imm(s, a, val[a->esz - 1][a->imm], fns[a->esz - 1]);        \
    }                                                                     \
    return true;                                                          \
}

#define float16_two  make_float16(0x4000)
#define float32_two  make_float32(0x40000000)
#define float64_two  make_float64(0x4000000000000000ULL)

DO_FP_IMM(FADD, fadds, half, one)
DO_FP_IMM(FSUB, fsubs, half, one)
DO_FP_IMM(FMUL, fmuls, half, two)
DO_FP_IMM(FSUBR, fsubrs, half, one)
DO_FP_IMM(FMAXNM, fmaxnms, zero, one)
DO_FP_IMM(FMINNM, fminnms, zero, one)
DO_FP_IMM(FMAX, fmaxs, zero, one)
DO_FP_IMM(FMIN, fmins, zero, one)

#undef DO_FP_IMM

static bool do_fp_cmp(DisasContext *s, arg_rprr_esz *a,
                      gen_helper_gvec_4_ptr *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
        tcg_gen_gvec_4_ptr(tcg_ctx, pred_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           pred_full_reg_offset(s, a->pg),
                           status, vsz, vsz, 0, fn);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

#define DO_FPCMP(NAME, name) \
static bool trans_##NAME##_ppzz(DisasContext *s, arg_rprr_esz *a)     \
{                                                                     \
    static gen_helper_gvec_4_ptr * const fns[4] = {                   \
        NULL, gen_helper_sve_##name##_h,                              \
        gen_helper_sve_##name##_s, gen_helper_sve_##name##_d          \
    };                                                                \
    return do_fp_cmp(s, a, fns[a->esz]);                              \
}

DO_FPCMP(FCMGE, fcmge)
DO_FPCMP(FCMGT, fcmgt)
DO_FPCMP(FCMEQ, fcmeq)
DO_FPCMP(FCMNE, fcmne)
DO_FPCMP(FCMUO, fcmuo)
DO_FPCMP(FACGE, facge)
DO_FPCMP(FACGT, facgt)

#undef DO_FPCMP

static bool trans_FCADD(DisasContext *s, arg_FCADD *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_4_ptr * const fns[3] = {
        gen_helper_sve_fcadd_h,
        gen_helper_sve_fcadd_s,
        gen_helper_sve_fcadd_d
    };

    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
        tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           pred_full_reg_offset(s, a->pg),
                           status, vsz, vsz, a->rot, fns[a->esz - 1]);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

typedef void gen_helper_sve_fmla(TCGContext *, TCGv_env, TCGv_ptr, TCGv_i32);

static bool do_fmla(DisasContext *s, arg_rprrr_esz *a, gen_helper_sve_fmla *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (fn == NULL) {
        return false;
    }
    if (!sve_access_check(s)) {
        return true;
    }

    unsigned vsz = vec_full_reg_size(s);
    unsigned desc;
    TCGv_i32 t_desc;
    TCGv_ptr pg = tcg_temp_new_ptr(tcg_ctx);

    /* We would need 7 operands to pass these arguments "properly".
     * So we encode all the register numbers into the descriptor.
     */
    desc = deposit32(a->rd, 5, 5, a->rn);
    desc = deposit32(desc, 10, 5, a->rm);
    desc = deposit32(desc, 15, 5, a->ra);
    desc = simd_desc(vsz, vsz, desc);

    t_desc = tcg_const_i32(tcg_ctx, desc);
    tcg_gen_addi_ptr(tcg_ctx, pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));
    fn(tcg_ctx, tcg_ctx->cpu_env, pg, t_desc);
    tcg_temp_free_i32(tcg_ctx, t_desc);
    tcg_temp_free_ptr(tcg_ctx, pg);
    return true;
}

#define DO_FMLA(NAME, name) \
static bool trans_##NAME(DisasContext *s, arg_rprrr_esz *a)          \
{                                                                    \
    static gen_helper_sve_fmla * const fns[4] = {                    \
        NULL, gen_helper_sve_##name##_h,                             \
        gen_helper_sve_##name##_s, gen_helper_sve_##name##_d         \
    };                                                               \
    return do_fmla(s, a, fns[a->esz]);                               \
}

DO_FMLA(FMLA_zpzzz, fmla_zpzzz)
DO_FMLA(FMLS_zpzzz, fmls_zpzzz)
DO_FMLA(FNMLA_zpzzz, fnmla_zpzzz)
DO_FMLA(FNMLS_zpzzz, fnmls_zpzzz)

#undef DO_FMLA

static bool trans_FCMLA_zpzzz(DisasContext *s, arg_FCMLA_zpzzz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_sve_fmla * const fns[3] = {
        gen_helper_sve_fcmla_zpzzz_h,
        gen_helper_sve_fcmla_zpzzz_s,
        gen_helper_sve_fcmla_zpzzz_d,
    };

    if (a->esz == 0) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        unsigned desc;
        TCGv_i32 t_desc;
        TCGv_ptr pg = tcg_temp_new_ptr(tcg_ctx);

        /* We would need 7 operands to pass these arguments "properly".
         * So we encode all the register numbers into the descriptor.
         */
        desc = deposit32(a->rd, 5, 5, a->rn);
        desc = deposit32(desc, 10, 5, a->rm);
        desc = deposit32(desc, 15, 5, a->ra);
        desc = deposit32(desc, 20, 2, a->rot);
        desc = sextract32(desc, 0, 22);
        desc = simd_desc(vsz, vsz, desc);

        t_desc = tcg_const_i32(tcg_ctx, desc);
        tcg_gen_addi_ptr(tcg_ctx, pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));
        fns[a->esz - 1](tcg_ctx, tcg_ctx->cpu_env, pg, t_desc);
        tcg_temp_free_i32(tcg_ctx, t_desc);
        tcg_temp_free_ptr(tcg_ctx, pg);
    }
    return true;
}

static bool trans_FCMLA_zzxz(DisasContext *s, arg_FCMLA_zzxz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_3_ptr * const fns[2] = {
        gen_helper_gvec_fcmlah_idx,
        gen_helper_gvec_fcmlas_idx,
    };

    tcg_debug_assert(a->esz == 1 || a->esz == 2);
    tcg_debug_assert(a->rd == a->ra);
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, a->esz == MO_16);
        tcg_gen_gvec_3_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           vec_full_reg_offset(s, a->rm),
                           status, vsz, vsz,
                           a->index * 4 + a->rot,
                           fns[a->esz - 1]);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

/*
 *** SVE Floating Point Unary Operations Predicated Group
 */

static bool do_zpz_ptr(DisasContext *s, int rd, int rn, int pg,
                       bool is_fp16, gen_helper_gvec_3_ptr *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, is_fp16);
        tcg_gen_gvec_3_ptr(tcg_ctx, vec_full_reg_offset(s, rd),
                           vec_full_reg_offset(s, rn),
                           pred_full_reg_offset(s, pg),
                           status, vsz, vsz, 0, fn);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

static bool trans_FCVT_sh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvt_sh);
}

static bool trans_FCVT_hs(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvt_hs);
}

static bool trans_FCVT_dh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvt_dh);
}

static bool trans_FCVT_hd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvt_hd);
}

static bool trans_FCVT_ds(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvt_ds);
}

static bool trans_FCVT_sd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvt_sd);
}

static bool trans_BFCVT(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve_bf16, s)) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_bfcvt);
}

static bool trans_FCVTNT_sh(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false,
                      gen_helper_sve2_fcvtnt_sh);
}

static bool trans_FCVTNT_ds(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false,
                      gen_helper_sve2_fcvtnt_ds);
}

static bool trans_BFCVTNT(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve_bf16, s)) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false,
                      gen_helper_sve_bfcvtnt);
}

static bool trans_FCVTLT_hs(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false,
                      gen_helper_sve2_fcvtlt_hs);
}

static bool trans_FCVTLT_sd(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false,
                      gen_helper_sve2_fcvtlt_sd);
}

static bool trans_FLOGB(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3_ptr * const fns[4] = {
        NULL, gen_helper_flogb_h, gen_helper_flogb_s, gen_helper_flogb_d
    };

    if (!dc_isar_feature(aa64_sve2, s) || a->esz == 0) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, a->esz == MO_16,
                      fns[a->esz]);
}

static bool trans_FCVTZS_hh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_fcvtzs_hh);
}

static bool trans_FCVTZU_hh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_fcvtzu_hh);
}

static bool trans_FCVTZS_hs(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_fcvtzs_hs);
}

static bool trans_FCVTZU_hs(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_fcvtzu_hs);
}

static bool trans_FCVTZS_hd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_fcvtzs_hd);
}

static bool trans_FCVTZU_hd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_fcvtzu_hd);
}

static bool trans_FCVTZS_ss(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvtzs_ss);
}

static bool trans_FCVTZU_ss(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvtzu_ss);
}

static bool trans_FCVTZS_sd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvtzs_sd);
}

static bool trans_FCVTZU_sd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvtzu_sd);
}

static bool trans_FCVTZS_ds(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvtzs_ds);
}

static bool trans_FCVTZU_ds(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvtzu_ds);
}

static bool trans_FCVTZS_dd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvtzs_dd);
}

static bool trans_FCVTZU_dd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_fcvtzu_dd);
}

static gen_helper_gvec_3_ptr * const frint_fns[3] = {
    gen_helper_sve_frint_h,
    gen_helper_sve_frint_s,
    gen_helper_sve_frint_d
};

static bool trans_FRINTI(DisasContext *s, arg_rpr_esz *a)
{
    if (a->esz == 0) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, a->esz == MO_16,
                      frint_fns[a->esz - 1]);
}

static bool trans_FRINTX(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3_ptr * const fns[3] = {
        gen_helper_sve_frintx_h,
        gen_helper_sve_frintx_s,
        gen_helper_sve_frintx_d
    };
    if (a->esz == 0) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, a->esz == MO_16, fns[a->esz - 1]);
}

static bool do_zpz_fp_rmode(DisasContext *s, arg_rpr_esz *a, int mode,
                            bool is_fp16, gen_helper_gvec_3_ptr *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (fn == NULL) {
        return false;
    }
    if (sve_access_check(s)) {
        unsigned vsz = vec_full_reg_size(s);
        TCGv_i32 tmode = tcg_const_i32(tcg_ctx, mode);
        TCGv_ptr status = get_fpstatus_ptr(tcg_ctx, is_fp16);

        gen_helper_set_rmode(tcg_ctx, tmode, tmode, status);

        tcg_gen_gvec_3_ptr(tcg_ctx, vec_full_reg_offset(s, a->rd),
                           vec_full_reg_offset(s, a->rn),
                           pred_full_reg_offset(s, a->pg),
                           status, vsz, vsz, 0, fn);

        gen_helper_set_rmode(tcg_ctx, tmode, tmode, status);
        tcg_temp_free_i32(tcg_ctx, tmode);
        tcg_temp_free_ptr(tcg_ctx, status);
    }
    return true;
}

static bool do_frint_mode(DisasContext *s, arg_rpr_esz *a, int mode)
{
    if (a->esz == 0) {
        return false;
    }
    return do_zpz_fp_rmode(s, a, mode, a->esz == MO_16,
                           frint_fns[a->esz - 1]);
}

static bool trans_FRINTN(DisasContext *s, arg_rpr_esz *a)
{
    return do_frint_mode(s, a, float_round_nearest_even);
}

static bool trans_FRINTP(DisasContext *s, arg_rpr_esz *a)
{
    return do_frint_mode(s, a, float_round_up);
}

static bool trans_FRINTM(DisasContext *s, arg_rpr_esz *a)
{
    return do_frint_mode(s, a, float_round_down);
}

static bool trans_FRINTZ(DisasContext *s, arg_rpr_esz *a)
{
    return do_frint_mode(s, a, float_round_to_zero);
}

static bool trans_FRINTA(DisasContext *s, arg_rpr_esz *a)
{
    return do_frint_mode(s, a, float_round_ties_away);
}

static bool trans_FCVTX_ds(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_fp_rmode(s, a, float_round_to_odd, false,
                           gen_helper_sve_fcvt_ds);
}

static bool trans_FCVTXNT_ds(DisasContext *s, arg_rpr_esz *a)
{
    if (!dc_isar_feature(aa64_sve2, s)) {
        return false;
    }
    return do_zpz_fp_rmode(s, a, float_round_to_odd, false,
                           gen_helper_sve2_fcvtnt_ds);
}

static bool trans_FRECPX(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3_ptr * const fns[3] = {
        gen_helper_sve_frecpx_h,
        gen_helper_sve_frecpx_s,
        gen_helper_sve_frecpx_d
    };
    if (a->esz == 0) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, a->esz == MO_16, fns[a->esz - 1]);
}

static bool trans_FSQRT(DisasContext *s, arg_rpr_esz *a)
{
    static gen_helper_gvec_3_ptr * const fns[3] = {
        gen_helper_sve_fsqrt_h,
        gen_helper_sve_fsqrt_s,
        gen_helper_sve_fsqrt_d
    };
    if (a->esz == 0) {
        return false;
    }
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, a->esz == MO_16, fns[a->esz - 1]);
}

static bool trans_SCVTF_hh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_scvt_hh);
}

static bool trans_SCVTF_sh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_scvt_sh);
}

static bool trans_SCVTF_dh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_scvt_dh);
}

static bool trans_SCVTF_ss(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_scvt_ss);
}

static bool trans_SCVTF_ds(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_scvt_ds);
}

static bool trans_SCVTF_sd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_scvt_sd);
}

static bool trans_SCVTF_dd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_scvt_dd);
}

static bool trans_UCVTF_hh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_ucvt_hh);
}

static bool trans_UCVTF_sh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_ucvt_sh);
}

static bool trans_UCVTF_dh(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, true, gen_helper_sve_ucvt_dh);
}

static bool trans_UCVTF_ss(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_ucvt_ss);
}

static bool trans_UCVTF_ds(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_ucvt_ds);
}

static bool trans_UCVTF_sd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_ucvt_sd);
}

static bool trans_UCVTF_dd(DisasContext *s, arg_rpr_esz *a)
{
    return do_zpz_ptr(s, a->rd, a->rn, a->pg, false, gen_helper_sve_ucvt_dd);
}

/*
 *** SVE Memory - 32-bit Gather and Unsized Contiguous Group
 */

static void gen_mov_ptr(TCGContext *tcg_ctx, TCGv_ptr ret, TCGv_ptr arg)
{
#if UINTPTR_MAX == UINT32_MAX
    tcg_gen_mov_i32(tcg_ctx, (TCGv_i32)ret, (TCGv_i32)arg);
#else
    tcg_gen_mov_i64(tcg_ctx, (TCGv_i64)ret, (TCGv_i64)arg);
#endif
}

/* Subroutine loading a vector register at BASE + VOFS of LEN bytes.
 * The load should begin at the address Rn + IMM.
 */

void gen_sve_ldr(DisasContext *s, TCGv_ptr base, int vofs,
                 int len, int rn, int imm)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int len_align = QEMU_ALIGN_DOWN(len, 8);
    int len_remain = len % 8;
    int nparts = len / 8 + ctpop8(len_remain);
    int midx = get_mem_index(s);
    TCGv_i64 dirty_addr, clean_addr, t0, t1;
    TCGv_ptr base_local = NULL;

    dirty_addr = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_addi_i64(tcg_ctx, dirty_addr, cpu_reg_sp(s, rn), imm);
    clean_addr = gen_mte_checkN(s, dirty_addr, false, rn != 31, len);
    tcg_temp_free_i64(tcg_ctx, dirty_addr);
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
            tcg_gen_qemu_ld_i64(tcg_ctx, t0, clean_addr, midx, MO_LEQ);
            tcg_gen_st_i64(tcg_ctx, t0, base, vofs + i);
            tcg_gen_addi_i64(tcg_ctx, clean_addr, clean_addr, 8);
        }
    } else {
        TCGLabel *loop = gen_new_label(tcg_ctx);
        TCGv_ptr tp, i = tcg_const_local_ptr(tcg_ctx, 0);
        TCGv_i64 clean_addr_local = tcg_temp_local_new_i64(tcg_ctx);

        tcg_gen_mov_i64(tcg_ctx, clean_addr_local, clean_addr);
        clean_addr = clean_addr_local;

        if (base != tcg_ctx->cpu_env) {
            base_local = tcg_temp_local_new_ptr(tcg_ctx);
            gen_mov_ptr(tcg_ctx, base_local, base);
            base = base_local;
        }

        gen_set_label(tcg_ctx, loop);

        /* Minimize the number of local temps that must be re-read from
         * the stack each iteration.  Instead, re-compute values other
         * than the loop counter.
         */
        tcg_gen_qemu_ld_i64(tcg_ctx, t0, clean_addr, midx, MO_LEQ);
        tcg_gen_addi_i64(tcg_ctx, clean_addr, clean_addr, 8);

        tp = tcg_temp_new_ptr(tcg_ctx);
        tcg_gen_add_ptr(tcg_ctx, tp, base, i);
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
        switch (len_remain) {
        case 2:
        case 4:
        case 8:
            tcg_gen_qemu_ld_i64(tcg_ctx, t0, clean_addr, midx,
                                MO_LE | ctz32(len_remain));
            break;

        case 6:
            t1 = tcg_temp_new_i64(tcg_ctx);
            tcg_gen_qemu_ld_i64(tcg_ctx, t0, clean_addr, midx, MO_LEUL);
            tcg_gen_addi_i64(tcg_ctx, clean_addr, clean_addr, 4);
            tcg_gen_qemu_ld_i64(tcg_ctx, t1, clean_addr, midx, MO_LEUW);
            tcg_gen_deposit_i64(tcg_ctx, t0, t0, t1, 32, 32);
            tcg_temp_free_i64(tcg_ctx, t1);
            break;

        default:
            g_assert_not_reached();
        }
        tcg_gen_st_i64(tcg_ctx, t0, base, vofs + len_align);
    }
    if (base_local != NULL) {
        tcg_temp_free_ptr(tcg_ctx, base_local);
    }
    tcg_temp_free_i64(tcg_ctx, t0);
}

/* Similarly for stores.  */
void gen_sve_str(DisasContext *s, TCGv_ptr base, int vofs,
                 int len, int rn, int imm)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int len_align = QEMU_ALIGN_DOWN(len, 8);
    int len_remain = len % 8;
    int nparts = len / 8 + ctpop8(len_remain);
    int midx = get_mem_index(s);
    TCGv_i64 dirty_addr, clean_addr, t0;
    TCGv_ptr base_local = NULL;

    dirty_addr = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_addi_i64(tcg_ctx, dirty_addr, cpu_reg_sp(s, rn), imm);
    clean_addr = gen_mte_checkN(s, dirty_addr, false, rn != 31, len);
    tcg_temp_free_i64(tcg_ctx, dirty_addr);
    t0 = tcg_temp_new_i64(tcg_ctx);

    /* Note that unpredicated load/store of vector/predicate registers
     * are defined as a stream of bytes, which equates to little-endian
     * operations on larger quantities.  There is no nice way to force
     * a little-endian store for aarch64_be-linux-user out of line.
     *
     * Attempt to keep code expansion to a minimum by limiting the
     * amount of unrolling done.
     */
    if (nparts <= 4) {
        int i;

        for (i = 0; i < len_align; i += 8) {
            tcg_gen_ld_i64(tcg_ctx, t0, base, vofs + i);
            tcg_gen_qemu_st_i64(tcg_ctx, t0, clean_addr, midx, MO_LEQ);
            tcg_gen_addi_i64(tcg_ctx, clean_addr, clean_addr, 8);
        }
    } else {
        TCGLabel *loop = gen_new_label(tcg_ctx);
        TCGv_ptr t2, i = tcg_const_local_ptr(tcg_ctx, 0);
        TCGv_i64 clean_addr_local = tcg_temp_local_new_i64(tcg_ctx);

        tcg_gen_mov_i64(tcg_ctx, clean_addr_local, clean_addr);
        clean_addr = clean_addr_local;

        if (base != tcg_ctx->cpu_env) {
            base_local = tcg_temp_local_new_ptr(tcg_ctx);
            gen_mov_ptr(tcg_ctx, base_local, base);
            base = base_local;
        }

        gen_set_label(tcg_ctx, loop);

        t2 = tcg_temp_new_ptr(tcg_ctx);
        tcg_gen_add_ptr(tcg_ctx, t2, base, i);
        tcg_gen_ld_i64(tcg_ctx, t0, t2, vofs);

        /* Minimize the number of local temps that must be re-read from
         * the stack each iteration.  Instead, re-compute values other
         * than the loop counter.
         */
        tcg_temp_free_ptr(tcg_ctx, t2);

        tcg_gen_qemu_st_i64(tcg_ctx, t0, clean_addr, midx, MO_LEQ);
        tcg_gen_addi_i64(tcg_ctx, clean_addr, clean_addr, 8);

        tcg_gen_addi_ptr(tcg_ctx, i, i, 8);

        tcg_gen_brcondi_ptr(tcg_ctx, TCG_COND_LTU, i, len_align, loop);
        tcg_temp_free_ptr(tcg_ctx, i);
    }

    /* Predicate register stores can be any multiple of 2.  */
    if (len_remain) {
        tcg_gen_ld_i64(tcg_ctx, t0, base, vofs + len_align);

        switch (len_remain) {
        case 2:
        case 4:
        case 8:
            tcg_gen_qemu_st_i64(tcg_ctx, t0, clean_addr, midx,
                                MO_LE | ctz32(len_remain));
            break;

        case 6:
            tcg_gen_qemu_st_i64(tcg_ctx, t0, clean_addr, midx, MO_LEUL);
            tcg_gen_addi_i64(tcg_ctx, clean_addr, clean_addr, 4);
            tcg_gen_shri_i64(tcg_ctx, t0, t0, 32);
            tcg_gen_qemu_st_i64(tcg_ctx, t0, clean_addr, midx, MO_LEUW);
            break;

        default:
            g_assert_not_reached();
        }
    }
    if (base_local != NULL) {
        tcg_temp_free_ptr(tcg_ctx, base_local);
    }
    tcg_temp_free_i64(tcg_ctx, t0);
}

static bool trans_LDR_zri(DisasContext *s, arg_rri *a)
{
    if (sve_access_check(s)) {
        int size = vec_full_reg_size(s);
        int off = vec_full_reg_offset(s, a->rd);
        gen_sve_ldr(s, s->uc->tcg_ctx->cpu_env, off, size, a->rn,
                    a->imm * size);
    }
    return true;
}

static bool trans_LDR_pri(DisasContext *s, arg_rri *a)
{
    if (sve_access_check(s)) {
        int size = pred_full_reg_size(s);
        int off = pred_full_reg_offset(s, a->rd);
        gen_sve_ldr(s, s->uc->tcg_ctx->cpu_env, off, size, a->rn,
                    a->imm * size);
    }
    return true;
}

static bool trans_STR_zri(DisasContext *s, arg_rri *a)
{
    if (sve_access_check(s)) {
        int size = vec_full_reg_size(s);
        int off = vec_full_reg_offset(s, a->rd);
        gen_sve_str(s, s->uc->tcg_ctx->cpu_env, off, size, a->rn,
                    a->imm * size);
    }
    return true;
}

static bool trans_STR_pri(DisasContext *s, arg_rri *a)
{
    if (sve_access_check(s)) {
        int size = pred_full_reg_size(s);
        int off = pred_full_reg_offset(s, a->rd);
        gen_sve_str(s, s->uc->tcg_ctx->cpu_env, off, size, a->rn,
                    a->imm * size);
    }
    return true;
}

/*
 *** SVE Memory - Contiguous Load Group
 */

/* The memory mode of the dtype.  */
static const MemOp dtype_mop[16] = {
    MO_UB, MO_UB, MO_UB, MO_UB,
    MO_SL, MO_UW, MO_UW, MO_UW,
    MO_SW, MO_SW, MO_UL, MO_UL,
    MO_SB, MO_SB, MO_SB, MO_Q
};

#define dtype_msz(x)  (dtype_mop[x] & MO_SIZE)

/* The vector element size of dtype.  */
static const uint8_t dtype_esz[16] = {
    0, 1, 2, 3,
    3, 1, 2, 3,
    3, 2, 2, 3,
    3, 2, 1, 3
};

static TCGMemOpIdx sve_memopidx(DisasContext *s, int dtype)
{
    return make_memop_idx(s->be_data | dtype_mop[dtype], get_mem_index(s));
}

static TCGv_i64 sve_clean_data_tbi(DisasContext *s, TCGv_i64 addr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 clean = new_tmp_a64(s);

    if (s->tbid == 0) {
        tcg_gen_mov_i64(tcg_ctx, clean, addr);
    } else if (!regime_has_2_ranges(s->mmu_idx)) {
        tcg_gen_extract_i64(tcg_ctx, clean, addr, 0, 56);
    } else {
        tcg_gen_sextract_i64(tcg_ctx, clean, addr, 0, 56);

        if (s->tbid != 3) {
            TCGv_i64 tcg_zero = tcg_const_i64(tcg_ctx, 0);

            tcg_gen_movcond_i64(tcg_ctx,
                                s->tbid == 1 ? TCG_COND_GE : TCG_COND_LT,
                                clean, clean, tcg_zero, clean, addr);
            tcg_temp_free_i64(tcg_ctx, tcg_zero);
        }
    }

    return clean;
}

static void do_mem_zpa(DisasContext *s, int zt, int pg, TCGv_i64 addr,
                       int dtype, bool mte, gen_helper_gvec_mem *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr t_pg;
    TCGv_i32 t_desc;
    int desc;

    /* For e.g. LD4, there are not enough arguments to pass all 4
     * registers as pointers, so encode the regno into the data field.
     * For consistency, do this even for LD1.
     */
    desc = sve_memopidx(s, dtype);
    desc |= zt << MEMOPIDX_SHIFT;
    desc = simd_desc(vsz, vsz, desc);
    t_desc = tcg_const_i32(tcg_ctx, desc);
    t_pg = tcg_temp_new_ptr(tcg_ctx);

    if (!mte) {
        addr = sve_clean_data_tbi(s, addr);
    }

    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, pg));
    fn(tcg_ctx, tcg_ctx->cpu_env, t_pg, addr, t_desc);

    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_i32(tcg_ctx, t_desc);
}

static void do_ld_zpa(DisasContext *s, int zt, int pg,
                      TCGv_i64 addr, int dtype, int nreg)
{
    static gen_helper_gvec_mem * const fns[2][16][4] = {
        /* Little-endian */
        { { gen_helper_sve_ld1bb_r, gen_helper_sve_ld2bb_r,
            gen_helper_sve_ld3bb_r, gen_helper_sve_ld4bb_r },
          { gen_helper_sve_ld1bhu_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1bsu_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1bdu_r, NULL, NULL, NULL },

          { gen_helper_sve_ld1sds_le_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1hh_le_r, gen_helper_sve_ld2hh_le_r,
            gen_helper_sve_ld3hh_le_r, gen_helper_sve_ld4hh_le_r },
          { gen_helper_sve_ld1hsu_le_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1hdu_le_r, NULL, NULL, NULL },

          { gen_helper_sve_ld1hds_le_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1hss_le_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1ss_le_r, gen_helper_sve_ld2ss_le_r,
            gen_helper_sve_ld3ss_le_r, gen_helper_sve_ld4ss_le_r },
          { gen_helper_sve_ld1sdu_le_r, NULL, NULL, NULL },

          { gen_helper_sve_ld1bds_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1bss_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1bhs_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1dd_le_r, gen_helper_sve_ld2dd_le_r,
            gen_helper_sve_ld3dd_le_r, gen_helper_sve_ld4dd_le_r } },

        /* Big-endian */
        { { gen_helper_sve_ld1bb_r, gen_helper_sve_ld2bb_r,
            gen_helper_sve_ld3bb_r, gen_helper_sve_ld4bb_r },
          { gen_helper_sve_ld1bhu_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1bsu_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1bdu_r, NULL, NULL, NULL },

          { gen_helper_sve_ld1sds_be_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1hh_be_r, gen_helper_sve_ld2hh_be_r,
            gen_helper_sve_ld3hh_be_r, gen_helper_sve_ld4hh_be_r },
          { gen_helper_sve_ld1hsu_be_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1hdu_be_r, NULL, NULL, NULL },

          { gen_helper_sve_ld1hds_be_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1hss_be_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1ss_be_r, gen_helper_sve_ld2ss_be_r,
            gen_helper_sve_ld3ss_be_r, gen_helper_sve_ld4ss_be_r },
          { gen_helper_sve_ld1sdu_be_r, NULL, NULL, NULL },

          { gen_helper_sve_ld1bds_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1bss_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1bhs_r, NULL, NULL, NULL },
          { gen_helper_sve_ld1dd_be_r, gen_helper_sve_ld2dd_be_r,
            gen_helper_sve_ld3dd_be_r, gen_helper_sve_ld4dd_be_r } }
    };
    static gen_helper_gvec_mem * const mte_fns[2][16][4] = {
        /* Little-endian */
        { { gen_helper_sve_ld1bb_r_mte, gen_helper_sve_ld2bb_r_mte,
            gen_helper_sve_ld3bb_r_mte, gen_helper_sve_ld4bb_r_mte },
          { gen_helper_sve_ld1bhu_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1bsu_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1bdu_r_mte, NULL, NULL, NULL },

          { gen_helper_sve_ld1sds_le_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1hh_le_r_mte,
            gen_helper_sve_ld2hh_le_r_mte,
            gen_helper_sve_ld3hh_le_r_mte,
            gen_helper_sve_ld4hh_le_r_mte },
          { gen_helper_sve_ld1hsu_le_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1hdu_le_r_mte, NULL, NULL, NULL },

          { gen_helper_sve_ld1hds_le_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1hss_le_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1ss_le_r_mte,
            gen_helper_sve_ld2ss_le_r_mte,
            gen_helper_sve_ld3ss_le_r_mte,
            gen_helper_sve_ld4ss_le_r_mte },
          { gen_helper_sve_ld1sdu_le_r_mte, NULL, NULL, NULL },

          { gen_helper_sve_ld1bds_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1bss_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1bhs_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1dd_le_r_mte,
            gen_helper_sve_ld2dd_le_r_mte,
            gen_helper_sve_ld3dd_le_r_mte,
            gen_helper_sve_ld4dd_le_r_mte } },

        /* Big-endian */
        { { gen_helper_sve_ld1bb_r_mte, gen_helper_sve_ld2bb_r_mte,
            gen_helper_sve_ld3bb_r_mte, gen_helper_sve_ld4bb_r_mte },
          { gen_helper_sve_ld1bhu_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1bsu_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1bdu_r_mte, NULL, NULL, NULL },

          { gen_helper_sve_ld1sds_be_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1hh_be_r_mte,
            gen_helper_sve_ld2hh_be_r_mte,
            gen_helper_sve_ld3hh_be_r_mte,
            gen_helper_sve_ld4hh_be_r_mte },
          { gen_helper_sve_ld1hsu_be_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1hdu_be_r_mte, NULL, NULL, NULL },

          { gen_helper_sve_ld1hds_be_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1hss_be_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1ss_be_r_mte,
            gen_helper_sve_ld2ss_be_r_mte,
            gen_helper_sve_ld3ss_be_r_mte,
            gen_helper_sve_ld4ss_be_r_mte },
          { gen_helper_sve_ld1sdu_be_r_mte, NULL, NULL, NULL },

          { gen_helper_sve_ld1bds_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1bss_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1bhs_r_mte, NULL, NULL, NULL },
          { gen_helper_sve_ld1dd_be_r_mte,
            gen_helper_sve_ld2dd_be_r_mte,
            gen_helper_sve_ld3dd_be_r_mte,
            gen_helper_sve_ld4dd_be_r_mte } }
    };
    gen_helper_gvec_mem *fn;

    if (s->mte_active[0]) {
        fn = mte_fns[s->be_data == MO_BE][dtype][nreg];
    } else {
        fn = fns[s->be_data == MO_BE][dtype][nreg];
    }

    /* While there are holes in the table, they are not
     * accessible via the instruction encoding.
     */
    assert(fn != NULL);
    do_mem_zpa(s, zt, pg, addr, dtype, s->mte_active[0], fn);
}

static bool trans_LD_zprr(DisasContext *s, arg_rprr_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->rm == 31) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGv_i64 addr = new_tmp_a64(s);
        tcg_gen_shli_i64(tcg_ctx, addr, cpu_reg(s, a->rm), dtype_msz(a->dtype));
        tcg_gen_add_i64(tcg_ctx, addr, addr, cpu_reg_sp(s, a->rn));
        do_ld_zpa(s, a->rd, a->pg, addr, a->dtype, a->nreg);
    }
    return true;
}

static bool trans_LD_zpri(DisasContext *s, arg_rpri_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        int vsz = vec_full_reg_size(s);
        int elements = vsz >> dtype_esz[a->dtype];
        TCGv_i64 addr = new_tmp_a64(s);

        tcg_gen_addi_i64(tcg_ctx, addr, cpu_reg_sp(s, a->rn),
                         (a->imm * elements * (a->nreg + 1))
                         << dtype_msz(a->dtype));
        do_ld_zpa(s, a->rd, a->pg, addr, a->dtype, a->nreg);
    }
    return true;
}

static bool trans_LDFF1_zprr(DisasContext *s, arg_rprr_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_mem * const fns[2][16] = {
        /* Little-endian */
        { gen_helper_sve_ldff1bb_r,
          gen_helper_sve_ldff1bhu_r,
          gen_helper_sve_ldff1bsu_r,
          gen_helper_sve_ldff1bdu_r,

          gen_helper_sve_ldff1sds_le_r,
          gen_helper_sve_ldff1hh_le_r,
          gen_helper_sve_ldff1hsu_le_r,
          gen_helper_sve_ldff1hdu_le_r,

          gen_helper_sve_ldff1hds_le_r,
          gen_helper_sve_ldff1hss_le_r,
          gen_helper_sve_ldff1ss_le_r,
          gen_helper_sve_ldff1sdu_le_r,

          gen_helper_sve_ldff1bds_r,
          gen_helper_sve_ldff1bss_r,
          gen_helper_sve_ldff1bhs_r,
          gen_helper_sve_ldff1dd_le_r },

        /* Big-endian */
        { gen_helper_sve_ldff1bb_r,
          gen_helper_sve_ldff1bhu_r,
          gen_helper_sve_ldff1bsu_r,
          gen_helper_sve_ldff1bdu_r,

          gen_helper_sve_ldff1sds_be_r,
          gen_helper_sve_ldff1hh_be_r,
          gen_helper_sve_ldff1hsu_be_r,
          gen_helper_sve_ldff1hdu_be_r,

          gen_helper_sve_ldff1hds_be_r,
          gen_helper_sve_ldff1hss_be_r,
          gen_helper_sve_ldff1ss_be_r,
          gen_helper_sve_ldff1sdu_be_r,

          gen_helper_sve_ldff1bds_r,
          gen_helper_sve_ldff1bss_r,
          gen_helper_sve_ldff1bhs_r,
          gen_helper_sve_ldff1dd_be_r },
    };
    static gen_helper_gvec_mem * const mte_fns[2][16] = {
        /* Little-endian */
        { gen_helper_sve_ldff1bb_r_mte,
          gen_helper_sve_ldff1bhu_r_mte,
          gen_helper_sve_ldff1bsu_r_mte,
          gen_helper_sve_ldff1bdu_r_mte,

          gen_helper_sve_ldff1sds_le_r_mte,
          gen_helper_sve_ldff1hh_le_r_mte,
          gen_helper_sve_ldff1hsu_le_r_mte,
          gen_helper_sve_ldff1hdu_le_r_mte,

          gen_helper_sve_ldff1hds_le_r_mte,
          gen_helper_sve_ldff1hss_le_r_mte,
          gen_helper_sve_ldff1ss_le_r_mte,
          gen_helper_sve_ldff1sdu_le_r_mte,

          gen_helper_sve_ldff1bds_r_mte,
          gen_helper_sve_ldff1bss_r_mte,
          gen_helper_sve_ldff1bhs_r_mte,
          gen_helper_sve_ldff1dd_le_r_mte },

        /* Big-endian */
        { gen_helper_sve_ldff1bb_r_mte,
          gen_helper_sve_ldff1bhu_r_mte,
          gen_helper_sve_ldff1bsu_r_mte,
          gen_helper_sve_ldff1bdu_r_mte,

          gen_helper_sve_ldff1sds_be_r_mte,
          gen_helper_sve_ldff1hh_be_r_mte,
          gen_helper_sve_ldff1hsu_be_r_mte,
          gen_helper_sve_ldff1hdu_be_r_mte,

          gen_helper_sve_ldff1hds_be_r_mte,
          gen_helper_sve_ldff1hss_be_r_mte,
          gen_helper_sve_ldff1ss_be_r_mte,
          gen_helper_sve_ldff1sdu_be_r_mte,

          gen_helper_sve_ldff1bds_r_mte,
          gen_helper_sve_ldff1bss_r_mte,
          gen_helper_sve_ldff1bhs_r_mte,
          gen_helper_sve_ldff1dd_be_r_mte },
    };
    gen_helper_gvec_mem *fn;

    if (sve_nonstreaming_access_check(s)) {
        TCGv_i64 addr = new_tmp_a64(s);
        tcg_gen_shli_i64(tcg_ctx, addr, cpu_reg(s, a->rm), dtype_msz(a->dtype));
        tcg_gen_add_i64(tcg_ctx, addr, addr, cpu_reg_sp(s, a->rn));
        if (s->mte_active[0]) {
            fn = mte_fns[s->be_data == MO_BE][a->dtype];
        } else {
            fn = fns[s->be_data == MO_BE][a->dtype];
        }
        do_mem_zpa(s, a->rd, a->pg, addr, a->dtype, s->mte_active[0], fn);
    }
    return true;
}

static bool trans_LDNF1_zpri(DisasContext *s, arg_rpri_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_mem * const fns[2][16] = {
        /* Little-endian */
        { gen_helper_sve_ldnf1bb_r,
          gen_helper_sve_ldnf1bhu_r,
          gen_helper_sve_ldnf1bsu_r,
          gen_helper_sve_ldnf1bdu_r,

          gen_helper_sve_ldnf1sds_le_r,
          gen_helper_sve_ldnf1hh_le_r,
          gen_helper_sve_ldnf1hsu_le_r,
          gen_helper_sve_ldnf1hdu_le_r,

          gen_helper_sve_ldnf1hds_le_r,
          gen_helper_sve_ldnf1hss_le_r,
          gen_helper_sve_ldnf1ss_le_r,
          gen_helper_sve_ldnf1sdu_le_r,

          gen_helper_sve_ldnf1bds_r,
          gen_helper_sve_ldnf1bss_r,
          gen_helper_sve_ldnf1bhs_r,
          gen_helper_sve_ldnf1dd_le_r },

        /* Big-endian */
        { gen_helper_sve_ldnf1bb_r,
          gen_helper_sve_ldnf1bhu_r,
          gen_helper_sve_ldnf1bsu_r,
          gen_helper_sve_ldnf1bdu_r,

          gen_helper_sve_ldnf1sds_be_r,
          gen_helper_sve_ldnf1hh_be_r,
          gen_helper_sve_ldnf1hsu_be_r,
          gen_helper_sve_ldnf1hdu_be_r,

          gen_helper_sve_ldnf1hds_be_r,
          gen_helper_sve_ldnf1hss_be_r,
          gen_helper_sve_ldnf1ss_be_r,
          gen_helper_sve_ldnf1sdu_be_r,

          gen_helper_sve_ldnf1bds_r,
          gen_helper_sve_ldnf1bss_r,
          gen_helper_sve_ldnf1bhs_r,
          gen_helper_sve_ldnf1dd_be_r },
    };
    static gen_helper_gvec_mem * const mte_fns[2][16] = {
        /* Little-endian */
        { gen_helper_sve_ldnf1bb_r_mte,
          gen_helper_sve_ldnf1bhu_r_mte,
          gen_helper_sve_ldnf1bsu_r_mte,
          gen_helper_sve_ldnf1bdu_r_mte,

          gen_helper_sve_ldnf1sds_le_r_mte,
          gen_helper_sve_ldnf1hh_le_r_mte,
          gen_helper_sve_ldnf1hsu_le_r_mte,
          gen_helper_sve_ldnf1hdu_le_r_mte,

          gen_helper_sve_ldnf1hds_le_r_mte,
          gen_helper_sve_ldnf1hss_le_r_mte,
          gen_helper_sve_ldnf1ss_le_r_mte,
          gen_helper_sve_ldnf1sdu_le_r_mte,

          gen_helper_sve_ldnf1bds_r_mte,
          gen_helper_sve_ldnf1bss_r_mte,
          gen_helper_sve_ldnf1bhs_r_mte,
          gen_helper_sve_ldnf1dd_le_r_mte },

        /* Big-endian */
        { gen_helper_sve_ldnf1bb_r_mte,
          gen_helper_sve_ldnf1bhu_r_mte,
          gen_helper_sve_ldnf1bsu_r_mte,
          gen_helper_sve_ldnf1bdu_r_mte,

          gen_helper_sve_ldnf1sds_be_r_mte,
          gen_helper_sve_ldnf1hh_be_r_mte,
          gen_helper_sve_ldnf1hsu_be_r_mte,
          gen_helper_sve_ldnf1hdu_be_r_mte,

          gen_helper_sve_ldnf1hds_be_r_mte,
          gen_helper_sve_ldnf1hss_be_r_mte,
          gen_helper_sve_ldnf1ss_be_r_mte,
          gen_helper_sve_ldnf1sdu_be_r_mte,

          gen_helper_sve_ldnf1bds_r_mte,
          gen_helper_sve_ldnf1bss_r_mte,
          gen_helper_sve_ldnf1bhs_r_mte,
          gen_helper_sve_ldnf1dd_be_r_mte },
    };
    gen_helper_gvec_mem *fn;

    if (sve_nonstreaming_access_check(s)) {
        int vsz = vec_full_reg_size(s);
        int elements = vsz >> dtype_esz[a->dtype];
        int off = (a->imm * elements) << dtype_msz(a->dtype);
        TCGv_i64 addr = new_tmp_a64(s);

        tcg_gen_addi_i64(tcg_ctx, addr, cpu_reg_sp(s, a->rn), off);
        if (s->mte_active[0]) {
            fn = mte_fns[s->be_data == MO_BE][a->dtype];
        } else {
            fn = fns[s->be_data == MO_BE][a->dtype];
        }
        do_mem_zpa(s, a->rd, a->pg, addr, a->dtype, s->mte_active[0], fn);
    }
    return true;
}

static void do_ldrq(DisasContext *s, int zt, int pg, TCGv_i64 addr, int msz)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_mem * const fns[2][4] = {
        { gen_helper_sve_ld1bb_r,    gen_helper_sve_ld1hh_le_r,
          gen_helper_sve_ld1ss_le_r, gen_helper_sve_ld1dd_le_r },
        { gen_helper_sve_ld1bb_r,    gen_helper_sve_ld1hh_be_r,
          gen_helper_sve_ld1ss_be_r, gen_helper_sve_ld1dd_be_r },
    };
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr t_pg;
    TCGv_i32 t_desc;
    int desc, poff;

    /* Load the first quadword using the normal predicated load helpers.  */
    desc = sve_memopidx(s, msz_dtype(s, msz));
    desc |= zt << MEMOPIDX_SHIFT;
    desc = simd_desc(16, 16, desc);
    t_desc = tcg_const_i32(tcg_ctx, desc);

    poff = pred_full_reg_offset(s, pg);
    if (vsz > 16) {
        /*
         * Zero-extend the first 16 bits of the predicate into a temporary.
         * This avoids triggering an assert making sure we don't have bits
         * set within a predicate beyond VQ, but we have lowered VQ to 1
         * for this load operation.
         */
        TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
#ifdef HOST_WORDS_BIGENDIAN
        poff += 6;
#endif
        tcg_gen_ld16u_i64(tcg_ctx, tmp, tcg_ctx->cpu_env, poff);

        poff = offsetof(CPUARMState, vfp.preg_tmp);
        tcg_gen_st_i64(tcg_ctx, tmp, tcg_ctx->cpu_env, poff);
        tcg_temp_free_i64(tcg_ctx, tmp);
    }

    t_pg = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, poff);

    fns[s->be_data == MO_BE][msz](tcg_ctx, tcg_ctx->cpu_env, t_pg, addr, t_desc);

    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_i32(tcg_ctx, t_desc);

    /* Replicate that first quadword.  */
    if (vsz > 16) {
        unsigned dofs = vec_full_reg_offset(s, zt);
        tcg_gen_gvec_dup_mem(tcg_ctx, 4, dofs + 16, dofs, vsz - 16, vsz - 16);
    }
}

static bool trans_LD1RQ_zprr(DisasContext *s, arg_rprr_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->rm == 31) {
        return false;
    }
    if (sve_access_check(s)) {
        int msz = dtype_msz(a->dtype);
        TCGv_i64 addr = new_tmp_a64(s);
        tcg_gen_shli_i64(tcg_ctx, addr, cpu_reg(s, a->rm), msz);
        tcg_gen_add_i64(tcg_ctx, addr, addr, cpu_reg_sp(s, a->rn));
        do_ldrq(s, a->rd, a->pg, addr, msz);
    }
    return true;
}

static bool trans_LD1RQ_zpri(DisasContext *s, arg_rpri_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (sve_access_check(s)) {
        TCGv_i64 addr = new_tmp_a64(s);
        tcg_gen_addi_i64(tcg_ctx, addr, cpu_reg_sp(s, a->rn), a->imm * 16);
        do_ldrq(s, a->rd, a->pg, addr, dtype_msz(a->dtype));
    }
    return true;
}

static void do_ldro(DisasContext *s, int zt, int pg, TCGv_i64 addr, int dtype)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    static gen_helper_gvec_mem * const fns[2][4] = {
        { gen_helper_sve_ld1bb_r,    gen_helper_sve_ld1hh_le_r,
          gen_helper_sve_ld1ss_le_r, gen_helper_sve_ld1dd_le_r },
        { gen_helper_sve_ld1bb_r,    gen_helper_sve_ld1hh_be_r,
          gen_helper_sve_ld1ss_be_r, gen_helper_sve_ld1dd_be_r },
    };
    static gen_helper_gvec_mem * const mte_fns[2][4] = {
        { gen_helper_sve_ld1bb_r_mte,    gen_helper_sve_ld1hh_le_r_mte,
          gen_helper_sve_ld1ss_le_r_mte, gen_helper_sve_ld1dd_le_r_mte },
        { gen_helper_sve_ld1bb_r_mte,    gen_helper_sve_ld1hh_be_r_mte,
          gen_helper_sve_ld1ss_be_r_mte, gen_helper_sve_ld1dd_be_r_mte },
    };
    unsigned vsz = vec_full_reg_size(s);
    unsigned vsz_r32;
    TCGv_ptr t_pg;
    TCGv_i32 t_desc;
    gen_helper_gvec_mem *fn;
    int desc, poff;
    unsigned dofs;

    if (vsz < 32) {
        unallocated_encoding(s);
        return;
    }

    desc = sve_memopidx(s, dtype);
    desc |= zt << MEMOPIDX_SHIFT;
    desc = simd_desc(32, 32, desc);
    t_desc = tcg_const_i32(tcg_ctx, desc);

    poff = pred_full_reg_offset(s, pg);
    if (vsz > 32) {
        TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);

#ifdef HOST_WORDS_BIGENDIAN
        poff += 4;
#endif
        tcg_gen_ld32u_i64(tcg_ctx, tmp, tcg_ctx->cpu_env, poff);

        poff = offsetof(CPUARMState, vfp.preg_tmp);
        tcg_gen_st_i64(tcg_ctx, tmp, tcg_ctx->cpu_env, poff);
        tcg_temp_free_i64(tcg_ctx, tmp);
    }

    t_pg = tcg_temp_new_ptr(tcg_ctx);
    if (s->mte_active[0]) {
        fn = mte_fns[s->be_data == MO_BE][dtype_msz(dtype)];
    } else {
        addr = sve_clean_data_tbi(s, addr);
        fn = fns[s->be_data == MO_BE][dtype_msz(dtype)];
    }
    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, poff);
    fn(tcg_ctx, tcg_ctx->cpu_env, t_pg, addr, t_desc);

    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_i32(tcg_ctx, t_desc);

    dofs = vec_full_reg_offset(s, zt);
    vsz_r32 = QEMU_ALIGN_DOWN(vsz, 32);
    if (vsz >= 64) {
        unsigned off;

        for (off = 32; off < vsz_r32; off += 32) {
            tcg_gen_gvec_dup_mem(tcg_ctx, 4, dofs + off, dofs, 16, 16);
            tcg_gen_gvec_dup_mem(tcg_ctx, 4, dofs + off + 16, dofs + 16,
                                 16, 16);
        }
    }
    vsz -= vsz_r32;
    if (vsz) {
        tcg_gen_gvec_dup_imm(tcg_ctx, MO_64, dofs + vsz_r32, vsz, vsz, 0);
    }
}

static bool trans_LD1RO_zprr(DisasContext *s, arg_rprr_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_f64mm, s)) {
        return false;
    }
    if (a->rm == 31) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        TCGv_i64 addr = new_tmp_a64(s);
        tcg_gen_shli_i64(tcg_ctx, addr, cpu_reg(s, a->rm),
                         dtype_msz(a->dtype));
        tcg_gen_add_i64(tcg_ctx, addr, addr, cpu_reg_sp(s, a->rn));
        do_ldro(s, a->rd, a->pg, addr, a->dtype);
    }
    return true;
}

static bool trans_LD1RO_zpri(DisasContext *s, arg_rpri_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (!dc_isar_feature(aa64_sve_f64mm, s)) {
        return false;
    }
    if (sve_nonstreaming_access_check(s)) {
        TCGv_i64 addr = new_tmp_a64(s);
        tcg_gen_addi_i64(tcg_ctx, addr, cpu_reg_sp(s, a->rn), a->imm * 32);
        do_ldro(s, a->rd, a->pg, addr, a->dtype);
    }
    return true;
}

/* Load and broadcast element.  */
static bool trans_LD1R_zpri(DisasContext *s, arg_rpri_load *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (!sve_access_check(s)) {
        return true;
    }

    unsigned vsz = vec_full_reg_size(s);
    unsigned psz = pred_full_reg_size(s);
    unsigned esz = dtype_esz[a->dtype];
    unsigned msz = dtype_msz(a->dtype);
    TCGLabel *over = gen_new_label(tcg_ctx);
    TCGv_i64 temp;

    /* If the guarding predicate has no bits set, no load occurs.  */
    if (psz <= 8) {
        /* Reduce the pred_esz_masks value simply to reduce the
         * size of the code generated here.
         */
        uint64_t psz_mask = MAKE_64BIT_MASK(0, psz * 8);
        temp = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_ld_i64(tcg_ctx, temp, tcg_ctx->cpu_env, pred_full_reg_offset(s, a->pg));
        tcg_gen_andi_i64(tcg_ctx, temp, temp, pred_esz_masks[esz] & psz_mask);
        tcg_gen_brcondi_i64(tcg_ctx, TCG_COND_EQ, temp, 0, over);
        tcg_temp_free_i64(tcg_ctx, temp);
    } else {
        TCGv_i32 t32 = tcg_temp_new_i32(tcg_ctx);
        find_last_active(s, t32, esz, a->pg);
        tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_LT, t32, 0, over);
        tcg_temp_free_i32(tcg_ctx, t32);
    }

    /* Load the data.  */
    temp = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_addi_i64(tcg_ctx, temp, cpu_reg_sp(s, a->rn), a->imm << msz);
    tcg_gen_qemu_ld_i64(tcg_ctx, temp, temp, get_mem_index(s),
                        s->be_data | dtype_mop[a->dtype]);

    /* Broadcast to *all* elements.  */
    tcg_gen_gvec_dup_i64(tcg_ctx, esz, vec_full_reg_offset(s, a->rd),
                         vsz, vsz, temp);
    tcg_temp_free_i64(tcg_ctx, temp);

    /* Zero the inactive elements.  */
    gen_set_label(tcg_ctx, over);
    do_movz_zpz(s, a->rd, a->rd, a->pg, esz);
    return true;
}

static void do_st_zpa(DisasContext *s, int zt, int pg, TCGv_i64 addr,
                      int msz, int esz, int nreg)
{
    static gen_helper_gvec_mem * const fn_single[2][4][4] = {
        { { gen_helper_sve_st1bb_r,
            gen_helper_sve_st1bh_r,
            gen_helper_sve_st1bs_r,
            gen_helper_sve_st1bd_r },
          { NULL,
            gen_helper_sve_st1hh_le_r,
            gen_helper_sve_st1hs_le_r,
            gen_helper_sve_st1hd_le_r },
          { NULL, NULL,
            gen_helper_sve_st1ss_le_r,
            gen_helper_sve_st1sd_le_r },
          { NULL, NULL, NULL,
            gen_helper_sve_st1dd_le_r } },
        { { gen_helper_sve_st1bb_r,
            gen_helper_sve_st1bh_r,
            gen_helper_sve_st1bs_r,
            gen_helper_sve_st1bd_r },
          { NULL,
            gen_helper_sve_st1hh_be_r,
            gen_helper_sve_st1hs_be_r,
            gen_helper_sve_st1hd_be_r },
          { NULL, NULL,
            gen_helper_sve_st1ss_be_r,
            gen_helper_sve_st1sd_be_r },
          { NULL, NULL, NULL,
            gen_helper_sve_st1dd_be_r } },
    };
    static gen_helper_gvec_mem * const fn_multiple[2][3][4] = {
        { { gen_helper_sve_st2bb_r,
            gen_helper_sve_st2hh_le_r,
            gen_helper_sve_st2ss_le_r,
            gen_helper_sve_st2dd_le_r },
          { gen_helper_sve_st3bb_r,
            gen_helper_sve_st3hh_le_r,
            gen_helper_sve_st3ss_le_r,
            gen_helper_sve_st3dd_le_r },
          { gen_helper_sve_st4bb_r,
            gen_helper_sve_st4hh_le_r,
            gen_helper_sve_st4ss_le_r,
            gen_helper_sve_st4dd_le_r } },
        { { gen_helper_sve_st2bb_r,
            gen_helper_sve_st2hh_be_r,
            gen_helper_sve_st2ss_be_r,
            gen_helper_sve_st2dd_be_r },
          { gen_helper_sve_st3bb_r,
            gen_helper_sve_st3hh_be_r,
            gen_helper_sve_st3ss_be_r,
            gen_helper_sve_st3dd_be_r },
          { gen_helper_sve_st4bb_r,
            gen_helper_sve_st4hh_be_r,
            gen_helper_sve_st4ss_be_r,
            gen_helper_sve_st4dd_be_r } },
    };
    static gen_helper_gvec_mem * const mte_fn_single[2][4][4] = {
        { { gen_helper_sve_st1bb_r_mte,
            gen_helper_sve_st1bh_r_mte,
            gen_helper_sve_st1bs_r_mte,
            gen_helper_sve_st1bd_r_mte },
          { NULL,
            gen_helper_sve_st1hh_le_r_mte,
            gen_helper_sve_st1hs_le_r_mte,
            gen_helper_sve_st1hd_le_r_mte },
          { NULL, NULL,
            gen_helper_sve_st1ss_le_r_mte,
            gen_helper_sve_st1sd_le_r_mte },
          { NULL, NULL, NULL,
            gen_helper_sve_st1dd_le_r_mte } },
        { { gen_helper_sve_st1bb_r_mte,
            gen_helper_sve_st1bh_r_mte,
            gen_helper_sve_st1bs_r_mte,
            gen_helper_sve_st1bd_r_mte },
          { NULL,
            gen_helper_sve_st1hh_be_r_mte,
            gen_helper_sve_st1hs_be_r_mte,
            gen_helper_sve_st1hd_be_r_mte },
          { NULL, NULL,
            gen_helper_sve_st1ss_be_r_mte,
            gen_helper_sve_st1sd_be_r_mte },
          { NULL, NULL, NULL,
            gen_helper_sve_st1dd_be_r_mte } },
    };
    static gen_helper_gvec_mem * const mte_fn_multiple[2][3][4] = {
        { { gen_helper_sve_st2bb_r_mte,
            gen_helper_sve_st2hh_le_r_mte,
            gen_helper_sve_st2ss_le_r_mte,
            gen_helper_sve_st2dd_le_r_mte },
          { gen_helper_sve_st3bb_r_mte,
            gen_helper_sve_st3hh_le_r_mte,
            gen_helper_sve_st3ss_le_r_mte,
            gen_helper_sve_st3dd_le_r_mte },
          { gen_helper_sve_st4bb_r_mte,
            gen_helper_sve_st4hh_le_r_mte,
            gen_helper_sve_st4ss_le_r_mte,
            gen_helper_sve_st4dd_le_r_mte } },
        { { gen_helper_sve_st2bb_r_mte,
            gen_helper_sve_st2hh_be_r_mte,
            gen_helper_sve_st2ss_be_r_mte,
            gen_helper_sve_st2dd_be_r_mte },
          { gen_helper_sve_st3bb_r_mte,
            gen_helper_sve_st3hh_be_r_mte,
            gen_helper_sve_st3ss_be_r_mte,
            gen_helper_sve_st3dd_be_r_mte },
          { gen_helper_sve_st4bb_r_mte,
            gen_helper_sve_st4hh_be_r_mte,
            gen_helper_sve_st4ss_be_r_mte,
            gen_helper_sve_st4dd_be_r_mte } },
    };
    gen_helper_gvec_mem *fn;
    int be = s->be_data == MO_BE;

    if (nreg == 0) {
        /* ST1 */
        if (s->mte_active[0]) {
            fn = mte_fn_single[be][msz][esz];
        } else {
            fn = fn_single[be][msz][esz];
        }
    } else {
        /* ST2, ST3, ST4 -- msz == esz, enforced by encoding */
        assert(msz == esz);
        if (s->mte_active[0]) {
            fn = mte_fn_multiple[be][nreg - 1][msz];
        } else {
            fn = fn_multiple[be][nreg - 1][msz];
        }
    }
    assert(fn != NULL);
    do_mem_zpa(s, zt, pg, addr, msz_dtype(s, msz), s->mte_active[0], fn);
}

static bool trans_ST_zprr(DisasContext *s, arg_rprr_store *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->rm == 31 || a->msz > a->esz) {
        return false;
    }
    if (sve_access_check(s)) {
        TCGv_i64 addr = new_tmp_a64(s);
        tcg_gen_shli_i64(tcg_ctx, addr, cpu_reg(s, a->rm), a->msz);
        tcg_gen_add_i64(tcg_ctx, addr, addr, cpu_reg_sp(s, a->rn));
        do_st_zpa(s, a->rd, a->pg, addr, a->msz, a->esz, a->nreg);
    }
    return true;
}

static bool trans_ST_zpri(DisasContext *s, arg_rpri_store *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (a->msz > a->esz) {
        return false;
    }
    if (sve_access_check(s)) {
        int vsz = vec_full_reg_size(s);
        int elements = vsz >> a->esz;
        TCGv_i64 addr = new_tmp_a64(s);

        tcg_gen_addi_i64(tcg_ctx, addr, cpu_reg_sp(s, a->rn),
                         (a->imm * elements * (a->nreg + 1)) << a->msz);
        do_st_zpa(s, a->rd, a->pg, addr, a->msz, a->esz, a->nreg);
    }
    return true;
}

/*
 *** SVE gather loads / scatter stores
 */

static void do_mem_zpz(DisasContext *s, int zt, int pg, int zm,
                       int scale, TCGv_i64 scalar, int msz,
                       gen_helper_gvec_mem_scatter *fn)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vsz = vec_full_reg_size(s);
    TCGv_ptr t_zm = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_pg = tcg_temp_new_ptr(tcg_ctx);
    TCGv_ptr t_zt = tcg_temp_new_ptr(tcg_ctx);
    TCGv_i32 t_desc;
    int desc;

    desc = sve_memopidx(s, msz_dtype(s, msz));
    desc |= scale << MEMOPIDX_SHIFT;
    desc = simd_desc(vsz, vsz, desc);
    t_desc = tcg_const_i32(tcg_ctx, desc);

    tcg_gen_addi_ptr(tcg_ctx, t_pg, tcg_ctx->cpu_env, pred_full_reg_offset(s, pg));
    tcg_gen_addi_ptr(tcg_ctx, t_zm, tcg_ctx->cpu_env, vec_full_reg_offset(s, zm));
    tcg_gen_addi_ptr(tcg_ctx, t_zt, tcg_ctx->cpu_env, vec_full_reg_offset(s, zt));
    fn(tcg_ctx, tcg_ctx->cpu_env, t_zt, t_pg, t_zm, scalar, t_desc);

    tcg_temp_free_ptr(tcg_ctx, t_zt);
    tcg_temp_free_ptr(tcg_ctx, t_zm);
    tcg_temp_free_ptr(tcg_ctx, t_pg);
    tcg_temp_free_i32(tcg_ctx, t_desc);
}

/* Indexed by [be][ff][xs][u][msz].  */
static gen_helper_gvec_mem_scatter * const gather_load_fn32[2][2][2][2][3] = {
    /* Little-endian */
    { { { { gen_helper_sve_ldbss_zsu,
            gen_helper_sve_ldhss_le_zsu,
            NULL, },
          { gen_helper_sve_ldbsu_zsu,
            gen_helper_sve_ldhsu_le_zsu,
            gen_helper_sve_ldss_le_zsu, } },
        { { gen_helper_sve_ldbss_zss,
            gen_helper_sve_ldhss_le_zss,
            NULL, },
          { gen_helper_sve_ldbsu_zss,
            gen_helper_sve_ldhsu_le_zss,
            gen_helper_sve_ldss_le_zss, } } },

      /* First-fault */
      { { { gen_helper_sve_ldffbss_zsu,
            gen_helper_sve_ldffhss_le_zsu,
            NULL, },
          { gen_helper_sve_ldffbsu_zsu,
            gen_helper_sve_ldffhsu_le_zsu,
            gen_helper_sve_ldffss_le_zsu, } },
        { { gen_helper_sve_ldffbss_zss,
            gen_helper_sve_ldffhss_le_zss,
            NULL, },
          { gen_helper_sve_ldffbsu_zss,
            gen_helper_sve_ldffhsu_le_zss,
            gen_helper_sve_ldffss_le_zss, } } } },

    /* Big-endian */
    { { { { gen_helper_sve_ldbss_zsu,
            gen_helper_sve_ldhss_be_zsu,
            NULL, },
          { gen_helper_sve_ldbsu_zsu,
            gen_helper_sve_ldhsu_be_zsu,
            gen_helper_sve_ldss_be_zsu, } },
        { { gen_helper_sve_ldbss_zss,
            gen_helper_sve_ldhss_be_zss,
            NULL, },
          { gen_helper_sve_ldbsu_zss,
            gen_helper_sve_ldhsu_be_zss,
            gen_helper_sve_ldss_be_zss, } } },

      /* First-fault */
      { { { gen_helper_sve_ldffbss_zsu,
            gen_helper_sve_ldffhss_be_zsu,
            NULL, },
          { gen_helper_sve_ldffbsu_zsu,
            gen_helper_sve_ldffhsu_be_zsu,
            gen_helper_sve_ldffss_be_zsu, } },
        { { gen_helper_sve_ldffbss_zss,
            gen_helper_sve_ldffhss_be_zss,
            NULL, },
          { gen_helper_sve_ldffbsu_zss,
            gen_helper_sve_ldffhsu_be_zss,
            gen_helper_sve_ldffss_be_zss, } } } },
};

/* Note that we overload xs=2 to indicate 64-bit offset.  */
static gen_helper_gvec_mem_scatter * const gather_load_fn64[2][2][3][2][4] = {
    /* Little-endian */
    { { { { gen_helper_sve_ldbds_zsu,
            gen_helper_sve_ldhds_le_zsu,
            gen_helper_sve_ldsds_le_zsu,
            NULL, },
          { gen_helper_sve_ldbdu_zsu,
            gen_helper_sve_ldhdu_le_zsu,
            gen_helper_sve_ldsdu_le_zsu,
            gen_helper_sve_lddd_le_zsu, } },
        { { gen_helper_sve_ldbds_zss,
            gen_helper_sve_ldhds_le_zss,
            gen_helper_sve_ldsds_le_zss,
            NULL, },
          { gen_helper_sve_ldbdu_zss,
            gen_helper_sve_ldhdu_le_zss,
            gen_helper_sve_ldsdu_le_zss,
            gen_helper_sve_lddd_le_zss, } },
        { { gen_helper_sve_ldbds_zd,
            gen_helper_sve_ldhds_le_zd,
            gen_helper_sve_ldsds_le_zd,
            NULL, },
          { gen_helper_sve_ldbdu_zd,
            gen_helper_sve_ldhdu_le_zd,
            gen_helper_sve_ldsdu_le_zd,
            gen_helper_sve_lddd_le_zd, } } },

      /* First-fault */
      { { { gen_helper_sve_ldffbds_zsu,
            gen_helper_sve_ldffhds_le_zsu,
            gen_helper_sve_ldffsds_le_zsu,
            NULL, },
          { gen_helper_sve_ldffbdu_zsu,
            gen_helper_sve_ldffhdu_le_zsu,
            gen_helper_sve_ldffsdu_le_zsu,
            gen_helper_sve_ldffdd_le_zsu, } },
        { { gen_helper_sve_ldffbds_zss,
            gen_helper_sve_ldffhds_le_zss,
            gen_helper_sve_ldffsds_le_zss,
            NULL, },
          { gen_helper_sve_ldffbdu_zss,
            gen_helper_sve_ldffhdu_le_zss,
            gen_helper_sve_ldffsdu_le_zss,
            gen_helper_sve_ldffdd_le_zss, } },
        { { gen_helper_sve_ldffbds_zd,
            gen_helper_sve_ldffhds_le_zd,
            gen_helper_sve_ldffsds_le_zd,
            NULL, },
          { gen_helper_sve_ldffbdu_zd,
            gen_helper_sve_ldffhdu_le_zd,
            gen_helper_sve_ldffsdu_le_zd,
            gen_helper_sve_ldffdd_le_zd, } } } },

    /* Big-endian */
    { { { { gen_helper_sve_ldbds_zsu,
            gen_helper_sve_ldhds_be_zsu,
            gen_helper_sve_ldsds_be_zsu,
            NULL, },
          { gen_helper_sve_ldbdu_zsu,
            gen_helper_sve_ldhdu_be_zsu,
            gen_helper_sve_ldsdu_be_zsu,
            gen_helper_sve_lddd_be_zsu, } },
        { { gen_helper_sve_ldbds_zss,
            gen_helper_sve_ldhds_be_zss,
            gen_helper_sve_ldsds_be_zss,
            NULL, },
          { gen_helper_sve_ldbdu_zss,
            gen_helper_sve_ldhdu_be_zss,
            gen_helper_sve_ldsdu_be_zss,
            gen_helper_sve_lddd_be_zss, } },
        { { gen_helper_sve_ldbds_zd,
            gen_helper_sve_ldhds_be_zd,
            gen_helper_sve_ldsds_be_zd,
            NULL, },
          { gen_helper_sve_ldbdu_zd,
            gen_helper_sve_ldhdu_be_zd,
            gen_helper_sve_ldsdu_be_zd,
            gen_helper_sve_lddd_be_zd, } } },

      /* First-fault */
      { { { gen_helper_sve_ldffbds_zsu,
            gen_helper_sve_ldffhds_be_zsu,
            gen_helper_sve_ldffsds_be_zsu,
            NULL, },
          { gen_helper_sve_ldffbdu_zsu,
            gen_helper_sve_ldffhdu_be_zsu,
            gen_helper_sve_ldffsdu_be_zsu,
            gen_helper_sve_ldffdd_be_zsu, } },
        { { gen_helper_sve_ldffbds_zss,
            gen_helper_sve_ldffhds_be_zss,
            gen_helper_sve_ldffsds_be_zss,
            NULL, },
          { gen_helper_sve_ldffbdu_zss,
            gen_helper_sve_ldffhdu_be_zss,
            gen_helper_sve_ldffsdu_be_zss,
            gen_helper_sve_ldffdd_be_zss, } },
        { { gen_helper_sve_ldffbds_zd,
            gen_helper_sve_ldffhds_be_zd,
            gen_helper_sve_ldffsds_be_zd,
            NULL, },
          { gen_helper_sve_ldffbdu_zd,
            gen_helper_sve_ldffhdu_be_zd,
            gen_helper_sve_ldffsdu_be_zd,
            gen_helper_sve_ldffdd_be_zd, } } } },
};

/* Indexed by [be][xs][u][msz].  */
static gen_helper_gvec_mem_scatter * const
gather_ld_mte_fn32[2][2][2][3] = {
    /* Little-endian */
    { { { gen_helper_sve_ldbss_zsu_mte,
          gen_helper_sve_ldhss_le_zsu_mte,
          NULL, },
        { gen_helper_sve_ldbsu_zsu_mte,
          gen_helper_sve_ldhsu_le_zsu_mte,
          gen_helper_sve_ldss_le_zsu_mte, } },
      { { gen_helper_sve_ldbss_zss_mte,
          gen_helper_sve_ldhss_le_zss_mte,
          NULL, },
        { gen_helper_sve_ldbsu_zss_mte,
          gen_helper_sve_ldhsu_le_zss_mte,
          gen_helper_sve_ldss_le_zss_mte, } } },

    /* Big-endian */
    { { { gen_helper_sve_ldbss_zsu_mte,
          gen_helper_sve_ldhss_be_zsu_mte,
          NULL, },
        { gen_helper_sve_ldbsu_zsu_mte,
          gen_helper_sve_ldhsu_be_zsu_mte,
          gen_helper_sve_ldss_be_zsu_mte, } },
      { { gen_helper_sve_ldbss_zss_mte,
          gen_helper_sve_ldhss_be_zss_mte,
          NULL, },
        { gen_helper_sve_ldbsu_zss_mte,
          gen_helper_sve_ldhsu_be_zss_mte,
          gen_helper_sve_ldss_be_zss_mte, } } },
};

/* Indexed by [be][xs][u][msz].  */
static gen_helper_gvec_mem_scatter * const
gather_ld_mte_fn64[2][3][2][4] = {
    /* Little-endian */
    { { { gen_helper_sve_ldbds_zsu_mte,
          gen_helper_sve_ldhds_le_zsu_mte,
          gen_helper_sve_ldsds_le_zsu_mte,
          NULL, },
        { gen_helper_sve_ldbdu_zsu_mte,
          gen_helper_sve_ldhdu_le_zsu_mte,
          gen_helper_sve_ldsdu_le_zsu_mte,
          gen_helper_sve_lddd_le_zsu_mte, } },
      { { gen_helper_sve_ldbds_zss_mte,
          gen_helper_sve_ldhds_le_zss_mte,
          gen_helper_sve_ldsds_le_zss_mte,
          NULL, },
        { gen_helper_sve_ldbdu_zss_mte,
          gen_helper_sve_ldhdu_le_zss_mte,
          gen_helper_sve_ldsdu_le_zss_mte,
          gen_helper_sve_lddd_le_zss_mte, } },
      { { gen_helper_sve_ldbds_zd_mte,
          gen_helper_sve_ldhds_le_zd_mte,
          gen_helper_sve_ldsds_le_zd_mte,
          NULL, },
        { gen_helper_sve_ldbdu_zd_mte,
          gen_helper_sve_ldhdu_le_zd_mte,
          gen_helper_sve_ldsdu_le_zd_mte,
          gen_helper_sve_lddd_le_zd_mte, } } },

    /* Big-endian */
    { { { gen_helper_sve_ldbds_zsu_mte,
          gen_helper_sve_ldhds_be_zsu_mte,
          gen_helper_sve_ldsds_be_zsu_mte,
          NULL, },
        { gen_helper_sve_ldbdu_zsu_mte,
          gen_helper_sve_ldhdu_be_zsu_mte,
          gen_helper_sve_ldsdu_be_zsu_mte,
          gen_helper_sve_lddd_be_zsu_mte, } },
      { { gen_helper_sve_ldbds_zss_mte,
          gen_helper_sve_ldhds_be_zss_mte,
          gen_helper_sve_ldsds_be_zss_mte,
          NULL, },
        { gen_helper_sve_ldbdu_zss_mte,
          gen_helper_sve_ldhdu_be_zss_mte,
          gen_helper_sve_ldsdu_be_zss_mte,
          gen_helper_sve_lddd_be_zss_mte, } },
      { { gen_helper_sve_ldbds_zd_mte,
          gen_helper_sve_ldhds_be_zd_mte,
          gen_helper_sve_ldsds_be_zd_mte,
          NULL, },
        { gen_helper_sve_ldbdu_zd_mte,
          gen_helper_sve_ldhdu_be_zd_mte,
          gen_helper_sve_ldsdu_be_zd_mte,
          gen_helper_sve_lddd_be_zd_mte, } } },
};

/* Indexed by [be][xs][u][msz].  */
static gen_helper_gvec_mem_scatter * const
gather_ldff_mte_fn32[2][2][2][3] = {
    /* Little-endian */
    { { { gen_helper_sve_ldffbss_zsu_mte,
          gen_helper_sve_ldffhss_le_zsu_mte,
          NULL, },
        { gen_helper_sve_ldffbsu_zsu_mte,
          gen_helper_sve_ldffhsu_le_zsu_mte,
          gen_helper_sve_ldffss_le_zsu_mte, } },
      { { gen_helper_sve_ldffbss_zss_mte,
          gen_helper_sve_ldffhss_le_zss_mte,
          NULL, },
        { gen_helper_sve_ldffbsu_zss_mte,
          gen_helper_sve_ldffhsu_le_zss_mte,
          gen_helper_sve_ldffss_le_zss_mte, } } },

    /* Big-endian */
    { { { gen_helper_sve_ldffbss_zsu_mte,
          gen_helper_sve_ldffhss_be_zsu_mte,
          NULL, },
        { gen_helper_sve_ldffbsu_zsu_mte,
          gen_helper_sve_ldffhsu_be_zsu_mte,
          gen_helper_sve_ldffss_be_zsu_mte, } },
      { { gen_helper_sve_ldffbss_zss_mte,
          gen_helper_sve_ldffhss_be_zss_mte,
          NULL, },
        { gen_helper_sve_ldffbsu_zss_mte,
          gen_helper_sve_ldffhsu_be_zss_mte,
          gen_helper_sve_ldffss_be_zss_mte, } } },
};

/* Indexed by [be][xs][u][msz].  */
static gen_helper_gvec_mem_scatter * const
gather_ldff_mte_fn64[2][3][2][4] = {
    /* Little-endian */
    { { { gen_helper_sve_ldffbds_zsu_mte,
          gen_helper_sve_ldffhds_le_zsu_mte,
          gen_helper_sve_ldffsds_le_zsu_mte,
          NULL, },
        { gen_helper_sve_ldffbdu_zsu_mte,
          gen_helper_sve_ldffhdu_le_zsu_mte,
          gen_helper_sve_ldffsdu_le_zsu_mte,
          gen_helper_sve_ldffdd_le_zsu_mte, } },
      { { gen_helper_sve_ldffbds_zss_mte,
          gen_helper_sve_ldffhds_le_zss_mte,
          gen_helper_sve_ldffsds_le_zss_mte,
          NULL, },
        { gen_helper_sve_ldffbdu_zss_mte,
          gen_helper_sve_ldffhdu_le_zss_mte,
          gen_helper_sve_ldffsdu_le_zss_mte,
          gen_helper_sve_ldffdd_le_zss_mte, } },
      { { gen_helper_sve_ldffbds_zd_mte,
          gen_helper_sve_ldffhds_le_zd_mte,
          gen_helper_sve_ldffsds_le_zd_mte,
          NULL, },
        { gen_helper_sve_ldffbdu_zd_mte,
          gen_helper_sve_ldffhdu_le_zd_mte,
          gen_helper_sve_ldffsdu_le_zd_mte,
          gen_helper_sve_ldffdd_le_zd_mte, } } },

    /* Big-endian */
    { { { gen_helper_sve_ldffbds_zsu_mte,
          gen_helper_sve_ldffhds_be_zsu_mte,
          gen_helper_sve_ldffsds_be_zsu_mte,
          NULL, },
        { gen_helper_sve_ldffbdu_zsu_mte,
          gen_helper_sve_ldffhdu_be_zsu_mte,
          gen_helper_sve_ldffsdu_be_zsu_mte,
          gen_helper_sve_ldffdd_be_zsu_mte, } },
      { { gen_helper_sve_ldffbds_zss_mte,
          gen_helper_sve_ldffhds_be_zss_mte,
          gen_helper_sve_ldffsds_be_zss_mte,
          NULL, },
        { gen_helper_sve_ldffbdu_zss_mte,
          gen_helper_sve_ldffhdu_be_zss_mte,
          gen_helper_sve_ldffsdu_be_zss_mte,
          gen_helper_sve_ldffdd_be_zss_mte, } },
      { { gen_helper_sve_ldffbds_zd_mte,
          gen_helper_sve_ldffhds_be_zd_mte,
          gen_helper_sve_ldffsds_be_zd_mte,
          NULL, },
        { gen_helper_sve_ldffbdu_zd_mte,
          gen_helper_sve_ldffhdu_be_zd_mte,
          gen_helper_sve_ldffsdu_be_zd_mte,
          gen_helper_sve_ldffdd_be_zd_mte, } } },
};

static bool trans_LD1_zprz(DisasContext *s, arg_LD1_zprz *a)
{
    gen_helper_gvec_mem_scatter *fn = NULL;
    int be = s->be_data == MO_BE;

    if (!sve_nonstreaming_access_check(s)) {
        return true;
    }

    switch (a->esz) {
    case MO_32:
        if (s->mte_active[0]) {
            fn = a->ff ? gather_ldff_mte_fn32[be][a->xs][a->u][a->msz]
                       : gather_ld_mte_fn32[be][a->xs][a->u][a->msz];
        } else {
            fn = gather_load_fn32[be][a->ff][a->xs][a->u][a->msz];
        }
        break;
    case MO_64:
        if (s->mte_active[0]) {
            fn = a->ff ? gather_ldff_mte_fn64[be][a->xs][a->u][a->msz]
                       : gather_ld_mte_fn64[be][a->xs][a->u][a->msz];
        } else {
            fn = gather_load_fn64[be][a->ff][a->xs][a->u][a->msz];
        }
        break;
    }
    assert(fn != NULL);

    do_mem_zpz(s, a->rd, a->pg, a->rm, a->scale * a->msz,
               cpu_reg_sp(s, a->rn), a->msz, fn);
    return true;
}

static bool trans_LD1_zpiz(DisasContext *s, arg_LD1_zpiz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_helper_gvec_mem_scatter *fn = NULL;
    int be = s->be_data == MO_BE;
    TCGv_i64 imm;

    if (a->esz < a->msz || (a->esz == a->msz && !a->u)) {
        return false;
    }
    if (!sve_nonstreaming_access_check(s)) {
        return true;
    }

    switch (a->esz) {
    case MO_32:
        if (s->mte_active[0]) {
            fn = a->ff ? gather_ldff_mte_fn32[be][0][a->u][a->msz]
                       : gather_ld_mte_fn32[be][0][a->u][a->msz];
        } else {
            fn = gather_load_fn32[be][a->ff][0][a->u][a->msz];
        }
        break;
    case MO_64:
        if (s->mte_active[0]) {
            fn = a->ff ? gather_ldff_mte_fn64[be][2][a->u][a->msz]
                       : gather_ld_mte_fn64[be][2][a->u][a->msz];
        } else {
            fn = gather_load_fn64[be][a->ff][2][a->u][a->msz];
        }
        break;
    }
    assert(fn != NULL);

    /* Treat LD1_zpiz (zn[x] + imm) the same way as LD1_zprz (rn + zm[x])
     * by loading the immediate into the scalar parameter.
     */
    imm = tcg_const_i64(tcg_ctx, a->imm << a->msz);
    do_mem_zpz(s, a->rd, a->pg, a->rn, 0, imm, a->msz, fn);
    tcg_temp_free_i64(tcg_ctx, imm);
    return true;
}

static bool trans_LDNT1_zprz(DisasContext *s, arg_LD1_zprz *a)
{
    gen_helper_gvec_mem_scatter *fn = NULL;
    int be = s->be_data == MO_BE;

    if (a->esz < a->msz + !a->u) {
        return false;
    }
    if (!sve_nonstreaming_access_check(s)) {
        return true;
    }

    switch (a->esz) {
    case MO_32:
        if (s->mte_active[0]) {
            fn = gather_ld_mte_fn32[be][0][a->u][a->msz];
        } else {
            fn = gather_load_fn32[be][0][0][a->u][a->msz];
        }
        break;
    case MO_64:
        if (s->mte_active[0]) {
            fn = gather_ld_mte_fn64[be][2][a->u][a->msz];
        } else {
            fn = gather_load_fn64[be][0][2][a->u][a->msz];
        }
        break;
    }
    assert(fn != NULL);

    do_mem_zpz(s, a->rd, a->pg, a->rn, 0,
               cpu_reg(s, a->rm), a->msz, fn);
    return true;
}

/* Indexed by [be][xs][msz].  */
static gen_helper_gvec_mem_scatter * const scatter_store_fn32[2][2][3] = {
    /* Little-endian */
    { { gen_helper_sve_stbs_zsu,
        gen_helper_sve_sths_le_zsu,
        gen_helper_sve_stss_le_zsu, },
      { gen_helper_sve_stbs_zss,
        gen_helper_sve_sths_le_zss,
        gen_helper_sve_stss_le_zss, } },
    /* Big-endian */
    { { gen_helper_sve_stbs_zsu,
        gen_helper_sve_sths_be_zsu,
        gen_helper_sve_stss_be_zsu, },
      { gen_helper_sve_stbs_zss,
        gen_helper_sve_sths_be_zss,
        gen_helper_sve_stss_be_zss, } },
};

/* Indexed by [be][xs][msz].  */
static gen_helper_gvec_mem_scatter * const scatter_store_mte_fn32[2][2][3] = {
    /* Little-endian */
    { { gen_helper_sve_stbs_zsu_mte,
        gen_helper_sve_sths_le_zsu_mte,
        gen_helper_sve_stss_le_zsu_mte, },
      { gen_helper_sve_stbs_zss_mte,
        gen_helper_sve_sths_le_zss_mte,
        gen_helper_sve_stss_le_zss_mte, } },
    /* Big-endian */
    { { gen_helper_sve_stbs_zsu_mte,
        gen_helper_sve_sths_be_zsu_mte,
        gen_helper_sve_stss_be_zsu_mte, },
      { gen_helper_sve_stbs_zss_mte,
        gen_helper_sve_sths_be_zss_mte,
        gen_helper_sve_stss_be_zss_mte, } },
};

/* Note that we overload xs=2 to indicate 64-bit offset.  */
static gen_helper_gvec_mem_scatter * const scatter_store_fn64[2][3][4] = {
    /* Little-endian */
    { { gen_helper_sve_stbd_zsu,
        gen_helper_sve_sthd_le_zsu,
        gen_helper_sve_stsd_le_zsu,
        gen_helper_sve_stdd_le_zsu, },
      { gen_helper_sve_stbd_zss,
        gen_helper_sve_sthd_le_zss,
        gen_helper_sve_stsd_le_zss,
        gen_helper_sve_stdd_le_zss, },
      { gen_helper_sve_stbd_zd,
        gen_helper_sve_sthd_le_zd,
        gen_helper_sve_stsd_le_zd,
        gen_helper_sve_stdd_le_zd, } },
    /* Big-endian */
    { { gen_helper_sve_stbd_zsu,
        gen_helper_sve_sthd_be_zsu,
        gen_helper_sve_stsd_be_zsu,
        gen_helper_sve_stdd_be_zsu, },
      { gen_helper_sve_stbd_zss,
        gen_helper_sve_sthd_be_zss,
        gen_helper_sve_stsd_be_zss,
        gen_helper_sve_stdd_be_zss, },
      { gen_helper_sve_stbd_zd,
        gen_helper_sve_sthd_be_zd,
        gen_helper_sve_stsd_be_zd,
        gen_helper_sve_stdd_be_zd, } },
};

/* Note that we overload xs=2 to indicate 64-bit offset.  */
static gen_helper_gvec_mem_scatter * const scatter_store_mte_fn64[2][3][4] = {
    /* Little-endian */
    { { gen_helper_sve_stbd_zsu_mte,
        gen_helper_sve_sthd_le_zsu_mte,
        gen_helper_sve_stsd_le_zsu_mte,
        gen_helper_sve_stdd_le_zsu_mte, },
      { gen_helper_sve_stbd_zss_mte,
        gen_helper_sve_sthd_le_zss_mte,
        gen_helper_sve_stsd_le_zss_mte,
        gen_helper_sve_stdd_le_zss_mte, },
      { gen_helper_sve_stbd_zd_mte,
        gen_helper_sve_sthd_le_zd_mte,
        gen_helper_sve_stsd_le_zd_mte,
        gen_helper_sve_stdd_le_zd_mte, } },
    /* Big-endian */
    { { gen_helper_sve_stbd_zsu_mte,
        gen_helper_sve_sthd_be_zsu_mte,
        gen_helper_sve_stsd_be_zsu_mte,
        gen_helper_sve_stdd_be_zsu_mte, },
      { gen_helper_sve_stbd_zss_mte,
        gen_helper_sve_sthd_be_zss_mte,
        gen_helper_sve_stsd_be_zss_mte,
        gen_helper_sve_stdd_be_zss_mte, },
      { gen_helper_sve_stbd_zd_mte,
        gen_helper_sve_sthd_be_zd_mte,
        gen_helper_sve_stsd_be_zd_mte,
        gen_helper_sve_stdd_be_zd_mte, } },
};

static bool trans_ST1_zprz(DisasContext *s, arg_ST1_zprz *a)
{
    gen_helper_gvec_mem_scatter *fn = NULL;
    int be = s->be_data == MO_BE;

    if (a->esz < a->msz || (a->msz == 0 && a->scale)) {
        return false;
    }
    if (!sve_nonstreaming_access_check(s)) {
        return true;
    }
    switch (a->esz) {
    case MO_32:
        if (s->mte_active[0]) {
            fn = scatter_store_mte_fn32[be][a->xs][a->msz];
        } else {
            fn = scatter_store_fn32[be][a->xs][a->msz];
        }
        break;
    case MO_64:
        if (s->mte_active[0]) {
            fn = scatter_store_mte_fn64[be][a->xs][a->msz];
        } else {
            fn = scatter_store_fn64[be][a->xs][a->msz];
        }
        break;
    default:
        g_assert_not_reached();
    }
    do_mem_zpz(s, a->rd, a->pg, a->rm, a->scale * a->msz,
               cpu_reg_sp(s, a->rn), a->msz, fn);
    return true;
}

static bool trans_ST1_zpiz(DisasContext *s, arg_ST1_zpiz *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_helper_gvec_mem_scatter *fn = NULL;
    int be = s->be_data == MO_BE;
    TCGv_i64 imm;

    if (a->esz < a->msz) {
        return false;
    }
    if (!sve_nonstreaming_access_check(s)) {
        return true;
    }

    switch (a->esz) {
    case MO_32:
        if (s->mte_active[0]) {
            fn = scatter_store_mte_fn32[be][0][a->msz];
        } else {
            fn = scatter_store_fn32[be][0][a->msz];
        }
        break;
    case MO_64:
        if (s->mte_active[0]) {
            fn = scatter_store_mte_fn64[be][2][a->msz];
        } else {
            fn = scatter_store_fn64[be][2][a->msz];
        }
        break;
    }
    assert(fn != NULL);

    /* Treat ST1_zpiz (zn[x] + imm) the same way as ST1_zprz (rn + zm[x])
     * by loading the immediate into the scalar parameter.
     */
    imm = tcg_const_i64(tcg_ctx, a->imm << a->msz);
    do_mem_zpz(s, a->rd, a->pg, a->rn, 0, imm, a->msz, fn);
    tcg_temp_free_i64(tcg_ctx, imm);
    return true;
}

static bool trans_STNT1_zprz(DisasContext *s, arg_ST1_zprz *a)
{
    gen_helper_gvec_mem_scatter *fn = NULL;
    int be = s->be_data == MO_BE;

    if (a->esz < a->msz) {
        return false;
    }
    if (!sve_nonstreaming_access_check(s)) {
        return true;
    }

    switch (a->esz) {
    case MO_32:
        if (s->mte_active[0]) {
            fn = scatter_store_mte_fn32[be][0][a->msz];
        } else {
            fn = scatter_store_fn32[be][0][a->msz];
        }
        break;
    case MO_64:
        if (s->mte_active[0]) {
            fn = scatter_store_mte_fn64[be][2][a->msz];
        } else {
            fn = scatter_store_fn64[be][2][a->msz];
        }
        break;
    default:
        g_assert_not_reached();
    }
    assert(fn != NULL);

    do_mem_zpz(s, a->rd, a->pg, a->rn, 0,
               cpu_reg(s, a->rm), a->msz, fn);
    return true;
}

/*
 * Prefetches
 */

static bool sve_prf_is_nonstreaming(uint32_t insn)
{
    uint32_t op = extract32(insn, 25, 7);
    bool scalar_offsets;
    bool vector_imm;

    if (op != 0x42 && op != 0x62) {
        return false;
    }

    scalar_offsets = extract32(insn, 23, 2) == 0 &&
                     extract32(insn, 21, 1);
    vector_imm = extract32(insn, 21, 2) == 0 &&
                 extract32(insn, 13, 3) == 7;

    return scalar_offsets || vector_imm;
}

static bool trans_PRF(DisasContext *s, arg_PRF *a)
{
    /* Prefetch is a nop within QEMU.  */
    if (sve_prf_is_nonstreaming(s->insn)) {
        s->is_nonstreaming = true;
    }
    (void)sve_access_check(s);
    return true;
}

static bool trans_PRF_rr(DisasContext *s, arg_PRF_rr *a)
{
    if (a->rm == 31) {
        return false;
    }
    /* Prefetch is a nop within QEMU.  */
    (void)sve_access_check(s);
    return true;
}

/*
 * Move Prefix
 *
 * TODO: The implementation so far could handle predicated merging movprfx.
 * The helper functions as written take an extra source register to
 * use in the operation, but the result is only written when predication
 * succeeds.  For unpredicated movprfx, we need to rearrange the helpers
 * to allow the final write back to the destination to be unconditional.
 * For predicated zeroing movprfx, we need to rearrange the helpers to
 * allow the final write back to zero inactives.
 *
 * In the meantime, just emit the moves.
 */

static bool trans_MOVPRFX(DisasContext *s, arg_MOVPRFX *a)
{
    return do_mov_z(s, a->rd, a->rn);
}

static bool trans_MOVPRFX_m(DisasContext *s, arg_rpr_esz *a)
{
    if (sve_access_check(s)) {
        do_sel_z(s, a->rd, a->rn, a->rd, a->pg, a->esz);
    }
    return true;
}

static bool trans_MOVPRFX_z(DisasContext *s, arg_rpr_esz *a)
{
    if (sve_access_check(s)) {
        do_movz_zpz(s, a->rd, a->rn, a->pg, a->esz);
    }
    return true;
}
