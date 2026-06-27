/*
 * M-profile MVE Operations
 *
 * Copyright (c) 2021 Linaro, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include "internals.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "fpu/softfloat.h"

#define H1(x) (x)
#define H2(x) (x)
#define H4(x) (x)
#define H8(x) (x)

static uint64_t mve_expand_pred_b(uint8_t mask)
{
    uint64_t ret = 0;
    int i;

    for (i = 0; i < 8; i++) {
        if (mask & (1U << i)) {
            ret |= 0xffULL << (i * 8);
        }
    }

    return ret;
}

static void mve_mergemask_ub(uint8_t *d, uint8_t r, uint8_t mask)
{
    if (mask & 1) {
        *d = r;
    }
}

static void mve_mergemask_uh(uint16_t *d, uint16_t r, uint8_t mask)
{
    uint16_t bmask = (uint16_t)mve_expand_pred_b(mask);

    *d = (*d & ~bmask) | (r & bmask);
}

static void mve_mergemask_uw(uint32_t *d, uint32_t r, uint8_t mask)
{
    uint32_t bmask = (uint32_t)mve_expand_pred_b(mask);

    *d = (*d & ~bmask) | (r & bmask);
}

static void mve_mergemask_uq(uint64_t *d, uint64_t r, uint8_t mask)
{
    uint64_t bmask = mve_expand_pred_b(mask);

    *d = (*d & ~bmask) | (r & bmask);
}

static void mve_mergemask_sb(int8_t *d, int8_t r, uint8_t mask)
{
    mve_mergemask_ub((uint8_t *)d, (uint8_t)r, mask);
}

static void mve_mergemask_sh(int16_t *d, int16_t r, uint8_t mask)
{
    mve_mergemask_uh((uint16_t *)d, (uint16_t)r, mask);
}

static void mve_mergemask_sw(int32_t *d, int32_t r, uint8_t mask)
{
    mve_mergemask_uw((uint32_t *)d, (uint32_t)r, mask);
}

static void mve_mergemask_sq(int64_t *d, int64_t r, uint8_t mask)
{
    mve_mergemask_uq((uint64_t *)d, (uint64_t)r, mask);
}

static uint16_t mve_eci_mask(CPUARMState *env)
{
    int eci;

    if ((env->condexec_bits & 0xf) != 0) {
        return 0xffff;
    }

    eci = env->condexec_bits >> 4;
    switch (eci) {
    case ECI_NONE:
        return 0xffff;
    case ECI_A0:
        return 0xfff0;
    case ECI_A0A1:
        return 0xff00;
    case ECI_A0A1A2:
    case ECI_A0A1A2B0:
        return 0xf000;
    default:
        g_assert_not_reached();
    }

    return 0;
}

static uint16_t mve_element_mask(CPUARMState *env)
{
    uint16_t mask = FIELD_EX32(env->v7m.vpr, V7M_VPR, P0);

    if (!(env->v7m.vpr & R_V7M_VPR_MASK01_MASK)) {
        mask |= 0xff;
    }
    if (!(env->v7m.vpr & R_V7M_VPR_MASK23_MASK)) {
        mask |= 0xff00;
    }

    if (env->v7m.ltpsize < 4 &&
        env->regs[14] <= (1 << (4 - env->v7m.ltpsize))) {
        int masklen = env->regs[14] << env->v7m.ltpsize;
        uint16_t ltpmask;

        assert(masklen <= 16);
        ltpmask = masklen ? MAKE_64BIT_MASK(0, masklen) : 0;
        mask &= ltpmask;
    }

    mask &= mve_eci_mask(env);
    return mask;
}

static void mve_advance_vpt(CPUARMState *env)
{
    uint32_t vpr = env->v7m.vpr;
    unsigned mask01;
    unsigned mask23;
    uint16_t inv_mask;
    uint16_t eci_mask = mve_eci_mask(env);

    if ((env->condexec_bits & 0xf) == 0) {
        env->condexec_bits = (env->condexec_bits == (ECI_A0A1A2B0 << 4)) ?
            (ECI_A0 << 4) : (ECI_NONE << 4);
    }

    if (!(vpr & ((uint32_t)R_V7M_VPR_MASK01_MASK |
                 (uint32_t)R_V7M_VPR_MASK23_MASK))) {
        return;
    }

    mask01 = FIELD_EX32(vpr, V7M_VPR, MASK01);
    mask23 = FIELD_EX32(vpr, V7M_VPR, MASK23);
    inv_mask = eci_mask;
    if (mask01 <= 8) {
        inv_mask &= ~0xff;
    }
    if (mask23 <= 8) {
        inv_mask &= ~0xff00;
    }
    vpr ^= inv_mask;
    if (eci_mask & 0xf0) {
        FIELD_DP32(vpr, V7M_VPR, MASK01, mask01 << 1, vpr);
    }
    FIELD_DP32(vpr, V7M_VPR, MASK23, mask23 << 1, vpr);
    env->v7m.vpr = vpr;
}

void HELPER(mve_vctp)(CPUARMState *env, uint32_t masklen)
{
    uint16_t mask = mve_element_mask(env);
    uint16_t eci_mask = mve_eci_mask(env);
    uint16_t newmask;

    assert(masklen <= 16);
    newmask = masklen ? MAKE_64BIT_MASK(0, masklen) : 0;
    newmask &= mask;
    env->v7m.vpr = (env->v7m.vpr & ~(uint32_t)eci_mask) |
                   (newmask & eci_mask);
    mve_advance_vpt(env);
}

void HELPER(mve_vpnot)(CPUARMState *env)
{
    uint16_t mask = mve_element_mask(env);
    uint16_t eci_mask = mve_eci_mask(env);
    uint16_t beatpred = ~env->v7m.vpr & mask;

    env->v7m.vpr = (env->v7m.vpr & ~(uint32_t)eci_mask) |
                   (beatpred & eci_mask);
    mve_advance_vpt(env);
}

void HELPER(mve_vdup)(CPUARMState *env, void *vd, uint32_t val)
{
    uint32_t *d = vd;
    uint16_t mask = mve_element_mask(env);
    unsigned e;

    for (e = 0; e < 16 / 4; e++, mask >>= 4) {
        mve_mergemask_uw(&d[H4(e)], val, mask);
    }
    mve_advance_vpt(env);
}

#define DO_VIDUP(OP, ESIZE, TYPE, MERGE, FN)                           \
    uint32_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,        \
                                    uint32_t offset, uint32_t imm)     \
    {                                                                  \
        TYPE *d = vd;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            MERGE(&d[glue(H, ESIZE)(e)], (TYPE)offset, mask);          \
            offset = FN(offset, imm);                                  \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return offset;                                                 \
    }

#define DO_VIWDUP(OP, ESIZE, TYPE, MERGE, FN)                          \
    uint32_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,        \
                                    uint32_t offset, uint32_t wrap,    \
                                    uint32_t imm)                      \
    {                                                                  \
        TYPE *d = vd;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            MERGE(&d[glue(H, ESIZE)(e)], (TYPE)offset, mask);          \
            offset = FN(offset, wrap, imm);                            \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return offset;                                                 \
    }

static uint32_t do_add_dup(uint32_t offset, uint32_t imm)
{
    return offset + imm;
}

static uint32_t do_add_wrap(uint32_t offset, uint32_t wrap, uint32_t imm)
{
    offset += imm;
    if (offset == wrap) {
        offset = 0;
    }
    return offset;
}

static uint32_t do_sub_wrap(uint32_t offset, uint32_t wrap, uint32_t imm)
{
    if (offset == 0) {
        offset = wrap;
    }
    offset -= imm;
    return offset;
}

DO_VIDUP(vidupb, 1, uint8_t, mve_mergemask_ub, do_add_dup)
DO_VIDUP(viduph, 2, uint16_t, mve_mergemask_uh, do_add_dup)
DO_VIDUP(vidupw, 4, uint32_t, mve_mergemask_uw, do_add_dup)
DO_VIWDUP(viwdupb, 1, uint8_t, mve_mergemask_ub, do_add_wrap)
DO_VIWDUP(viwduph, 2, uint16_t, mve_mergemask_uh, do_add_wrap)
DO_VIWDUP(viwdupw, 4, uint32_t, mve_mergemask_uw, do_add_wrap)
DO_VIWDUP(vdwdupb, 1, uint8_t, mve_mergemask_ub, do_sub_wrap)
DO_VIWDUP(vdwduph, 2, uint16_t, mve_mergemask_uh, do_sub_wrap)
DO_VIWDUP(vdwdupw, 4, uint32_t, mve_mergemask_uw, do_sub_wrap)

#define DO_VCMP(OP, ESIZE, TYPE, FN)                                    \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vn, void *vm)   \
    {                                                                   \
        TYPE *n = vn;                                                   \
        TYPE *m = vm;                                                   \
        uint16_t mask = mve_element_mask(env);                          \
        uint16_t eci_mask = mve_eci_mask(env);                          \
        uint16_t beatpred = 0;                                          \
        uint16_t emask = MAKE_64BIT_MASK(0, ESIZE);                     \
        unsigned e;                                                     \
                                                                        \
        for (e = 0; e < 16 / ESIZE; e++) {                              \
            bool r = FN(n[H##ESIZE(e)], m[H##ESIZE(e)]);                \
                                                                        \
            beatpred |= r * emask;                                      \
            emask <<= ESIZE;                                            \
        }                                                               \
        beatpred &= mask;                                               \
        env->v7m.vpr = (env->v7m.vpr & ~(uint32_t)eci_mask) |           \
            (beatpred & eci_mask);                                      \
        mve_advance_vpt(env);                                           \
    }

#define DO_VCMP_SCALAR(OP, ESIZE, TYPE, FN)                             \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vn,             \
                                uint32_t rm)                            \
    {                                                                   \
        TYPE *n = vn;                                                   \
        uint16_t mask = mve_element_mask(env);                          \
        uint16_t eci_mask = mve_eci_mask(env);                          \
        uint16_t beatpred = 0;                                          \
        uint16_t emask = MAKE_64BIT_MASK(0, ESIZE);                     \
        unsigned e;                                                     \
                                                                        \
        for (e = 0; e < 16 / ESIZE; e++) {                              \
            bool r = FN(n[H##ESIZE(e)], (TYPE)rm);                      \
                                                                        \
            beatpred |= r * emask;                                      \
            emask <<= ESIZE;                                            \
        }                                                               \
        beatpred &= mask;                                               \
        env->v7m.vpr = (env->v7m.vpr & ~(uint32_t)eci_mask) |           \
            (beatpred & eci_mask);                                      \
        mve_advance_vpt(env);                                           \
    }

#define DO_VCMP_S(OP, FN)                                               \
    DO_VCMP(OP##b, 1, int8_t, FN)                                       \
    DO_VCMP(OP##h, 2, int16_t, FN)                                      \
    DO_VCMP(OP##w, 4, int32_t, FN)                                      \
    DO_VCMP_SCALAR(OP##_scalarb, 1, int8_t, FN)                         \
    DO_VCMP_SCALAR(OP##_scalarh, 2, int16_t, FN)                        \
    DO_VCMP_SCALAR(OP##_scalarw, 4, int32_t, FN)

#define DO_VCMP_U(OP, FN)                                               \
    DO_VCMP(OP##b, 1, uint8_t, FN)                                      \
    DO_VCMP(OP##h, 2, uint16_t, FN)                                     \
    DO_VCMP(OP##w, 4, uint32_t, FN)                                     \
    DO_VCMP_SCALAR(OP##_scalarb, 1, uint8_t, FN)                        \
    DO_VCMP_SCALAR(OP##_scalarh, 2, uint16_t, FN)                       \
    DO_VCMP_SCALAR(OP##_scalarw, 4, uint32_t, FN)

#define DO_EQ(N, M) ((N) == (M))
#define DO_NE(N, M) ((N) != (M))
#define DO_GE(N, M) ((N) >= (M))
#define DO_LT(N, M) ((N) < (M))
#define DO_GT(N, M) ((N) > (M))
#define DO_LE(N, M) ((N) <= (M))

DO_VCMP_U(vcmpeq, DO_EQ)
DO_VCMP_U(vcmpne, DO_NE)
DO_VCMP_U(vcmpcs, DO_GE)
DO_VCMP_U(vcmphi, DO_GT)
DO_VCMP_S(vcmpge, DO_GE)
DO_VCMP_S(vcmplt, DO_LT)
DO_VCMP_S(vcmpgt, DO_GT)
DO_VCMP_S(vcmple, DO_LE)

#define DO_VCMP_FP(OP, ESIZE, TYPE, FN)                                \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vn, void *vm)  \
    {                                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        uint16_t eci_mask = mve_eci_mask(env);                         \
        uint16_t beatpred = 0;                                         \
        uint16_t emask = MAKE_64BIT_MASK(0, ESIZE);                    \
        unsigned e;                                                    \
        float_status *fpst;                                            \
        float_status scratch_fpst;                                     \
        bool r;                                                        \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, emask <<= ESIZE) {            \
            if ((mask & emask) == 0) {                                 \
                continue;                                              \
            }                                                          \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :   \
                &env->vfp.standard_fp_status;                          \
            if (!(mask & (1U << (e * ESIZE)))) {                       \
                scratch_fpst = *fpst;                                  \
                fpst = &scratch_fpst;                                  \
            }                                                          \
            r = FN(n[glue(H, ESIZE)(e)], m[glue(H, ESIZE)(e)], fpst);  \
            beatpred |= r * emask;                                     \
        }                                                              \
        beatpred &= mask;                                              \
        env->v7m.vpr = (env->v7m.vpr & ~(uint32_t)eci_mask) |          \
            (beatpred & eci_mask);                                     \
        mve_advance_vpt(env);                                          \
    }

#define DO_VCMP_FP_SCALAR(OP, ESIZE, TYPE, FN)                         \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vn,            \
                                uint32_t rm)                           \
    {                                                                  \
        TYPE *n = vn;                                                  \
        TYPE m = (TYPE)rm;                                             \
        uint16_t mask = mve_element_mask(env);                         \
        uint16_t eci_mask = mve_eci_mask(env);                         \
        uint16_t beatpred = 0;                                         \
        uint16_t emask = MAKE_64BIT_MASK(0, ESIZE);                    \
        unsigned e;                                                    \
        float_status *fpst;                                            \
        float_status scratch_fpst;                                     \
        bool r;                                                        \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, emask <<= ESIZE) {            \
            if ((mask & emask) == 0) {                                 \
                continue;                                              \
            }                                                          \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :   \
                &env->vfp.standard_fp_status;                          \
            if (!(mask & (1U << (e * ESIZE)))) {                       \
                scratch_fpst = *fpst;                                  \
                fpst = &scratch_fpst;                                  \
            }                                                          \
            r = FN(n[glue(H, ESIZE)(e)], m, fpst);                     \
            beatpred |= r * emask;                                     \
        }                                                              \
        beatpred &= mask;                                              \
        env->v7m.vpr = (env->v7m.vpr & ~(uint32_t)eci_mask) |          \
            (beatpred & eci_mask);                                     \
        mve_advance_vpt(env);                                          \
    }

#define DO_VCMP_FP_BOTH(VOP, SOP, ESIZE, TYPE, FN)                     \
    DO_VCMP_FP(VOP, ESIZE, TYPE, FN)                                   \
    DO_VCMP_FP_SCALAR(SOP, ESIZE, TYPE, FN)

#define DO_FEQ16(X, Y, S) (float16_compare(X, Y, S) == 0)
#define DO_FEQ32(X, Y, S) (float32_compare(X, Y, S) == 0)
#define DO_FLE16(X, Y, S) (float16_compare(X, Y, S) <= 0)
#define DO_FLE32(X, Y, S) (float32_compare(X, Y, S) <= 0)
#define DO_FLT16(X, Y, S) (float16_compare(X, Y, S) < 0)
#define DO_FLT32(X, Y, S) (float32_compare(X, Y, S) < 0)
#define DO_GE16(X, Y, S) DO_FLE16(Y, X, S)
#define DO_GE32(X, Y, S) DO_FLE32(Y, X, S)
#define DO_GT16(X, Y, S) DO_FLT16(Y, X, S)
#define DO_GT32(X, Y, S) DO_FLT32(Y, X, S)

DO_VCMP_FP_BOTH(vfcmpeqh, vfcmpeq_scalarh, 2, float16, DO_FEQ16)
DO_VCMP_FP_BOTH(vfcmpeqs, vfcmpeq_scalars, 4, float32, DO_FEQ32)
DO_VCMP_FP_BOTH(vfcmpneh, vfcmpne_scalarh, 2, float16, !DO_FEQ16)
DO_VCMP_FP_BOTH(vfcmpnes, vfcmpne_scalars, 4, float32, !DO_FEQ32)
DO_VCMP_FP_BOTH(vfcmpgeh, vfcmpge_scalarh, 2, float16, DO_GE16)
DO_VCMP_FP_BOTH(vfcmpges, vfcmpge_scalars, 4, float32, DO_GE32)
DO_VCMP_FP_BOTH(vfcmplth, vfcmplt_scalarh, 2, float16, !DO_GE16)
DO_VCMP_FP_BOTH(vfcmplts, vfcmplt_scalars, 4, float32, !DO_GE32)
DO_VCMP_FP_BOTH(vfcmpgth, vfcmpgt_scalarh, 2, float16, DO_GT16)
DO_VCMP_FP_BOTH(vfcmpgts, vfcmpgt_scalars, 4, float32, DO_GT32)
DO_VCMP_FP_BOTH(vfcmpleh, vfcmple_scalarh, 2, float16, !DO_GT16)
DO_VCMP_FP_BOTH(vfcmples, vfcmple_scalars, 4, float32, !DO_GT32)

#define DO_1OP_IMM(OP, FN)                                             \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                uint64_t imm)                          \
    {                                                                  \
        uint64_t *d = vd;                                              \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / 8; e++, mask >>= 8) {                     \
            mve_mergemask_uq(&d[H8(e)], FN(d[H8(e)], imm), mask);      \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_MOVI(N, I) (I)
#define DO_ANDI(N, I) ((N) & (I))
#define DO_ORRI(N, I) ((N) | (I))

DO_1OP_IMM(vmovi, DO_MOVI)
DO_1OP_IMM(vandi, DO_ANDI)
DO_1OP_IMM(vorri, DO_ORRI)

#define DO_2OP(OP, ESIZE, TYPE, MERGE, FN)                             \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, void *vm)                    \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            TYPE r = FN(n[glue(H, ESIZE)(e)], m[glue(H, ESIZE)(e)]);   \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_2OP_SCALAR(OP, ESIZE, TYPE, MERGE, FN)                      \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, uint32_t rm)                 \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE m = (TYPE)rm;                                             \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            TYPE r = FN(n[glue(H, ESIZE)(e)], m);                      \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_2OP_L(OP, TOP, ESIZE, TYPE, LESIZE, LTYPE, MERGE, FN)        \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, void *vm)                    \
    {                                                                  \
        LTYPE *d = vd;                                                 \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned le;                                                   \
                                                                       \
        for (le = 0; le < 16 / LESIZE; le++, mask >>= LESIZE) {        \
            LTYPE r = FN((LTYPE)n[glue(H, ESIZE)(le * 2 + TOP)],       \
                         m[glue(H, ESIZE)(le * 2 + TOP)]);             \
                                                                       \
            MERGE(&d[glue(H, LESIZE)(le)], r, mask);                   \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_AND(N, M) ((N) & (M))
#define DO_BIC(N, M) ((N) & ~(M))
#define DO_ORR(N, M) ((N) | (M))
#define DO_ORN(N, M) ((N) | ~(M))
#define DO_EOR(N, M) ((N) ^ (M))
#define DO_ADD(N, M) ((N) + (M))
#define DO_SUB(N, M) ((N) - (M))
#define DO_MUL(N, M) ((N) * (M))
#define DO_MAX(N, M) ((N) >= (M) ? (N) : (M))
#define DO_MIN(N, M) ((N) >= (M) ? (M) : (N))
#define DO_ABD(N, M) ((N) >= (M) ? (N) - (M) : (M) - (N))

DO_2OP(vand, 8, uint64_t, mve_mergemask_uq, DO_AND)
DO_2OP(vbic, 8, uint64_t, mve_mergemask_uq, DO_BIC)
DO_2OP(vorr, 8, uint64_t, mve_mergemask_uq, DO_ORR)
DO_2OP(vorn, 8, uint64_t, mve_mergemask_uq, DO_ORN)
DO_2OP(veor, 8, uint64_t, mve_mergemask_uq, DO_EOR)

DO_2OP(vaddb, 1, uint8_t, mve_mergemask_ub, DO_ADD)
DO_2OP(vaddh, 2, uint16_t, mve_mergemask_uh, DO_ADD)
DO_2OP(vaddw, 4, uint32_t, mve_mergemask_uw, DO_ADD)
DO_2OP_SCALAR(vadd_scalarb, 1, uint8_t, mve_mergemask_ub, DO_ADD)
DO_2OP_SCALAR(vadd_scalarh, 2, uint16_t, mve_mergemask_uh, DO_ADD)
DO_2OP_SCALAR(vadd_scalarw, 4, uint32_t, mve_mergemask_uw, DO_ADD)
DO_2OP(vsubb, 1, uint8_t, mve_mergemask_ub, DO_SUB)
DO_2OP(vsubh, 2, uint16_t, mve_mergemask_uh, DO_SUB)
DO_2OP(vsubw, 4, uint32_t, mve_mergemask_uw, DO_SUB)
DO_2OP_SCALAR(vsub_scalarb, 1, uint8_t, mve_mergemask_ub, DO_SUB)
DO_2OP_SCALAR(vsub_scalarh, 2, uint16_t, mve_mergemask_uh, DO_SUB)
DO_2OP_SCALAR(vsub_scalarw, 4, uint32_t, mve_mergemask_uw, DO_SUB)
DO_2OP(vmulb, 1, uint8_t, mve_mergemask_ub, DO_MUL)
DO_2OP(vmulh, 2, uint16_t, mve_mergemask_uh, DO_MUL)
DO_2OP(vmulw, 4, uint32_t, mve_mergemask_uw, DO_MUL)
DO_2OP_SCALAR(vmul_scalarb, 1, uint8_t, mve_mergemask_ub, DO_MUL)
DO_2OP_SCALAR(vmul_scalarh, 2, uint16_t, mve_mergemask_uh, DO_MUL)
DO_2OP_SCALAR(vmul_scalarw, 4, uint32_t, mve_mergemask_uw, DO_MUL)

static inline int8_t do_mulh_s_b(int8_t n, int8_t m)
{
    return ((int32_t)n * m) >> 8;
}

static inline int16_t do_mulh_s_h(int16_t n, int16_t m)
{
    return ((int32_t)n * m) >> 16;
}

static inline int32_t do_mulh_s_w(int32_t n, int32_t m)
{
    return ((int64_t)n * m) >> 32;
}

static inline uint8_t do_mulh_u_b(uint8_t n, uint8_t m)
{
    return ((uint32_t)n * m) >> 8;
}

static inline uint16_t do_mulh_u_h(uint16_t n, uint16_t m)
{
    return ((uint32_t)n * m) >> 16;
}

static inline uint32_t do_mulh_u_w(uint32_t n, uint32_t m)
{
    return ((uint64_t)n * m) >> 32;
}

static inline int8_t do_rmulh_s_b(int8_t n, int8_t m)
{
    return (((int32_t)n * m) + (1U << 7)) >> 8;
}

static inline int16_t do_rmulh_s_h(int16_t n, int16_t m)
{
    return (((int32_t)n * m) + (1U << 15)) >> 16;
}

static inline int32_t do_rmulh_s_w(int32_t n, int32_t m)
{
    return (((int64_t)n * m) + (1U << 31)) >> 32;
}

static inline uint8_t do_rmulh_u_b(uint8_t n, uint8_t m)
{
    return (((uint32_t)n * m) + (1U << 7)) >> 8;
}

static inline uint16_t do_rmulh_u_h(uint16_t n, uint16_t m)
{
    return (((uint32_t)n * m) + (1U << 15)) >> 16;
}

static inline uint32_t do_rmulh_u_w(uint32_t n, uint32_t m)
{
    return (((uint64_t)n * m) + (1U << 31)) >> 32;
}

DO_2OP(vmulhsb, 1, int8_t, mve_mergemask_sb, do_mulh_s_b)
DO_2OP(vmulhsh, 2, int16_t, mve_mergemask_sh, do_mulh_s_h)
DO_2OP(vmulhsw, 4, int32_t, mve_mergemask_sw, do_mulh_s_w)
DO_2OP(vmulhub, 1, uint8_t, mve_mergemask_ub, do_mulh_u_b)
DO_2OP(vmulhuh, 2, uint16_t, mve_mergemask_uh, do_mulh_u_h)
DO_2OP(vmulhuw, 4, uint32_t, mve_mergemask_uw, do_mulh_u_w)
DO_2OP(vrmulhsb, 1, int8_t, mve_mergemask_sb, do_rmulh_s_b)
DO_2OP(vrmulhsh, 2, int16_t, mve_mergemask_sh, do_rmulh_s_h)
DO_2OP(vrmulhsw, 4, int32_t, mve_mergemask_sw, do_rmulh_s_w)
DO_2OP(vrmulhub, 1, uint8_t, mve_mergemask_ub, do_rmulh_u_b)
DO_2OP(vrmulhuh, 2, uint16_t, mve_mergemask_uh, do_rmulh_u_h)
DO_2OP(vrmulhuw, 4, uint32_t, mve_mergemask_uw, do_rmulh_u_w)

DO_2OP_L(vmullbsb, 0, 1, int8_t, 2, int16_t, mve_mergemask_sh, DO_MUL)
DO_2OP_L(vmullbsh, 0, 2, int16_t, 4, int32_t, mve_mergemask_sw, DO_MUL)
DO_2OP_L(vmullbsw, 0, 4, int32_t, 8, int64_t, mve_mergemask_sq, DO_MUL)
DO_2OP_L(vmullbub, 0, 1, uint8_t, 2, uint16_t, mve_mergemask_uh, DO_MUL)
DO_2OP_L(vmullbuh, 0, 2, uint16_t, 4, uint32_t, mve_mergemask_uw, DO_MUL)
DO_2OP_L(vmullbuw, 0, 4, uint32_t, 8, uint64_t, mve_mergemask_uq, DO_MUL)
DO_2OP_L(vmulltsb, 1, 1, int8_t, 2, int16_t, mve_mergemask_sh, DO_MUL)
DO_2OP_L(vmulltsh, 1, 2, int16_t, 4, int32_t, mve_mergemask_sw, DO_MUL)
DO_2OP_L(vmulltsw, 1, 4, int32_t, 8, int64_t, mve_mergemask_sq, DO_MUL)
DO_2OP_L(vmulltub, 1, 1, uint8_t, 2, uint16_t, mve_mergemask_uh, DO_MUL)
DO_2OP_L(vmulltuh, 1, 2, uint16_t, 4, uint32_t, mve_mergemask_uw, DO_MUL)
DO_2OP_L(vmulltuw, 1, 4, uint32_t, 8, uint64_t, mve_mergemask_uq, DO_MUL)

static uint64_t mve_pmull_h(uint64_t op1, uint64_t op2)
{
    uint64_t result = 0;
    int i;

    for (i = 0; i < 8; i++) {
        uint64_t mask = (op1 & 0x0001000100010001ULL) * 0xffff;

        result ^= op2 & mask;
        op1 >>= 1;
        op2 <<= 1;
    }
    return result;
}

static uint64_t mve_pmull_w(uint64_t op1, uint64_t op2)
{
    uint64_t result = 0;
    int i;

    for (i = 0; i < 16; i++) {
        uint64_t mask = (op1 & 0x0000000100000001ULL) * 0xffffffff;

        result ^= op2 & mask;
        op1 >>= 1;
        op2 <<= 1;
    }
    return result;
}

#define VMULLPH_MASK 0x00ff00ff00ff00ffULL
#define VMULLPW_MASK 0x0000ffff0000ffffULL
#define DO_VMULLPBH(N, M) \
    mve_pmull_h((N) & VMULLPH_MASK, (M) & VMULLPH_MASK)
#define DO_VMULLPTH(N, M) DO_VMULLPBH((N) >> 8, (M) >> 8)
#define DO_VMULLPBW(N, M) \
    mve_pmull_w((N) & VMULLPW_MASK, (M) & VMULLPW_MASK)
#define DO_VMULLPTW(N, M) DO_VMULLPBW((N) >> 16, (M) >> 16)

DO_2OP(vmullpbh, 8, uint64_t, mve_mergemask_uq, DO_VMULLPBH)
DO_2OP(vmullpth, 8, uint64_t, mve_mergemask_uq, DO_VMULLPTH)
DO_2OP(vmullpbw, 8, uint64_t, mve_mergemask_uq, DO_VMULLPBW)
DO_2OP(vmullptw, 8, uint64_t, mve_mergemask_uq, DO_VMULLPTW)

DO_2OP(vmaxsb, 1, int8_t, mve_mergemask_sb, DO_MAX)
DO_2OP(vmaxsh, 2, int16_t, mve_mergemask_sh, DO_MAX)
DO_2OP(vmaxsw, 4, int32_t, mve_mergemask_sw, DO_MAX)
DO_2OP(vmaxub, 1, uint8_t, mve_mergemask_ub, DO_MAX)
DO_2OP(vmaxuh, 2, uint16_t, mve_mergemask_uh, DO_MAX)
DO_2OP(vmaxuw, 4, uint32_t, mve_mergemask_uw, DO_MAX)
DO_2OP(vminsb, 1, int8_t, mve_mergemask_sb, DO_MIN)
DO_2OP(vminsh, 2, int16_t, mve_mergemask_sh, DO_MIN)
DO_2OP(vminsw, 4, int32_t, mve_mergemask_sw, DO_MIN)
DO_2OP(vminub, 1, uint8_t, mve_mergemask_ub, DO_MIN)
DO_2OP(vminuh, 2, uint16_t, mve_mergemask_uh, DO_MIN)
DO_2OP(vminuw, 4, uint32_t, mve_mergemask_uw, DO_MIN)
DO_2OP(vabdsb, 1, int8_t, mve_mergemask_sb, DO_ABD)
DO_2OP(vabdsh, 2, int16_t, mve_mergemask_sh, DO_ABD)
DO_2OP(vabdsw, 4, int32_t, mve_mergemask_sw, DO_ABD)
DO_2OP(vabdub, 1, uint8_t, mve_mergemask_ub, DO_ABD)
DO_2OP(vabduh, 2, uint16_t, mve_mergemask_uh, DO_ABD)
DO_2OP(vabduw, 4, uint32_t, mve_mergemask_uw, DO_ABD)

static inline uint32_t do_vhadd_u(uint32_t n, uint32_t m)
{
    return ((uint64_t)n + m) >> 1;
}

static inline int32_t do_vhadd_s(int32_t n, int32_t m)
{
    return ((int64_t)n + m) >> 1;
}

static inline uint32_t do_vrhadd_u(uint32_t n, uint32_t m)
{
    return ((uint64_t)n + m + 1) >> 1;
}

static inline int32_t do_vrhadd_s(int32_t n, int32_t m)
{
    return ((int64_t)n + m + 1) >> 1;
}

static inline uint32_t do_vhsub_u(uint32_t n, uint32_t m)
{
    return ((uint64_t)n - m) >> 1;
}

static inline int32_t do_vhsub_s(int32_t n, int32_t m)
{
    return ((int64_t)n - m) >> 1;
}

DO_2OP(vhaddsb, 1, int8_t, mve_mergemask_sb, do_vhadd_s)
DO_2OP(vhaddsh, 2, int16_t, mve_mergemask_sh, do_vhadd_s)
DO_2OP(vhaddsw, 4, int32_t, mve_mergemask_sw, do_vhadd_s)
DO_2OP(vhaddub, 1, uint8_t, mve_mergemask_ub, do_vhadd_u)
DO_2OP(vhadduh, 2, uint16_t, mve_mergemask_uh, do_vhadd_u)
DO_2OP(vhadduw, 4, uint32_t, mve_mergemask_uw, do_vhadd_u)
DO_2OP_SCALAR(vhadds_scalarb, 1, int8_t, mve_mergemask_sb, do_vhadd_s)
DO_2OP_SCALAR(vhadds_scalarh, 2, int16_t, mve_mergemask_sh, do_vhadd_s)
DO_2OP_SCALAR(vhadds_scalarw, 4, int32_t, mve_mergemask_sw, do_vhadd_s)
DO_2OP_SCALAR(vhaddu_scalarb, 1, uint8_t, mve_mergemask_ub, do_vhadd_u)
DO_2OP_SCALAR(vhaddu_scalarh, 2, uint16_t, mve_mergemask_uh, do_vhadd_u)
DO_2OP_SCALAR(vhaddu_scalarw, 4, uint32_t, mve_mergemask_uw, do_vhadd_u)
DO_2OP(vrhaddsb, 1, int8_t, mve_mergemask_sb, do_vrhadd_s)
DO_2OP(vrhaddsh, 2, int16_t, mve_mergemask_sh, do_vrhadd_s)
DO_2OP(vrhaddsw, 4, int32_t, mve_mergemask_sw, do_vrhadd_s)
DO_2OP(vrhaddub, 1, uint8_t, mve_mergemask_ub, do_vrhadd_u)
DO_2OP(vrhadduh, 2, uint16_t, mve_mergemask_uh, do_vrhadd_u)
DO_2OP(vrhadduw, 4, uint32_t, mve_mergemask_uw, do_vrhadd_u)
DO_2OP(vhsubsb, 1, int8_t, mve_mergemask_sb, do_vhsub_s)
DO_2OP(vhsubsh, 2, int16_t, mve_mergemask_sh, do_vhsub_s)
DO_2OP(vhsubsw, 4, int32_t, mve_mergemask_sw, do_vhsub_s)
DO_2OP(vhsubub, 1, uint8_t, mve_mergemask_ub, do_vhsub_u)
DO_2OP(vhsubuh, 2, uint16_t, mve_mergemask_uh, do_vhsub_u)
DO_2OP(vhsubuw, 4, uint32_t, mve_mergemask_uw, do_vhsub_u)
DO_2OP_SCALAR(vhsubs_scalarb, 1, int8_t, mve_mergemask_sb, do_vhsub_s)
DO_2OP_SCALAR(vhsubs_scalarh, 2, int16_t, mve_mergemask_sh, do_vhsub_s)
DO_2OP_SCALAR(vhsubs_scalarw, 4, int32_t, mve_mergemask_sw, do_vhsub_s)
DO_2OP_SCALAR(vhsubu_scalarb, 1, uint8_t, mve_mergemask_ub, do_vhsub_u)
DO_2OP_SCALAR(vhsubu_scalarh, 2, uint16_t, mve_mergemask_uh, do_vhsub_u)
DO_2OP_SCALAR(vhsubu_scalarw, 4, uint32_t, mve_mergemask_uw, do_vhsub_u)

static void do_vadc(CPUARMState *env, uint32_t *d, uint32_t *n,
                    uint32_t *m, uint32_t inv, uint32_t carry_in,
                    bool update_flags)
{
    uint16_t mask = mve_element_mask(env);
    unsigned e;

    if (mask & 0x1111) {
        update_flags = true;
    }

    for (e = 0; e < 16 / 4; e++, mask >>= 4) {
        uint64_t r = carry_in;

        r += n[H4(e)];
        r += m[H4(e)] ^ inv;
        if (mask & 1) {
            carry_in = (uint32_t)(r >> 32);
        }
        mve_mergemask_uw(&d[H4(e)], (uint32_t)r, mask);
    }

    if (update_flags) {
        env->vfp.xregs[ARM_VFP_FPSCR] &= ~FPCR_NZCV_MASK;
        env->vfp.xregs[ARM_VFP_FPSCR] |= carry_in ? FPCR_C : 0;
    }
    mve_advance_vpt(env);
}

void HELPER(mve_vadc)(CPUARMState *env, void *vd, void *vn, void *vm)
{
    uint32_t carry_in =
        (env->vfp.xregs[ARM_VFP_FPSCR] & FPCR_C) != 0;

    do_vadc(env, vd, vn, vm, 0, carry_in, false);
}

void HELPER(mve_vadci)(CPUARMState *env, void *vd, void *vn, void *vm)
{
    do_vadc(env, vd, vn, vm, 0, 0, true);
}

void HELPER(mve_vsbc)(CPUARMState *env, void *vd, void *vn, void *vm)
{
    uint32_t carry_in =
        (env->vfp.xregs[ARM_VFP_FPSCR] & FPCR_C) != 0;

    do_vadc(env, vd, vn, vm, UINT32_MAX, carry_in, false);
}

void HELPER(mve_vsbci)(CPUARMState *env, void *vd, void *vn, void *vm)
{
    do_vadc(env, vd, vn, vm, UINT32_MAX, 1, true);
}

#define DO_VCADD(OP, ESIZE, TYPE, MERGE, FN0, FN1)                     \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, void *vm)                    \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        TYPE r[16 / ESIZE];                                            \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++) {                             \
            if (!(e & 1)) {                                            \
                r[e] = FN0(n[glue(H, ESIZE)(e)],                       \
                           m[glue(H, ESIZE)(e + 1)]);                  \
            } else {                                                   \
                r[e] = FN1(n[glue(H, ESIZE)(e)],                       \
                           m[glue(H, ESIZE)(e - 1)]);                  \
            }                                                          \
        }                                                              \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            MERGE(&d[glue(H, ESIZE)(e)], r[e], mask);                  \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_VCADD_ALL(OP, FN0, FN1)                                     \
    DO_VCADD(OP##b, 1, int8_t, mve_mergemask_sb, FN0, FN1)             \
    DO_VCADD(OP##h, 2, int16_t, mve_mergemask_sh, FN0, FN1)            \
    DO_VCADD(OP##w, 4, int32_t, mve_mergemask_sw, FN0, FN1)

DO_VCADD_ALL(vcadd90, DO_SUB, DO_ADD)
DO_VCADD_ALL(vcadd270, DO_ADD, DO_SUB)
DO_VCADD_ALL(vhcadd90, do_vhsub_s, do_vhadd_s)
DO_VCADD_ALL(vhcadd270, do_vhadd_s, do_vhsub_s)

#define DO_1OP(OP, ESIZE, TYPE, MERGE, FN)                             \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd, void *vm)  \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            TYPE r = FN(m[glue(H, ESIZE)(e)]);                         \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_CLS_B(N) (clrsb32(N) - 24)
#define DO_CLS_H(N) (clrsb32(N) - 16)
#define DO_CLZ_B(N) (clz32(N) - 24)
#define DO_CLZ_H(N) (clz32(N) - 16)
#define DO_NOT(N) (~(N))
#define DO_ABS(N) ((N) < 0 ? -(N) : (N))
#define DO_NEG(N) (-(N))
#define DO_FABSH(N) ((N) & dup_const(MO_16, 0x7fff))
#define DO_FABSS(N) ((N) & dup_const(MO_32, 0x7fffffff))
#define DO_FNEGH(N) ((N) ^ dup_const(MO_16, 0x8000))
#define DO_FNEGS(N) ((N) ^ dup_const(MO_32, 0x80000000))

static inline uint32_t mve_hswap32(uint32_t h)
{
    return (h << 16) | (h >> 16);
}

static inline uint64_t mve_hswap64(uint64_t h)
{
    uint64_t m = 0x0000ffff0000ffffull;

    h = (h << 32) | (h >> 32);
    return ((h & m) << 16) | ((h >> 16) & m);
}

static inline uint64_t mve_wswap64(uint64_t h)
{
    return (h << 32) | (h >> 32);
}

DO_1OP(vclsb, 1, int8_t, mve_mergemask_sb, DO_CLS_B)
DO_1OP(vclsh, 2, int16_t, mve_mergemask_sh, DO_CLS_H)
DO_1OP(vclsw, 4, int32_t, mve_mergemask_sw, clrsb32)
DO_1OP(vclzb, 1, uint8_t, mve_mergemask_ub, DO_CLZ_B)
DO_1OP(vclzh, 2, uint16_t, mve_mergemask_uh, DO_CLZ_H)
DO_1OP(vclzw, 4, uint32_t, mve_mergemask_uw, clz32)
DO_1OP(vrev16b, 2, uint16_t, mve_mergemask_uh, bswap16)
DO_1OP(vrev32b, 4, uint32_t, mve_mergemask_uw, bswap32)
DO_1OP(vrev32h, 4, uint32_t, mve_mergemask_uw, mve_hswap32)
DO_1OP(vrev64b, 8, uint64_t, mve_mergemask_uq, bswap64)
DO_1OP(vrev64h, 8, uint64_t, mve_mergemask_uq, mve_hswap64)
DO_1OP(vrev64w, 8, uint64_t, mve_mergemask_uq, mve_wswap64)
DO_1OP(vmvn, 8, uint64_t, mve_mergemask_uq, DO_NOT)
DO_1OP(vabsb, 1, int8_t, mve_mergemask_sb, DO_ABS)
DO_1OP(vabsh, 2, int16_t, mve_mergemask_sh, DO_ABS)
DO_1OP(vabsw, 4, int32_t, mve_mergemask_sw, DO_ABS)
DO_1OP(vfabsh, 8, uint64_t, mve_mergemask_uq, DO_FABSH)
DO_1OP(vfabss, 8, uint64_t, mve_mergemask_uq, DO_FABSS)
DO_1OP(vnegb, 1, int8_t, mve_mergemask_sb, DO_NEG)
DO_1OP(vnegh, 2, int16_t, mve_mergemask_sh, DO_NEG)
DO_1OP(vnegw, 4, int32_t, mve_mergemask_sw, DO_NEG)
DO_1OP(vfnegh, 8, uint64_t, mve_mergemask_uq, DO_FNEGH)
DO_1OP(vfnegs, 8, uint64_t, mve_mergemask_uq, DO_FNEGS)

#define DO_VMAXMINA(OP, ESIZE, STYPE, UTYPE, MERGE, FN)                \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd, void *vm)  \
    {                                                                  \
        UTYPE *d = vd;                                                 \
        STYPE *m = vm;                                                 \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            UTYPE r = DO_ABS(m[glue(H, ESIZE)(e)]);                    \
                                                                       \
            r = FN(d[glue(H, ESIZE)(e)], r);                           \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_VMAXMINA(vmaxab, 1, int8_t, uint8_t, mve_mergemask_ub, DO_MAX)
DO_VMAXMINA(vmaxah, 2, int16_t, uint16_t, mve_mergemask_uh, DO_MAX)
DO_VMAXMINA(vmaxaw, 4, int32_t, uint32_t, mve_mergemask_uw, DO_MAX)
DO_VMAXMINA(vminab, 1, int8_t, uint8_t, mve_mergemask_ub, DO_MIN)
DO_VMAXMINA(vminah, 2, int16_t, uint16_t, mve_mergemask_uh, DO_MIN)
DO_VMAXMINA(vminaw, 4, int32_t, uint32_t, mve_mergemask_uw, DO_MIN)

#define DO_LDAV(OP, ESIZE, TYPE, XCHG, EVENACC, ODDACC)                \
    uint64_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vn,        \
                                    void *vm, uint64_t ra)             \
    {                                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if (mask & 1) {                                            \
                if (e & 1) {                                           \
                    ra ODDACC                                          \
                        (int64_t)n[glue(H, ESIZE)(e - 1 * XCHG)] *     \
                        m[glue(H, ESIZE)(e)];                          \
                } else {                                               \
                    ra EVENACC                                         \
                        (int64_t)n[glue(H, ESIZE)(e + 1 * XCHG)] *     \
                        m[glue(H, ESIZE)(e)];                          \
                }                                                      \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return ra;                                                     \
    }

DO_LDAV(vmlaldavsh, 2, int16_t, false, +=, +=)
DO_LDAV(vmlaldavxsh, 2, int16_t, true, +=, +=)
DO_LDAV(vmlaldavsw, 4, int32_t, false, +=, +=)
DO_LDAV(vmlaldavxsw, 4, int32_t, true, +=, +=)
DO_LDAV(vmlaldavuh, 2, uint16_t, false, +=, +=)
DO_LDAV(vmlaldavuw, 4, uint32_t, false, +=, +=)
DO_LDAV(vmlsldavsh, 2, int16_t, false, +=, -=)
DO_LDAV(vmlsldavxsh, 2, int16_t, true, +=, -=)
DO_LDAV(vmlsldavsw, 4, int32_t, false, +=, -=)
DO_LDAV(vmlsldavxsw, 4, int32_t, true, +=, -=)

#define DO_LDAVH(OP, TYPE, LTYPE, XCHG, SUB)                           \
    uint64_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vn,        \
                                    void *vm, uint64_t ra)             \
    {                                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / 4; e++, mask >>= 4) {                     \
            if (mask & 1) {                                            \
                LTYPE product;                                         \
                                                                       \
                if (e & 1) {                                           \
                    product = (LTYPE)n[H4(e - 1 * XCHG)] * m[H4(e)];   \
                    if (SUB) {                                         \
                        product = -product;                            \
                    }                                                  \
                } else {                                               \
                    product = (LTYPE)n[H4(e + 1 * XCHG)] * m[H4(e)];   \
                }                                                      \
                product = (product >> 8) + ((product >> 7) & 1);       \
                ra += product;                                         \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return ra;                                                     \
    }

DO_LDAVH(vrmlaldavhsw, int32_t, int64_t, false, false)
DO_LDAVH(vrmlaldavhxsw, int32_t, int64_t, true, false)
DO_LDAVH(vrmlaldavhuw, uint32_t, uint64_t, false, false)
DO_LDAVH(vrmlsldavhsw, int32_t, int64_t, false, true)
DO_LDAVH(vrmlsldavhxsw, int32_t, int64_t, true, true)

#define DO_DAV(OP, ESIZE, TYPE, XCHG, EVENACC, ODDACC)                 \
    uint32_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vn,        \
                                    void *vm, uint32_t ra)             \
    {                                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if (mask & 1) {                                            \
                if (e & 1) {                                           \
                    ra ODDACC n[glue(H, ESIZE)(e - 1 * XCHG)] *        \
                        m[glue(H, ESIZE)(e)];                          \
                } else {                                               \
                    ra EVENACC n[glue(H, ESIZE)(e + 1 * XCHG)] *       \
                        m[glue(H, ESIZE)(e)];                          \
                }                                                      \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return ra;                                                     \
    }

#define DO_DAV_S(INSN, XCHG, EVENACC, ODDACC)                          \
    DO_DAV(INSN##b, 1, int8_t, XCHG, EVENACC, ODDACC)                  \
    DO_DAV(INSN##h, 2, int16_t, XCHG, EVENACC, ODDACC)                 \
    DO_DAV(INSN##w, 4, int32_t, XCHG, EVENACC, ODDACC)

#define DO_DAV_U(INSN, XCHG, EVENACC, ODDACC)                          \
    DO_DAV(INSN##b, 1, uint8_t, XCHG, EVENACC, ODDACC)                 \
    DO_DAV(INSN##h, 2, uint16_t, XCHG, EVENACC, ODDACC)                \
    DO_DAV(INSN##w, 4, uint32_t, XCHG, EVENACC, ODDACC)

DO_DAV_S(vmladavs, false, +=, +=)
DO_DAV_U(vmladavu, false, +=, +=)
DO_DAV_S(vmlsdav, false, +=, -=)
DO_DAV_S(vmladavsx, true, +=, +=)
DO_DAV_S(vmlsdavx, true, +=, -=)

#define DO_VADDV(OP, ESIZE, TYPE)                                      \
    uint32_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vm,        \
                                    uint32_t ra)                       \
    {                                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if (mask & 1) {                                            \
                ra += m[glue(H, ESIZE)(e)];                            \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return ra;                                                     \
    }

DO_VADDV(vaddvsb, 1, int8_t)
DO_VADDV(vaddvsh, 2, int16_t)
DO_VADDV(vaddvsw, 4, int32_t)
DO_VADDV(vaddvub, 1, uint8_t)
DO_VADDV(vaddvuh, 2, uint16_t)
DO_VADDV(vaddvuw, 4, uint32_t)

#define DO_VMAXMINV(OP, ESIZE, TYPE, RATYPE, FN)                       \
    uint32_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vm,        \
                                    uint32_t ra_in)                    \
    {                                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        int64_t ra = (RATYPE)ra_in;                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if (mask & 1) {                                            \
                ra = FN(ra, m[glue(H, ESIZE)(e)]);                     \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return ra;                                                     \
    }

#define DO_VMAXMINV_U(OP, FN)                                          \
    DO_VMAXMINV(OP##b, 1, uint8_t, uint8_t, FN)                        \
    DO_VMAXMINV(OP##h, 2, uint16_t, uint16_t, FN)                      \
    DO_VMAXMINV(OP##w, 4, uint32_t, uint32_t, FN)
#define DO_VMAXMINV_S(OP, FN)                                          \
    DO_VMAXMINV(OP##b, 1, int8_t, int8_t, FN)                          \
    DO_VMAXMINV(OP##h, 2, int16_t, int16_t, FN)                        \
    DO_VMAXMINV(OP##w, 4, int32_t, int32_t, FN)

static int64_t do_maxa(int64_t n, int64_t m)
{
    if (m < 0) {
        m = -m;
    }
    return DO_MAX(n, m);
}

static int64_t do_mina(int64_t n, int64_t m)
{
    if (m < 0) {
        m = -m;
    }
    return DO_MIN(n, m);
}

DO_VMAXMINV_S(vmaxvs, DO_MAX)
DO_VMAXMINV_U(vmaxvu, DO_MAX)
DO_VMAXMINV_S(vminvs, DO_MIN)
DO_VMAXMINV_U(vminvu, DO_MIN)
DO_VMAXMINV(vmaxavb, 1, int8_t, uint8_t, do_maxa)
DO_VMAXMINV(vmaxavh, 2, int16_t, uint16_t, do_maxa)
DO_VMAXMINV(vmaxavw, 4, int32_t, uint32_t, do_maxa)
DO_VMAXMINV(vminavb, 1, int8_t, uint8_t, do_mina)
DO_VMAXMINV(vminavh, 2, int16_t, uint16_t, do_mina)
DO_VMAXMINV(vminavw, 4, int32_t, uint32_t, do_mina)

#define DO_FP_VMAXMINV(OP, ESIZE, TYPE, ABS, FN)                       \
    uint32_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vm,        \
                                    uint32_t ra_in)                    \
    {                                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        TYPE ra = (TYPE)ra_in;                                         \
        float_status *fpst = (ESIZE == 2) ?                            \
            &env->vfp.standard_fp_status_f16 :                         \
            &env->vfp.standard_fp_status;                              \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if (mask & 1) {                                            \
                TYPE v = m[glue(H, ESIZE)(e)];                         \
                                                                       \
                if (TYPE##_is_signaling_nan(ra, fpst)) {               \
                    ra = TYPE##_silence_nan(ra, fpst);                 \
                    fpst->float_exception_flags |= float_flag_invalid;  \
                }                                                      \
                if (TYPE##_is_signaling_nan(v, fpst)) {                \
                    v = TYPE##_silence_nan(v, fpst);                   \
                    fpst->float_exception_flags |= float_flag_invalid;  \
                }                                                      \
                if (ABS) {                                             \
                    v &= MAKE_64BIT_MASK(0, ESIZE * 8 - 1);            \
                }                                                      \
                ra = FN(ra, v, fpst);                                  \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return ra;                                                     \
    }

DO_FP_VMAXMINV(vmaxnmvh, 2, float16, false, float16_maxnum)
DO_FP_VMAXMINV(vmaxnmvs, 4, float32, false, float32_maxnum)
DO_FP_VMAXMINV(vminnmvh, 2, float16, false, float16_minnum)
DO_FP_VMAXMINV(vminnmvs, 4, float32, false, float32_minnum)
DO_FP_VMAXMINV(vmaxnmavh, 2, float16, true, float16_maxnum)
DO_FP_VMAXMINV(vmaxnmavs, 4, float32, true, float32_maxnum)
DO_FP_VMAXMINV(vminnmavh, 2, float16, true, float16_minnum)
DO_FP_VMAXMINV(vminnmavs, 4, float32, true, float32_minnum)

#define DO_VADDLV(OP, TYPE, LTYPE)                                     \
    uint64_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vm,        \
                                    uint64_t ra)                       \
    {                                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / 4; e++, mask >>= 4) {                     \
            if (mask & 1) {                                            \
                ra += (LTYPE)m[H4(e)];                                 \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return ra;                                                     \
    }

DO_VADDLV(vaddlv_s, int32_t, int64_t)
DO_VADDLV(vaddlv_u, uint32_t, uint64_t)

#define DO_VABAV(OP, ESIZE, TYPE)                                      \
    uint32_t HELPER(glue(mve_, OP))(CPUARMState *env, void *vn,        \
                                    void *vm, uint32_t ra)             \
    {                                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if (mask & 1) {                                            \
                int64_t n0 = n[glue(H, ESIZE)(e)];                     \
                int64_t m0 = m[glue(H, ESIZE)(e)];                     \
                uint32_t r = n0 >= m0 ? n0 - m0 : m0 - n0;             \
                                                                       \
                ra += r;                                               \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
        return ra;                                                     \
    }

DO_VABAV(vabavsb, 1, int8_t)
DO_VABAV(vabavsh, 2, int16_t)
DO_VABAV(vabavsw, 4, int32_t)
DO_VABAV(vabavub, 1, uint8_t)
DO_VABAV(vabavuh, 2, uint16_t)
DO_VABAV(vabavuw, 4, uint32_t)

static inline int32_t mve_do_sat_bhs(int64_t val, int64_t min, int64_t max,
                                     bool *satp)
{
    if (val > max) {
        *satp = true;
        return max;
    } else if (val < min) {
        *satp = true;
        return min;
    }
    return val;
}

static inline uint32_t mve_do_usat_bhs(uint64_t val, uint64_t max,
                                       bool *satp)
{
    if (val > max) {
        *satp = true;
        return (uint32_t)max;
    }
    return val;
}

#define DO_2OP_SAT(OP, ESIZE, TYPE, MERGE, FN)                         \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, void *vm)                    \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        bool qc = false;                                               \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            bool sat = false;                                          \
            TYPE r = FN(n[glue(H, ESIZE)(e)],                          \
                        m[glue(H, ESIZE)(e)], &sat);                   \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
            qc |= sat && (mask & 1);                                   \
        }                                                              \
        if (qc) {                                                      \
            env->vfp.qc[0] = qc;                                       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_2OP_SCALAR_SAT(OP, ESIZE, TYPE, MERGE, FN)                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, uint32_t rm)                 \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE m = (TYPE)rm;                                             \
        uint16_t mask = mve_element_mask(env);                         \
        bool qc = false;                                               \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            bool sat = false;                                          \
            TYPE r = FN(n[glue(H, ESIZE)(e)], m, &sat);                \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
            qc |= sat && (mask & 1);                                   \
        }                                                              \
        if (qc) {                                                      \
            env->vfp.qc[0] = qc;                                       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_2OP_SCALAR_ACC(OP, ESIZE, TYPE, MERGE, FN)                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, uint32_t rm)                 \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE m = (TYPE)rm;                                             \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            TYPE r = FN(d[glue(H, ESIZE)(e)], n[glue(H, ESIZE)(e)], m);\
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_2OP_SCALAR_SAT_ACC(OP, ESIZE, TYPE, MERGE, FN)              \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, uint32_t rm)                 \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE m = (TYPE)rm;                                             \
        uint16_t mask = mve_element_mask(env);                         \
        bool qc = false;                                               \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            bool sat = false;                                          \
            TYPE r = FN(d[glue(H, ESIZE)(e)], n[glue(H, ESIZE)(e)],    \
                        m, &sat);                                      \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
            qc |= sat && (mask & 1);                                   \
        }                                                              \
        if (qc) {                                                      \
            env->vfp.qc[0] = qc;                                       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_SQADD_B(N, M, SATP) \
    mve_do_sat_bhs((int64_t)(N) + (M), INT8_MIN, INT8_MAX, SATP)
#define DO_SQADD_H(N, M, SATP) \
    mve_do_sat_bhs((int64_t)(N) + (M), INT16_MIN, INT16_MAX, SATP)
#define DO_SQADD_W(N, M, SATP) \
    mve_do_sat_bhs((int64_t)(N) + (M), INT32_MIN, INT32_MAX, SATP)
#define DO_UQADD_B(N, M, SATP) \
    mve_do_usat_bhs((uint64_t)(N) + (M), UINT8_MAX, SATP)
#define DO_UQADD_H(N, M, SATP) \
    mve_do_usat_bhs((uint64_t)(N) + (M), UINT16_MAX, SATP)
#define DO_UQADD_W(N, M, SATP) \
    mve_do_usat_bhs((uint64_t)(N) + (M), UINT32_MAX, SATP)
#define DO_SQSUB_B(N, M, SATP) \
    mve_do_sat_bhs((int64_t)(N) - (M), INT8_MIN, INT8_MAX, SATP)
#define DO_SQSUB_H(N, M, SATP) \
    mve_do_sat_bhs((int64_t)(N) - (M), INT16_MIN, INT16_MAX, SATP)
#define DO_SQSUB_W(N, M, SATP) \
    mve_do_sat_bhs((int64_t)(N) - (M), INT32_MIN, INT32_MAX, SATP)
#define DO_UQSUB_B(N, M, SATP) \
    mve_do_usat_bhs((uint64_t)(N) - (M), (N) >= (M) ? UINT8_MAX : 0, SATP)
#define DO_UQSUB_H(N, M, SATP) \
    mve_do_usat_bhs((uint64_t)(N) - (M), (N) >= (M) ? UINT16_MAX : 0, SATP)
#define DO_UQSUB_W(N, M, SATP) \
    mve_do_usat_bhs((uint64_t)(N) - (M), (N) >= (M) ? UINT32_MAX : 0, SATP)
#define DO_QDMULH_B(N, M, SATP) \
    mve_do_sat_bhs(((int64_t)(N) * (M)) >> 7, INT8_MIN, INT8_MAX, SATP)
#define DO_QDMULH_H(N, M, SATP) \
    mve_do_sat_bhs(((int64_t)(N) * (M)) >> 15, INT16_MIN, INT16_MAX, SATP)
#define DO_QDMULH_W(N, M, SATP) \
    mve_do_sat_bhs(((int64_t)(N) * (M)) >> 31, INT32_MIN, INT32_MAX, SATP)
#define DO_QRDMULH_B(N, M, SATP) \
    mve_do_sat_bhs((((int64_t)(N) * (M)) + (1 << 6)) >> 7, \
                   INT8_MIN, INT8_MAX, SATP)
#define DO_QRDMULH_H(N, M, SATP) \
    mve_do_sat_bhs((((int64_t)(N) * (M)) + (1 << 14)) >> 15, \
                   INT16_MIN, INT16_MAX, SATP)
#define DO_QRDMULH_W(N, M, SATP) \
    mve_do_sat_bhs((((int64_t)(N) * (M)) + (1 << 30)) >> 31, \
                   INT32_MIN, INT32_MAX, SATP)

#define DO_2OP_SAT_L(OP, TOP, ESIZE, TYPE, LESIZE, LTYPE, MERGE, FN, SATMASK) \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, void *vm)                    \
    {                                                                  \
        LTYPE *d = vd;                                                 \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        bool qc = false;                                               \
        unsigned le;                                                   \
                                                                       \
        for (le = 0; le < 16 / LESIZE; le++, mask >>= LESIZE) {        \
            bool sat = false;                                          \
            LTYPE r = FN(n[glue(H, ESIZE)(le * 2 + TOP)],              \
                         m[glue(H, ESIZE)(le * 2 + TOP)], &sat);       \
                                                                       \
            MERGE(&d[glue(H, LESIZE)(le)], r, mask);                   \
            qc |= sat && (mask & SATMASK);                             \
        }                                                              \
        if (qc) {                                                      \
            env->vfp.qc[0] = qc;                                       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_2OP_SCALAR_SAT_L(OP, TOP, ESIZE, TYPE, LESIZE, LTYPE,       \
                            MERGE, FN, SATMASK)                        \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, uint32_t rm)                 \
    {                                                                  \
        LTYPE *d = vd;                                                 \
        TYPE *n = vn;                                                  \
        TYPE m = (TYPE)rm;                                             \
        uint16_t mask = mve_element_mask(env);                         \
        bool qc = false;                                               \
        unsigned le;                                                   \
                                                                       \
        for (le = 0; le < 16 / LESIZE; le++, mask >>= LESIZE) {        \
            bool sat = false;                                          \
            LTYPE r = FN(n[glue(H, ESIZE)(le * 2 + TOP)], m, &sat);    \
                                                                       \
            MERGE(&d[glue(H, LESIZE)(le)], r, mask);                   \
            qc |= sat && (mask & SATMASK);                             \
        }                                                              \
        if (qc) {                                                      \
            env->vfp.qc[0] = qc;                                       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

static inline int32_t do_qdmull_h(int16_t n, int16_t m, bool *sat)
{
    int64_t r = ((int64_t)n * m) * 2;

    return mve_do_sat_bhs(r, INT32_MIN, INT32_MAX, sat);
}

static inline int64_t do_qdmull_w(int32_t n, int32_t m, bool *sat)
{
    int64_t r = (int64_t)n * m;

    if (r > INT64_MAX / 2) {
        *sat = true;
        return INT64_MAX;
    } else if (r < INT64_MIN / 2) {
        *sat = true;
        return INT64_MIN;
    }
    return r * 2;
}

#define SATMASK16B 1
#define SATMASK16T (1 << 2)
#define SATMASK32 ((1 << 4) | 1)

DO_2OP_SAT(vqaddsb, 1, int8_t, mve_mergemask_sb, DO_SQADD_B)
DO_2OP_SAT(vqaddsh, 2, int16_t, mve_mergemask_sh, DO_SQADD_H)
DO_2OP_SAT(vqaddsw, 4, int32_t, mve_mergemask_sw, DO_SQADD_W)
DO_2OP_SAT(vqaddub, 1, uint8_t, mve_mergemask_ub, DO_UQADD_B)
DO_2OP_SAT(vqadduh, 2, uint16_t, mve_mergemask_uh, DO_UQADD_H)
DO_2OP_SAT(vqadduw, 4, uint32_t, mve_mergemask_uw, DO_UQADD_W)
DO_2OP_SAT(vqsubsb, 1, int8_t, mve_mergemask_sb, DO_SQSUB_B)
DO_2OP_SAT(vqsubsh, 2, int16_t, mve_mergemask_sh, DO_SQSUB_H)
DO_2OP_SAT(vqsubsw, 4, int32_t, mve_mergemask_sw, DO_SQSUB_W)
DO_2OP_SAT(vqsubub, 1, uint8_t, mve_mergemask_ub, DO_UQSUB_B)
DO_2OP_SAT(vqsubuh, 2, uint16_t, mve_mergemask_uh, DO_UQSUB_H)
DO_2OP_SAT(vqsubuw, 4, uint32_t, mve_mergemask_uw, DO_UQSUB_W)
DO_2OP_SAT(vqdmulhb, 1, int8_t, mve_mergemask_sb, DO_QDMULH_B)
DO_2OP_SAT(vqdmulhh, 2, int16_t, mve_mergemask_sh, DO_QDMULH_H)
DO_2OP_SAT(vqdmulhw, 4, int32_t, mve_mergemask_sw, DO_QDMULH_W)
DO_2OP_SAT(vqrdmulhb, 1, int8_t, mve_mergemask_sb, DO_QRDMULH_B)
DO_2OP_SAT(vqrdmulhh, 2, int16_t, mve_mergemask_sh, DO_QRDMULH_H)
DO_2OP_SAT(vqrdmulhw, 4, int32_t, mve_mergemask_sw, DO_QRDMULH_W)
DO_2OP_SCALAR_SAT(vqadds_scalarb, 1, int8_t, mve_mergemask_sb, DO_SQADD_B)
DO_2OP_SCALAR_SAT(vqadds_scalarh, 2, int16_t, mve_mergemask_sh, DO_SQADD_H)
DO_2OP_SCALAR_SAT(vqadds_scalarw, 4, int32_t, mve_mergemask_sw, DO_SQADD_W)
DO_2OP_SCALAR_SAT(vqaddu_scalarb, 1, uint8_t, mve_mergemask_ub, DO_UQADD_B)
DO_2OP_SCALAR_SAT(vqaddu_scalarh, 2, uint16_t, mve_mergemask_uh, DO_UQADD_H)
DO_2OP_SCALAR_SAT(vqaddu_scalarw, 4, uint32_t, mve_mergemask_uw, DO_UQADD_W)
DO_2OP_SCALAR_SAT(vqsubs_scalarb, 1, int8_t, mve_mergemask_sb, DO_SQSUB_B)
DO_2OP_SCALAR_SAT(vqsubs_scalarh, 2, int16_t, mve_mergemask_sh, DO_SQSUB_H)
DO_2OP_SCALAR_SAT(vqsubs_scalarw, 4, int32_t, mve_mergemask_sw, DO_SQSUB_W)
DO_2OP_SCALAR_SAT(vqsubu_scalarb, 1, uint8_t, mve_mergemask_ub, DO_UQSUB_B)
DO_2OP_SCALAR_SAT(vqsubu_scalarh, 2, uint16_t, mve_mergemask_uh, DO_UQSUB_H)
DO_2OP_SCALAR_SAT(vqsubu_scalarw, 4, uint32_t, mve_mergemask_uw, DO_UQSUB_W)
DO_2OP_SCALAR_SAT(vqdmulh_scalarb, 1, int8_t, mve_mergemask_sb, DO_QDMULH_B)
DO_2OP_SCALAR_SAT(vqdmulh_scalarh, 2, int16_t, mve_mergemask_sh, DO_QDMULH_H)
DO_2OP_SCALAR_SAT(vqdmulh_scalarw, 4, int32_t, mve_mergemask_sw, DO_QDMULH_W)
DO_2OP_SCALAR_SAT(vqrdmulh_scalarb, 1, int8_t, mve_mergemask_sb,
                  DO_QRDMULH_B)
DO_2OP_SCALAR_SAT(vqrdmulh_scalarh, 2, int16_t, mve_mergemask_sh,
                  DO_QRDMULH_H)
DO_2OP_SCALAR_SAT(vqrdmulh_scalarw, 4, int32_t, mve_mergemask_sw,
                  DO_QRDMULH_W)

#define DO_VMLA(D, N, M) ((N) * (M) + (D))
#define DO_VMLAS(D, N, M) ((N) * (D) + (M))

DO_2OP_SCALAR_ACC(vmlab, 1, uint8_t, mve_mergemask_ub, DO_VMLA)
DO_2OP_SCALAR_ACC(vmlah, 2, uint16_t, mve_mergemask_uh, DO_VMLA)
DO_2OP_SCALAR_ACC(vmlaw, 4, uint32_t, mve_mergemask_uw, DO_VMLA)
DO_2OP_SCALAR_ACC(vmlasb, 1, uint8_t, mve_mergemask_ub, DO_VMLAS)
DO_2OP_SCALAR_ACC(vmlash, 2, uint16_t, mve_mergemask_uh, DO_VMLAS)
DO_2OP_SCALAR_ACC(vmlasw, 4, uint32_t, mve_mergemask_uw, DO_VMLAS)

static int8_t do_vqdmlah_b(int8_t d, int8_t n, int8_t m, int round,
                           bool *sat)
{
    int64_t r = (int64_t)n * m * 2 + ((int64_t)d << 8) + (round << 7);

    return mve_do_sat_bhs(r, INT16_MIN, INT16_MAX, sat) >> 8;
}

static int16_t do_vqdmlah_h(int16_t d, int16_t n, int16_t m, int round,
                            bool *sat)
{
    int64_t r = (int64_t)n * m * 2 + ((int64_t)d << 16) + (round << 15);

    return mve_do_sat_bhs(r, INT32_MIN, INT32_MAX, sat) >> 16;
}

static int32_t do_vqdmlah_w(int32_t d, int32_t n, int32_t m, int round,
                            bool *sat)
{
    int64_t m1 = (int64_t)n * m;
    int64_t m2 = (int64_t)d << 31;
    int64_t r;

    if (sadd64_overflow(m1, m2, &r) ||
        sadd64_overflow(r, (int64_t)round << 30, &r) ||
        sadd64_overflow(r, r, &r)) {
        *sat = true;
        return r < 0 ? INT32_MAX : INT32_MIN;
    }
    return r >> 32;
}

#define DO_VQDMLAH_B(D, N, M, S) do_vqdmlah_b(D, N, M, 0, S)
#define DO_VQDMLAH_H(D, N, M, S) do_vqdmlah_h(D, N, M, 0, S)
#define DO_VQDMLAH_W(D, N, M, S) do_vqdmlah_w(D, N, M, 0, S)
#define DO_VQRDMLAH_B(D, N, M, S) do_vqdmlah_b(D, N, M, 1, S)
#define DO_VQRDMLAH_H(D, N, M, S) do_vqdmlah_h(D, N, M, 1, S)
#define DO_VQRDMLAH_W(D, N, M, S) do_vqdmlah_w(D, N, M, 1, S)
#define DO_VQDMLASH_B(D, N, M, S) do_vqdmlah_b(M, N, D, 0, S)
#define DO_VQDMLASH_H(D, N, M, S) do_vqdmlah_h(M, N, D, 0, S)
#define DO_VQDMLASH_W(D, N, M, S) do_vqdmlah_w(M, N, D, 0, S)
#define DO_VQRDMLASH_B(D, N, M, S) do_vqdmlah_b(M, N, D, 1, S)
#define DO_VQRDMLASH_H(D, N, M, S) do_vqdmlah_h(M, N, D, 1, S)
#define DO_VQRDMLASH_W(D, N, M, S) do_vqdmlah_w(M, N, D, 1, S)

DO_2OP_SCALAR_SAT_ACC(vqdmlahb, 1, int8_t, mve_mergemask_sb, DO_VQDMLAH_B)
DO_2OP_SCALAR_SAT_ACC(vqdmlahh, 2, int16_t, mve_mergemask_sh, DO_VQDMLAH_H)
DO_2OP_SCALAR_SAT_ACC(vqdmlahw, 4, int32_t, mve_mergemask_sw, DO_VQDMLAH_W)
DO_2OP_SCALAR_SAT_ACC(vqrdmlahb, 1, int8_t, mve_mergemask_sb, DO_VQRDMLAH_B)
DO_2OP_SCALAR_SAT_ACC(vqrdmlahh, 2, int16_t, mve_mergemask_sh, DO_VQRDMLAH_H)
DO_2OP_SCALAR_SAT_ACC(vqrdmlahw, 4, int32_t, mve_mergemask_sw, DO_VQRDMLAH_W)
DO_2OP_SCALAR_SAT_ACC(vqdmlashb, 1, int8_t, mve_mergemask_sb,
                      DO_VQDMLASH_B)
DO_2OP_SCALAR_SAT_ACC(vqdmlashh, 2, int16_t, mve_mergemask_sh,
                      DO_VQDMLASH_H)
DO_2OP_SCALAR_SAT_ACC(vqdmlashw, 4, int32_t, mve_mergemask_sw,
                      DO_VQDMLASH_W)
DO_2OP_SCALAR_SAT_ACC(vqrdmlashb, 1, int8_t, mve_mergemask_sb,
                      DO_VQRDMLASH_B)
DO_2OP_SCALAR_SAT_ACC(vqrdmlashh, 2, int16_t, mve_mergemask_sh,
                      DO_VQRDMLASH_H)
DO_2OP_SCALAR_SAT_ACC(vqrdmlashw, 4, int32_t, mve_mergemask_sw,
                      DO_VQRDMLASH_W)

static uint32_t do_vbrsrb(uint32_t n, uint32_t m)
{
    m &= 0xff;
    if (m == 0) {
        return 0;
    }
    n = revbit8(n);
    if (m < 8) {
        n >>= 8 - m;
    }
    return n;
}

static uint32_t do_vbrsrh(uint32_t n, uint32_t m)
{
    m &= 0xff;
    if (m == 0) {
        return 0;
    }
    n = revbit16(n);
    if (m < 16) {
        n >>= 16 - m;
    }
    return n;
}

static uint32_t do_vbrsrw(uint32_t n, uint32_t m)
{
    m &= 0xff;
    if (m == 0) {
        return 0;
    }
    n = revbit32(n);
    if (m < 32) {
        n >>= 32 - m;
    }
    return n;
}

DO_2OP_SCALAR(vbrsrb, 1, uint8_t, mve_mergemask_ub, do_vbrsrb)
DO_2OP_SCALAR(vbrsrh, 2, uint16_t, mve_mergemask_uh, do_vbrsrh)
DO_2OP_SCALAR(vbrsrw, 4, uint32_t, mve_mergemask_uw, do_vbrsrw)
DO_2OP_SAT_L(vqdmullbh, 0, 2, int16_t, 4, int32_t, mve_mergemask_sw,
             do_qdmull_h, SATMASK16B)
DO_2OP_SAT_L(vqdmullbw, 0, 4, int32_t, 8, int64_t, mve_mergemask_sq,
             do_qdmull_w, SATMASK32)
DO_2OP_SAT_L(vqdmullth, 1, 2, int16_t, 4, int32_t, mve_mergemask_sw,
             do_qdmull_h, SATMASK16T)
DO_2OP_SAT_L(vqdmulltw, 1, 4, int32_t, 8, int64_t, mve_mergemask_sq,
             do_qdmull_w, SATMASK32)
DO_2OP_SCALAR_SAT_L(vqdmullb_scalarh, 0, 2, int16_t, 4, int32_t,
                    mve_mergemask_sw, do_qdmull_h, SATMASK16B)
DO_2OP_SCALAR_SAT_L(vqdmullb_scalarw, 0, 4, int32_t, 8, int64_t,
                    mve_mergemask_sq, do_qdmull_w, SATMASK32)
DO_2OP_SCALAR_SAT_L(vqdmullt_scalarh, 1, 2, int16_t, 4, int32_t,
                    mve_mergemask_sw, do_qdmull_h, SATMASK16T)
DO_2OP_SCALAR_SAT_L(vqdmullt_scalarw, 1, 4, int32_t, 8, int64_t,
                    mve_mergemask_sq, do_qdmull_w, SATMASK32)

#define DO_VCVT_FIXED(OP, ESIZE, TYPE, MERGE, FN)                      \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vm, uint32_t shift)              \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *m = vm;                                                  \
        TYPE r;                                                        \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        float_status *fpst;                                            \
        float_status scratch_fpst;                                     \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE)) == 0) {             \
                continue;                                              \
            }                                                          \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :   \
                &env->vfp.standard_fp_status;                          \
            if (!(mask & 1)) {                                         \
                scratch_fpst = *fpst;                                  \
                fpst = &scratch_fpst;                                  \
            }                                                          \
            r = FN(m[glue(H, ESIZE)(e)], shift, fpst);                 \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_VCVT_FIXED(vcvt_sh, 2, int16_t, mve_mergemask_sh, helper_vfp_shtoh)
DO_VCVT_FIXED(vcvt_uh, 2, uint16_t, mve_mergemask_uh, helper_vfp_uhtoh)
DO_VCVT_FIXED(vcvt_hs, 2, int16_t, mve_mergemask_sh,
              helper_vfp_toshh_round_to_zero)
DO_VCVT_FIXED(vcvt_hu, 2, uint16_t, mve_mergemask_uh,
              helper_vfp_touhh_round_to_zero)
DO_VCVT_FIXED(vcvt_sf, 4, int32_t, mve_mergemask_sw, helper_vfp_sltos)
DO_VCVT_FIXED(vcvt_uf, 4, uint32_t, mve_mergemask_uw, helper_vfp_ultos)
DO_VCVT_FIXED(vcvt_fs, 4, int32_t, mve_mergemask_sw,
              helper_vfp_tosls_round_to_zero)
DO_VCVT_FIXED(vcvt_fu, 4, uint32_t, mve_mergemask_uw,
              helper_vfp_touls_round_to_zero)

#define DO_VCVT_RMODE(OP, ESIZE, TYPE, MERGE, FN)                      \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vm, uint32_t rmode)              \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *m = vm;                                                  \
        TYPE r;                                                        \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        float_status *fpst;                                            \
        float_status scratch_fpst;                                     \
        float_status *base_fpst = (ESIZE == 2) ?                       \
            &env->vfp.standard_fp_status_f16 :                         \
            &env->vfp.standard_fp_status;                              \
        uint32_t prev_rmode = get_float_rounding_mode(base_fpst);      \
                                                                       \
        set_float_rounding_mode(rmode, base_fpst);                     \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE)) == 0) {             \
                continue;                                              \
            }                                                          \
            fpst = base_fpst;                                          \
            if (!(mask & 1)) {                                         \
                scratch_fpst = *fpst;                                  \
                fpst = &scratch_fpst;                                  \
            }                                                          \
            r = FN(m[glue(H, ESIZE)(e)], 0, fpst);                     \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        set_float_rounding_mode(prev_rmode, base_fpst);                \
        mve_advance_vpt(env);                                          \
    }

DO_VCVT_RMODE(vcvt_rm_sh, 2, uint16_t, mve_mergemask_uh, helper_vfp_toshh)
DO_VCVT_RMODE(vcvt_rm_uh, 2, uint16_t, mve_mergemask_uh, helper_vfp_touhh)
DO_VCVT_RMODE(vcvt_rm_ss, 4, uint32_t, mve_mergemask_uw, helper_vfp_tosls)
DO_VCVT_RMODE(vcvt_rm_us, 4, uint32_t, mve_mergemask_uw, helper_vfp_touls)

static inline uint16_t mve_vrint_rm_h(uint16_t m, uint32_t ignored,
                                      float_status *fpst)
{
    (void)ignored;
    return helper_rinth(m, fpst);
}

static inline uint32_t mve_vrint_rm_s(uint32_t m, uint32_t ignored,
                                      float_status *fpst)
{
    (void)ignored;
    return helper_rints(m, fpst);
}

DO_VCVT_RMODE(vrint_rm_h, 2, uint16_t, mve_mergemask_uh, mve_vrint_rm_h)
DO_VCVT_RMODE(vrint_rm_s, 4, uint32_t, mve_mergemask_uw, mve_vrint_rm_s)

static void do_vcvt_sh(CPUARMState *env, void *vd, void *vm, int top)
{
    uint16_t *d = vd;
    uint32_t *m = vm;
    uint16_t r;
    uint16_t mask = mve_element_mask(env);
    bool ieee = !(env->vfp.xregs[ARM_VFP_FPSCR] & FPCR_AHP);
    unsigned e;
    float_status *fpst;
    float_status scratch_fpst;
    float_status *base_fpst = &env->vfp.standard_fp_status;
    bool old_fz = get_flush_to_zero(base_fpst);

    set_flush_to_zero(false, base_fpst);
    for (e = 0; e < 16 / 4; e++, mask >>= 4) {
        if ((mask & MAKE_64BIT_MASK(0, 4)) == 0) {
            continue;
        }
        fpst = base_fpst;
        if (!(mask & 1)) {
            scratch_fpst = *fpst;
            fpst = &scratch_fpst;
        }
        r = float32_to_float16(m[H4(e)], ieee, fpst);
        mve_mergemask_uh(&d[H2(e * 2 + top)], r, mask >> (top * 2));
    }
    set_flush_to_zero(old_fz, base_fpst);
    mve_advance_vpt(env);
}

static void do_vcvt_hs(CPUARMState *env, void *vd, void *vm, int top)
{
    uint32_t *d = vd;
    uint16_t *m = vm;
    uint32_t r;
    uint16_t mask = mve_element_mask(env);
    bool ieee = !(env->vfp.xregs[ARM_VFP_FPSCR] & FPCR_AHP);
    unsigned e;
    float_status *fpst;
    float_status scratch_fpst;
    float_status *base_fpst = &env->vfp.standard_fp_status;
    bool old_fiz = get_flush_inputs_to_zero(base_fpst);

    set_flush_inputs_to_zero(false, base_fpst);
    for (e = 0; e < 16 / 4; e++, mask >>= 4) {
        if ((mask & MAKE_64BIT_MASK(0, 4)) == 0) {
            continue;
        }
        fpst = base_fpst;
        if (!(mask & (1 << (top * 2)))) {
            scratch_fpst = *fpst;
            fpst = &scratch_fpst;
        }
        r = float16_to_float32(m[H2(e * 2 + top)], ieee, fpst);
        mve_mergemask_uw(&d[H4(e)], r, mask);
    }
    set_flush_inputs_to_zero(old_fiz, base_fpst);
    mve_advance_vpt(env);
}

void HELPER(mve_vcvtb_sh)(CPUARMState *env, void *vd, void *vm)
{
    do_vcvt_sh(env, vd, vm, 0);
}

void HELPER(mve_vcvtt_sh)(CPUARMState *env, void *vd, void *vm)
{
    do_vcvt_sh(env, vd, vm, 1);
}

void HELPER(mve_vcvtb_hs)(CPUARMState *env, void *vd, void *vm)
{
    do_vcvt_hs(env, vd, vm, 0);
}

void HELPER(mve_vcvtt_hs)(CPUARMState *env, void *vd, void *vm)
{
    do_vcvt_hs(env, vd, vm, 1);
}

#define DO_1OP_FP(OP, ESIZE, TYPE, MERGE, FN)                          \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd, void *vm)  \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *m = vm;                                                  \
        TYPE r;                                                        \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        float_status *fpst;                                            \
        float_status scratch_fpst;                                     \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE)) == 0) {             \
                continue;                                              \
            }                                                          \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :   \
                &env->vfp.standard_fp_status;                          \
            if (!(mask & 1)) {                                         \
                scratch_fpst = *fpst;                                  \
                fpst = &scratch_fpst;                                  \
            }                                                          \
            r = FN(m[glue(H, ESIZE)(e)], fpst);                        \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_1OP_FP(vrintx_h, 2, uint16_t, mve_mergemask_uh, float16_round_to_int)
DO_1OP_FP(vrintx_s, 4, uint32_t, mve_mergemask_uw, float32_round_to_int)

#define DO_2OP_FP(OP, ESIZE, TYPE, MERGE, FN)                          \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, void *vm)                    \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        float_status *fpst;                                            \
        float_status scratch_fpst;                                     \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            TYPE r;                                                    \
                                                                       \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE)) == 0) {             \
                continue;                                              \
            }                                                          \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :   \
                &env->vfp.standard_fp_status;                          \
            if (!(mask & 1)) {                                         \
                scratch_fpst = *fpst;                                  \
                fpst = &scratch_fpst;                                  \
            }                                                          \
            r = FN(n[glue(H, ESIZE)(e)], m[glue(H, ESIZE)(e)], fpst);  \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_2OP_FP(vfaddh, 2, float16, mve_mergemask_uh, float16_add)
DO_2OP_FP(vfadds, 4, float32, mve_mergemask_uw, float32_add)
DO_2OP_FP(vfsubh, 2, float16, mve_mergemask_uh, float16_sub)
DO_2OP_FP(vfsubs, 4, float32, mve_mergemask_uw, float32_sub)
DO_2OP_FP(vfmulh, 2, float16, mve_mergemask_uh, float16_mul)
DO_2OP_FP(vfmuls, 4, float32, mve_mergemask_uw, float32_mul)

static inline float16 float16_abd(float16 a, float16 b, float_status *s)
{
    return make_float16(float16_val(float16_sub(a, b, s)) & 0x7fff);
}

static inline float32 float32_abd(float32 a, float32 b, float_status *s)
{
    return make_float32(float32_val(float32_sub(a, b, s)) & 0x7fffffff);
}

DO_2OP_FP(vfabdh, 2, float16, mve_mergemask_uh, float16_abd)
DO_2OP_FP(vfabds, 4, float32, mve_mergemask_uw, float32_abd)
DO_2OP_FP(vmaxnmh, 2, float16, mve_mergemask_uh, float16_maxnum)
DO_2OP_FP(vmaxnms, 4, float32, mve_mergemask_uw, float32_maxnum)
DO_2OP_FP(vminnmh, 2, float16, mve_mergemask_uh, float16_minnum)
DO_2OP_FP(vminnms, 4, float32, mve_mergemask_uw, float32_minnum)

static inline float16 float16_maxnuma(float16 a, float16 b, float_status *s)
{
    return float16_maxnum(float16_abs(a), float16_abs(b), s);
}

static inline float32 float32_maxnuma(float32 a, float32 b, float_status *s)
{
    return float32_maxnum(float32_abs(a), float32_abs(b), s);
}

static inline float16 float16_minnuma(float16 a, float16 b, float_status *s)
{
    return float16_minnum(float16_abs(a), float16_abs(b), s);
}

static inline float32 float32_minnuma(float32 a, float32 b, float_status *s)
{
    return float32_minnum(float32_abs(a), float32_abs(b), s);
}

DO_2OP_FP(vmaxnmah, 2, float16, mve_mergemask_uh, float16_maxnuma)
DO_2OP_FP(vmaxnmas, 4, float32, mve_mergemask_uw, float32_maxnuma)
DO_2OP_FP(vminnmah, 2, float16, mve_mergemask_uh, float16_minnuma)
DO_2OP_FP(vminnmas, 4, float32, mve_mergemask_uw, float32_minnuma)

#define DO_VCADD_FP(OP, ESIZE, TYPE, MERGE, FN0, FN1)                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,             \
                                void *vn, void *vm)                    \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        TYPE r[16 / ESIZE];                                            \
        uint16_t tm;                                                   \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        float_status *fpst;                                            \
        float_status scratch_fpst;                                     \
                                                                       \
        for (e = 0, tm = mask; e < 16 / ESIZE; e++, tm >>= ESIZE) {    \
            if ((tm & MAKE_64BIT_MASK(0, ESIZE)) == 0) {               \
                r[e] = 0;                                              \
                continue;                                              \
            }                                                          \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :   \
                &env->vfp.standard_fp_status;                          \
            if (!(tm & 1)) {                                           \
                scratch_fpst = *fpst;                                  \
                fpst = &scratch_fpst;                                  \
            }                                                          \
            if (!(e & 1)) {                                            \
                r[e] = FN0(n[glue(H, ESIZE)(e)],                       \
                           m[glue(H, ESIZE)(e + 1)], fpst);            \
            } else {                                                   \
                r[e] = FN1(n[glue(H, ESIZE)(e)],                       \
                           m[glue(H, ESIZE)(e - 1)], fpst);            \
            }                                                          \
        }                                                              \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            MERGE(&d[glue(H, ESIZE)(e)], r[e], mask);                  \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_VCADD_FP(vfcadd90h, 2, float16, mve_mergemask_uh, float16_sub,
            float16_add)
DO_VCADD_FP(vfcadd90s, 4, float32, mve_mergemask_uw, float32_sub,
            float32_add)
DO_VCADD_FP(vfcadd270h, 2, float16, mve_mergemask_uh, float16_add,
            float16_sub)
DO_VCADD_FP(vfcadd270s, 4, float32, mve_mergemask_uw, float32_add,
            float32_sub)

static inline float16 mve_float16_chs(float16 a)
{
    return make_float16(float16_val(a) ^ 0x8000);
}

static inline float32 mve_float32_chs(float32 a)
{
    return make_float32(float32_val(a) ^ 0x80000000);
}

static inline float16 mve_float16_fma(float16 n, float16 m, float16 d,
                                      float_status *s)
{
    return float16_muladd(n, m, d, 0, s);
}

static inline float32 mve_float32_fma(float32 n, float32 m, float32 d,
                                      float_status *s)
{
    return float32_muladd(n, m, d, 0, s);
}

static inline float16 mve_float16_fms(float16 n, float16 m, float16 d,
                                      float_status *s)
{
    return float16_muladd(mve_float16_chs(n), m, d, 0, s);
}

static inline float32 mve_float32_fms(float32 n, float32 m, float32 d,
                                      float_status *s)
{
    return float32_muladd(mve_float32_chs(n), m, d, 0, s);
}

#define DO_VCMUL_FP(OP, ESIZE, TYPE, MERGE, CHS, MUL, ROT)             \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,             \
                                void *vn, void *vm)                    \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        TYPE e1;                                                       \
        TYPE e2;                                                       \
        TYPE e3;                                                       \
        TYPE e4;                                                       \
        TYPE r0;                                                       \
        TYPE r1;                                                       \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        float_status *fpst0;                                           \
        float_status *fpst1;                                           \
        float_status scratch_fpst0;                                    \
        float_status scratch_fpst1;                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e += 2, mask >>= ESIZE * 2) {      \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE * 2)) == 0) {         \
                continue;                                              \
            }                                                          \
            fpst0 = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :  \
                &env->vfp.standard_fp_status;                          \
            fpst1 = fpst0;                                             \
            if (!(mask & 1)) {                                         \
                scratch_fpst0 = *fpst0;                                \
                fpst0 = &scratch_fpst0;                                \
            }                                                          \
            if (!(mask & (1 << ESIZE))) {                              \
                scratch_fpst1 = *fpst1;                                \
                fpst1 = &scratch_fpst1;                                \
            }                                                          \
            switch (ROT) {                                             \
            case 0:                                                    \
                e1 = m[glue(H, ESIZE)(e)];                             \
                e2 = n[glue(H, ESIZE)(e)];                             \
                e3 = m[glue(H, ESIZE)(e + 1)];                         \
                e4 = n[glue(H, ESIZE)(e)];                             \
                break;                                                 \
            case 1:                                                    \
                e1 = CHS(m[glue(H, ESIZE)(e + 1)]);                    \
                e2 = n[glue(H, ESIZE)(e + 1)];                         \
                e3 = m[glue(H, ESIZE)(e)];                             \
                e4 = n[glue(H, ESIZE)(e + 1)];                         \
                break;                                                 \
            case 2:                                                    \
                e1 = CHS(m[glue(H, ESIZE)(e)]);                        \
                e2 = n[glue(H, ESIZE)(e)];                             \
                e3 = CHS(m[glue(H, ESIZE)(e + 1)]);                    \
                e4 = n[glue(H, ESIZE)(e)];                             \
                break;                                                 \
            case 3:                                                    \
                e1 = m[glue(H, ESIZE)(e + 1)];                         \
                e2 = n[glue(H, ESIZE)(e + 1)];                         \
                e3 = CHS(m[glue(H, ESIZE)(e)]);                        \
                e4 = n[glue(H, ESIZE)(e + 1)];                         \
                break;                                                 \
            default:                                                   \
                g_assert_not_reached();                                \
            }                                                          \
            r0 = MUL(e2, e1, fpst0);                                   \
            r1 = MUL(e4, e3, fpst1);                                   \
            MERGE(&d[glue(H, ESIZE)(e)], r0, mask);                    \
            MERGE(&d[glue(H, ESIZE)(e + 1)], r1, mask >> ESIZE);       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_VCMUL_FP(vcmul0h, 2, float16, mve_mergemask_uh, mve_float16_chs,
            float16_mul, 0)
DO_VCMUL_FP(vcmul0s, 4, float32, mve_mergemask_uw, mve_float32_chs,
            float32_mul, 0)
DO_VCMUL_FP(vcmul90h, 2, float16, mve_mergemask_uh, mve_float16_chs,
            float16_mul, 1)
DO_VCMUL_FP(vcmul90s, 4, float32, mve_mergemask_uw, mve_float32_chs,
            float32_mul, 1)
DO_VCMUL_FP(vcmul180h, 2, float16, mve_mergemask_uh, mve_float16_chs,
            float16_mul, 2)
DO_VCMUL_FP(vcmul180s, 4, float32, mve_mergemask_uw, mve_float32_chs,
            float32_mul, 2)
DO_VCMUL_FP(vcmul270h, 2, float16, mve_mergemask_uh, mve_float16_chs,
            float16_mul, 3)
DO_VCMUL_FP(vcmul270s, 4, float32, mve_mergemask_uw, mve_float32_chs,
            float32_mul, 3)

#define DO_VCMLA_FP(OP, ESIZE, TYPE, MERGE, CHS, MULADD, ROT)          \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,             \
                                void *vn, void *vm)                    \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        TYPE e1;                                                       \
        TYPE e2;                                                       \
        TYPE e3;                                                       \
        TYPE e4;                                                       \
        TYPE r0;                                                       \
        TYPE r1;                                                       \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
        float_status *fpst0;                                           \
        float_status *fpst1;                                           \
        float_status scratch_fpst0;                                    \
        float_status scratch_fpst1;                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e += 2, mask >>= ESIZE * 2) {      \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE * 2)) == 0) {         \
                continue;                                              \
            }                                                          \
            fpst0 = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :  \
                &env->vfp.standard_fp_status;                          \
            fpst1 = fpst0;                                             \
            if (!(mask & 1)) {                                         \
                scratch_fpst0 = *fpst0;                                \
                fpst0 = &scratch_fpst0;                                \
            }                                                          \
            if (!(mask & (1 << ESIZE))) {                              \
                scratch_fpst1 = *fpst1;                                \
                fpst1 = &scratch_fpst1;                                \
            }                                                          \
            switch (ROT) {                                             \
            case 0:                                                    \
                e1 = m[glue(H, ESIZE)(e)];                             \
                e2 = n[glue(H, ESIZE)(e)];                             \
                e3 = m[glue(H, ESIZE)(e + 1)];                         \
                e4 = n[glue(H, ESIZE)(e)];                             \
                break;                                                 \
            case 1:                                                    \
                e1 = CHS(m[glue(H, ESIZE)(e + 1)]);                    \
                e2 = n[glue(H, ESIZE)(e + 1)];                         \
                e3 = m[glue(H, ESIZE)(e)];                             \
                e4 = n[glue(H, ESIZE)(e + 1)];                         \
                break;                                                 \
            case 2:                                                    \
                e1 = CHS(m[glue(H, ESIZE)(e)]);                        \
                e2 = n[glue(H, ESIZE)(e)];                             \
                e3 = CHS(m[glue(H, ESIZE)(e + 1)]);                    \
                e4 = n[glue(H, ESIZE)(e)];                             \
                break;                                                 \
            case 3:                                                    \
                e1 = m[glue(H, ESIZE)(e + 1)];                         \
                e2 = n[glue(H, ESIZE)(e + 1)];                         \
                e3 = CHS(m[glue(H, ESIZE)(e)]);                        \
                e4 = n[glue(H, ESIZE)(e + 1)];                         \
                break;                                                 \
            default:                                                   \
                g_assert_not_reached();                                \
            }                                                          \
            r0 = MULADD(e2, e1, d[glue(H, ESIZE)(e)], fpst0);          \
            r1 = MULADD(e4, e3, d[glue(H, ESIZE)(e + 1)], fpst1);      \
            MERGE(&d[glue(H, ESIZE)(e)], r0, mask);                    \
            MERGE(&d[glue(H, ESIZE)(e + 1)], r1, mask >> ESIZE);       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_VCMLA_FP(vcmla0h, 2, float16, mve_mergemask_uh, mve_float16_chs,
            mve_float16_fma, 0)
DO_VCMLA_FP(vcmla0s, 4, float32, mve_mergemask_uw, mve_float32_chs,
            mve_float32_fma, 0)
DO_VCMLA_FP(vcmla90h, 2, float16, mve_mergemask_uh, mve_float16_chs,
            mve_float16_fma, 1)
DO_VCMLA_FP(vcmla90s, 4, float32, mve_mergemask_uw, mve_float32_chs,
            mve_float32_fma, 1)
DO_VCMLA_FP(vcmla180h, 2, float16, mve_mergemask_uh, mve_float16_chs,
            mve_float16_fma, 2)
DO_VCMLA_FP(vcmla180s, 4, float32, mve_mergemask_uw, mve_float32_chs,
            mve_float32_fma, 2)
DO_VCMLA_FP(vcmla270h, 2, float16, mve_mergemask_uh, mve_float16_chs,
            mve_float16_fma, 3)
DO_VCMLA_FP(vcmla270s, 4, float32, mve_mergemask_uw, mve_float32_chs,
            mve_float32_fma, 3)

#define DO_2OP_FP_ACC(OP, ESIZE, TYPE, MERGE, FN)                       \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,             \
                                void *vn, void *vm)                     \
    {                                                                   \
        TYPE *d = vd;                                                   \
        TYPE *n = vn;                                                   \
        TYPE *m = vm;                                                   \
        uint16_t mask = mve_element_mask(env);                          \
        unsigned e;                                                     \
        float_status *fpst;                                             \
        float_status scratch_fpst;                                      \
                                                                        \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {              \
            TYPE r;                                                     \
                                                                        \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE)) == 0) {              \
                continue;                                               \
            }                                                           \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :    \
                &env->vfp.standard_fp_status;                           \
            if (!(mask & 1)) {                                          \
                scratch_fpst = *fpst;                                   \
                fpst = &scratch_fpst;                                   \
            }                                                           \
            r = FN(n[glue(H, ESIZE)(e)], m[glue(H, ESIZE)(e)],          \
                   d[glue(H, ESIZE)(e)], fpst);                         \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                      \
        }                                                               \
        mve_advance_vpt(env);                                           \
    }

DO_2OP_FP_ACC(vfmah, 2, float16, mve_mergemask_uh, mve_float16_fma)
DO_2OP_FP_ACC(vfmas, 4, float32, mve_mergemask_uw, mve_float32_fma)
DO_2OP_FP_ACC(vfmsh, 2, float16, mve_mergemask_uh, mve_float16_fms)
DO_2OP_FP_ACC(vfmss, 4, float32, mve_mergemask_uw, mve_float32_fms)

#define DO_2OP_FP_SCALAR(OP, ESIZE, TYPE, MERGE, FN)                    \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,             \
                                void *vn, uint32_t rm)                  \
    {                                                                   \
        TYPE *d = vd;                                                   \
        TYPE *n = vn;                                                   \
        TYPE m = (TYPE)rm;                                              \
        uint16_t mask = mve_element_mask(env);                          \
        unsigned e;                                                     \
        float_status *fpst;                                             \
        float_status scratch_fpst;                                      \
                                                                        \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {              \
            TYPE r;                                                     \
                                                                        \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE)) == 0) {              \
                continue;                                               \
            }                                                           \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :    \
                &env->vfp.standard_fp_status;                           \
            if (!(mask & 1)) {                                          \
                scratch_fpst = *fpst;                                   \
                fpst = &scratch_fpst;                                   \
            }                                                           \
            r = FN(n[glue(H, ESIZE)(e)], m, fpst);                      \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                      \
        }                                                               \
        mve_advance_vpt(env);                                           \
    }

DO_2OP_FP_SCALAR(vfadd_scalarh, 2, float16, mve_mergemask_uh, float16_add)
DO_2OP_FP_SCALAR(vfadd_scalars, 4, float32, mve_mergemask_uw, float32_add)
DO_2OP_FP_SCALAR(vfsub_scalarh, 2, float16, mve_mergemask_uh, float16_sub)
DO_2OP_FP_SCALAR(vfsub_scalars, 4, float32, mve_mergemask_uw, float32_sub)
DO_2OP_FP_SCALAR(vfmul_scalarh, 2, float16, mve_mergemask_uh, float16_mul)
DO_2OP_FP_SCALAR(vfmul_scalars, 4, float32, mve_mergemask_uw, float32_mul)

#define DO_2OP_FP_ACC_SCALAR(OP, ESIZE, TYPE, MERGE, FN)                \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,             \
                                void *vn, uint32_t rm)                  \
    {                                                                   \
        TYPE *d = vd;                                                   \
        TYPE *n = vn;                                                   \
        TYPE m = (TYPE)rm;                                              \
        uint16_t mask = mve_element_mask(env);                          \
        unsigned e;                                                     \
        float_status *fpst;                                             \
        float_status scratch_fpst;                                      \
                                                                        \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {              \
            TYPE r;                                                     \
                                                                        \
            if ((mask & MAKE_64BIT_MASK(0, ESIZE)) == 0) {              \
                continue;                                               \
            }                                                           \
            fpst = (ESIZE == 2) ? &env->vfp.standard_fp_status_f16 :    \
                &env->vfp.standard_fp_status;                           \
            if (!(mask & 1)) {                                          \
                scratch_fpst = *fpst;                                   \
                fpst = &scratch_fpst;                                   \
            }                                                           \
            r = FN(n[glue(H, ESIZE)(e)], m, d[glue(H, ESIZE)(e)],       \
                   0, fpst);                                           \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                      \
        }                                                               \
        mve_advance_vpt(env);                                           \
    }

#define DO_VFMAS_SCALARH(N, M, D, F, S) float16_muladd(N, D, M, F, S)
#define DO_VFMAS_SCALARS(N, M, D, F, S) float32_muladd(N, D, M, F, S)

DO_2OP_FP_ACC_SCALAR(vfma_scalarh, 2, float16, mve_mergemask_uh,
                     float16_muladd)
DO_2OP_FP_ACC_SCALAR(vfma_scalars, 4, float32, mve_mergemask_uw,
                     float32_muladd)
DO_2OP_FP_ACC_SCALAR(vfmas_scalarh, 2, float16, mve_mergemask_uh,
                     DO_VFMAS_SCALARH)
DO_2OP_FP_ACC_SCALAR(vfmas_scalars, 4, float32, mve_mergemask_uw,
                     DO_VFMAS_SCALARS)

static inline int32_t do_vshl_s(int32_t n, int32_t m, unsigned bits,
                                bool rounded)
{
    int8_t shift = (int8_t)m;

    if (shift <= -(int)bits) {
        return rounded ? 0 : n >> 31;
    } else if (shift < 0) {
        if (rounded) {
            n >>= -shift - 1;
            return (n >> 1) + (n & 1);
        }
        return n >> -shift;
    } else if (shift < (int)bits) {
        uint32_t val = (uint32_t)n << shift;

        if (bits == 32) {
            return val;
        }
        return sextract32(val, 0, bits);
    }
    return 0;
}

static inline uint32_t do_vshl_u(uint32_t n, uint32_t m, unsigned bits,
                                 bool rounded)
{
    int8_t shift = (int8_t)m;

    if (shift <= -((int)bits + rounded)) {
        return 0;
    } else if (shift < 0) {
        if (rounded) {
            n >>= -shift - 1;
            return (n >> 1) + (n & 1);
        }
        return n >> -shift;
    } else if (shift < (int)bits) {
        uint32_t val = n << shift;

        if (bits == 32) {
            return val;
        }
        return extract32(val, 0, bits);
    }
    return 0;
}

static inline int8_t do_vshl_s_b(int8_t n, int8_t m)
{
    return do_vshl_s(n, m, 8, false);
}

static inline int16_t do_vshl_s_h(int16_t n, int16_t m)
{
    return do_vshl_s(n, m, 16, false);
}

static inline int32_t do_vshl_s_w(int32_t n, int32_t m)
{
    return do_vshl_s(n, m, 32, false);
}

static inline uint8_t do_vshl_u_b(uint8_t n, uint8_t m)
{
    return do_vshl_u(n, m, 8, false);
}

static inline uint16_t do_vshl_u_h(uint16_t n, uint16_t m)
{
    return do_vshl_u(n, m, 16, false);
}

static inline uint32_t do_vshl_u_w(uint32_t n, uint32_t m)
{
    return do_vshl_u(n, m, 32, false);
}

static inline int8_t do_vrshl_s_b(int8_t n, int8_t m)
{
    return do_vshl_s(n, m, 8, true);
}

static inline int16_t do_vrshl_s_h(int16_t n, int16_t m)
{
    return do_vshl_s(n, m, 16, true);
}

static inline int32_t do_vrshl_s_w(int32_t n, int32_t m)
{
    return do_vshl_s(n, m, 32, true);
}

static inline uint8_t do_vrshl_u_b(uint8_t n, uint8_t m)
{
    return do_vshl_u(n, m, 8, true);
}

static inline uint16_t do_vrshl_u_h(uint16_t n, uint16_t m)
{
    return do_vshl_u(n, m, 16, true);
}

static inline uint32_t do_vrshl_u_w(uint32_t n, uint32_t m)
{
    return do_vshl_u(n, m, 32, true);
}

DO_2OP(vshlsb, 1, int8_t, mve_mergemask_sb, do_vshl_s_b)
DO_2OP(vshlsh, 2, int16_t, mve_mergemask_sh, do_vshl_s_h)
DO_2OP(vshlsw, 4, int32_t, mve_mergemask_sw, do_vshl_s_w)
DO_2OP(vshlub, 1, uint8_t, mve_mergemask_ub, do_vshl_u_b)
DO_2OP(vshluh, 2, uint16_t, mve_mergemask_uh, do_vshl_u_h)
DO_2OP(vshluw, 4, uint32_t, mve_mergemask_uw, do_vshl_u_w)
DO_2OP(vrshlsb, 1, int8_t, mve_mergemask_sb, do_vrshl_s_b)
DO_2OP(vrshlsh, 2, int16_t, mve_mergemask_sh, do_vrshl_s_h)
DO_2OP(vrshlsw, 4, int32_t, mve_mergemask_sw, do_vrshl_s_w)
DO_2OP(vrshlub, 1, uint8_t, mve_mergemask_ub, do_vrshl_u_b)
DO_2OP(vrshluh, 2, uint16_t, mve_mergemask_uh, do_vrshl_u_h)
DO_2OP(vrshluw, 4, uint32_t, mve_mergemask_uw, do_vrshl_u_w)

#define DO_2SHIFT_IMM(OP, ESIZE, TYPE, MERGE, FN)                      \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vm, uint32_t shift)              \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            TYPE r = FN(m[glue(H, ESIZE)(e)], shift);                  \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_2SHIFT_IMM_U(OP, FN)                                        \
    DO_2SHIFT_IMM(OP##b, 1, uint8_t, mve_mergemask_ub, FN##_b)         \
    DO_2SHIFT_IMM(OP##h, 2, uint16_t, mve_mergemask_uh, FN##_h)        \
    DO_2SHIFT_IMM(OP##w, 4, uint32_t, mve_mergemask_uw, FN##_w)

#define DO_2SHIFT_IMM_S(OP, FN)                                        \
    DO_2SHIFT_IMM(OP##b, 1, int8_t, mve_mergemask_sb, FN##_b)          \
    DO_2SHIFT_IMM(OP##h, 2, int16_t, mve_mergemask_sh, FN##_h)         \
    DO_2SHIFT_IMM(OP##w, 4, int32_t, mve_mergemask_sw, FN##_w)

DO_2SHIFT_IMM_U(vshli_u, do_vshl_u)
DO_2SHIFT_IMM_S(vshli_s, do_vshl_s)
DO_2SHIFT_IMM_U(vrshli_u, do_vrshl_u)
DO_2SHIFT_IMM_S(vrshli_s, do_vrshl_s)

#define DO_2SHIFT_IMM_SAT(OP, ESIZE, TYPE, MERGE, FN)                 \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,           \
                                void *vm, uint32_t shift)             \
    {                                                                 \
        TYPE *d = vd;                                                 \
        TYPE *m = vm;                                                 \
        uint16_t mask = mve_element_mask(env);                        \
        bool qc = false;                                              \
        unsigned e;                                                   \
                                                                      \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {            \
            bool sat = false;                                         \
            TYPE r = FN(m[glue(H, ESIZE)(e)], shift, &sat);           \
                                                                      \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                    \
            qc |= sat && (mask & 1);                                  \
        }                                                             \
        if (qc) {                                                     \
            env->vfp.qc[0] = qc;                                      \
        }                                                             \
        mve_advance_vpt(env);                                         \
    }

#define DO_2SHIFT_IMM_SAT_U(OP, FN)                                   \
    DO_2SHIFT_IMM_SAT(OP##b, 1, uint8_t, mve_mergemask_ub, FN##_B)    \
    DO_2SHIFT_IMM_SAT(OP##h, 2, uint16_t, mve_mergemask_uh, FN##_H)   \
    DO_2SHIFT_IMM_SAT(OP##w, 4, uint32_t, mve_mergemask_uw, FN##_W)

#define DO_2SHIFT_IMM_SAT_S(OP, FN)                                   \
    DO_2SHIFT_IMM_SAT(OP##b, 1, int8_t, mve_mergemask_sb, FN##_B)     \
    DO_2SHIFT_IMM_SAT(OP##h, 2, int16_t, mve_mergemask_sh, FN##_H)    \
    DO_2SHIFT_IMM_SAT(OP##w, 4, int32_t, mve_mergemask_sw, FN##_W)

#define DO_SQSHLI_B(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs((int64_t)(N) * (1LL << (SHIFT)),                   \
                   INT8_MIN, INT8_MAX, SATP)
#define DO_SQSHLI_H(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs((int64_t)(N) * (1LL << (SHIFT)),                   \
                   INT16_MIN, INT16_MAX, SATP)
#define DO_SQSHLI_W(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs((int64_t)(N) * (1LL << (SHIFT)),                   \
                   INT32_MIN, INT32_MAX, SATP)
#define DO_UQSHLI_B(N, SHIFT, SATP)                                   \
    mve_do_usat_bhs((uint64_t)(N) << (SHIFT), UINT8_MAX, SATP)
#define DO_UQSHLI_H(N, SHIFT, SATP)                                   \
    mve_do_usat_bhs((uint64_t)(N) << (SHIFT), UINT16_MAX, SATP)
#define DO_UQSHLI_W(N, SHIFT, SATP)                                   \
    mve_do_usat_bhs((uint64_t)(N) << (SHIFT), UINT32_MAX, SATP)

static inline int32_t mve_do_sqrshl_bhs(int32_t src, int32_t shift,
                                        int bits, bool round, bool *satp)
{
    if (shift <= -bits) {
        return round ? 0 : src >> 31;
    } else if (shift < 0) {
        if (round) {
            src >>= -shift - 1;
            return (src >> 1) + (src & 1);
        }
        return src >> -shift;
    } else if (shift < bits) {
        uint32_t val_u = (uint32_t)src << shift;
        int32_t val = (int32_t)val_u;

        if (bits == 32) {
            if (val >> shift == src) {
                return val;
            }
        } else {
            int32_t extval = sextract32(val, 0, bits);

            if (val == extval) {
                return extval;
            }
        }
    } else if (src == 0) {
        return 0;
    }

    *satp = true;
    return (1u << (bits - 1)) - (src >= 0);
}

static inline uint32_t mve_do_uqrshl_bhs(uint32_t src, int32_t shift,
                                         int bits, bool round, bool *satp)
{
    if (shift <= -(bits + round)) {
        return 0;
    } else if (shift < 0) {
        if (round) {
            src >>= -shift - 1;
            return (src >> 1) + (src & 1);
        }
        return src >> -shift;
    } else if (shift < bits) {
        uint32_t val = src << shift;

        if (bits == 32) {
            if (val >> shift == src) {
                return val;
            }
        } else {
            uint32_t extval = extract32(val, 0, bits);

            if (val == extval) {
                return extval;
            }
        }
    } else if (src == 0) {
        return 0;
    }

    *satp = true;
    return (uint32_t)MAKE_64BIT_MASK(0, bits);
}

static inline uint32_t mve_do_suqrshl_bhs(int32_t src, int32_t shift,
                                          int bits, bool round, bool *satp)
{
    if (src < 0) {
        *satp = true;
        return 0;
    }
    return mve_do_uqrshl_bhs((uint32_t)src, shift, bits, round, satp);
}

static inline int64_t mve_do_sqrshl_d(int64_t src, int64_t shift,
                                      bool round, bool *satp)
{
    if (shift <= -64) {
        return round ? 0 : src >> 63;
    } else if (shift < 0) {
        if (round) {
            src >>= -shift - 1;
            return (src >> 1) + (src & 1);
        }
        return src >> -shift;
    } else if (shift < 64) {
        uint64_t val_u = (uint64_t)src << shift;
        int64_t val = (int64_t)val_u;

        if (!satp || val >> shift == src) {
            return val;
        }
    } else if (!satp || src == 0) {
        return 0;
    }

    *satp = true;
    return src >= 0 ? INT64_MAX : INT64_MIN;
}

static inline uint64_t mve_do_uqrshl_d(uint64_t src, int64_t shift,
                                       bool round, bool *satp)
{
    if (shift <= -(64 + round)) {
        return 0;
    } else if (shift < 0) {
        if (round) {
            src >>= -shift - 1;
            return (src >> 1) + (src & 1);
        }
        return src >> -shift;
    } else if (shift < 64) {
        uint64_t val = src << shift;

        if (!satp || val >> shift == src) {
            return val;
        }
    } else if (!satp || src == 0) {
        return 0;
    }

    *satp = true;
    return UINT64_MAX;
}

static inline int64_t mve_do_sqrshl48_d(int64_t src, int64_t shift,
                                        bool round, bool *satp)
{
    int64_t val;
    int64_t extval;

    if (shift <= -48) {
        return round ? 0 : src >> 63;
    } else if (shift < 0) {
        if (round) {
            src >>= -shift - 1;
            val = (src >> 1) + (src & 1);
        } else {
            val = src >> -shift;
        }
        extval = sextract64(val, 0, 48);
        if (val == extval) {
            return extval;
        }
    } else if (shift < 48) {
        extval = sextract64((uint64_t)src << shift, 0, 48);
        if (src == (extval >> shift)) {
            return extval;
        }
    } else if (src == 0) {
        return 0;
    }

    if (satp) {
        *satp = true;
    }
    return src >= 0 ? MAKE_64BIT_MASK(0, 47) : MAKE_64BIT_MASK(47, 17);
}

static inline uint64_t mve_do_uqrshl48_d(uint64_t src, int64_t shift,
                                         bool round, bool *satp)
{
    uint64_t val;
    uint64_t extval;

    if (shift <= -(48 + round)) {
        return 0;
    } else if (shift < 0) {
        if (round) {
            val = src >> (-shift - 1);
            val = (val >> 1) + (val & 1);
        } else {
            val = src >> -shift;
        }
        extval = extract64(val, 0, 48);
        if (val == extval) {
            return extval;
        }
    } else if (shift < 48) {
        extval = extract64(src << shift, 0, 48);
        if (src == (extval >> shift)) {
            return extval;
        }
    } else if (src == 0) {
        return 0;
    }

    if (satp) {
        *satp = true;
    }
    return MAKE_64BIT_MASK(0, 48);
}

uint64_t HELPER(mve_sshrl)(CPUARMState *env, uint64_t n, uint32_t shift)
{
    return mve_do_sqrshl_d(n, -(int8_t)shift, false, NULL);
}

uint64_t HELPER(mve_ushll)(CPUARMState *env, uint64_t n, uint32_t shift)
{
    return mve_do_uqrshl_d(n, (int8_t)shift, false, NULL);
}

uint64_t HELPER(mve_sqshll)(CPUARMState *env, uint64_t n, uint32_t shift)
{
    bool sat = false;
    uint64_t ret = mve_do_sqrshl_d(n, (int8_t)shift, false, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint64_t HELPER(mve_uqshll)(CPUARMState *env, uint64_t n, uint32_t shift)
{
    bool sat = false;
    uint64_t ret = mve_do_uqrshl_d(n, (int8_t)shift, false, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint64_t HELPER(mve_sqrshrl)(CPUARMState *env, uint64_t n, uint32_t shift)
{
    bool sat = false;
    uint64_t ret = mve_do_sqrshl_d(n, -(int8_t)shift, true, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint64_t HELPER(mve_uqrshll)(CPUARMState *env, uint64_t n, uint32_t shift)
{
    bool sat = false;
    uint64_t ret = mve_do_uqrshl_d(n, (int8_t)shift, true, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint64_t HELPER(mve_sqrshrl48)(CPUARMState *env, uint64_t n, uint32_t shift)
{
    bool sat = false;
    uint64_t ret = mve_do_sqrshl48_d(n, -(int8_t)shift, true, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint64_t HELPER(mve_uqrshll48)(CPUARMState *env, uint64_t n, uint32_t shift)
{
    bool sat = false;
    uint64_t ret = mve_do_uqrshl48_d(n, (int8_t)shift, true, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint32_t HELPER(mve_uqshl)(CPUARMState *env, uint32_t n, uint32_t shift)
{
    bool sat = false;
    uint32_t ret = mve_do_uqrshl_bhs(n, (int8_t)shift, 32, false, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint32_t HELPER(mve_sqshl)(CPUARMState *env, uint32_t n, uint32_t shift)
{
    bool sat = false;
    uint32_t ret = mve_do_sqrshl_bhs(n, (int8_t)shift, 32, false, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint32_t HELPER(mve_uqrshl)(CPUARMState *env, uint32_t n, uint32_t shift)
{
    bool sat = false;
    uint32_t ret = mve_do_uqrshl_bhs(n, (int8_t)shift, 32, true, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

uint32_t HELPER(mve_sqrshr)(CPUARMState *env, uint32_t n, uint32_t shift)
{
    bool sat = false;
    uint32_t ret = mve_do_sqrshl_bhs(n, -(int8_t)shift, 32, true, &sat);

    if (sat) {
        env->vfp.qc[0] = 1;
    }
    return ret;
}

#undef DO_SQSHLI_B
#undef DO_SQSHLI_H
#undef DO_SQSHLI_W
#undef DO_UQSHLI_B
#undef DO_UQSHLI_H
#undef DO_UQSHLI_W

#define DO_SQSHLI_B(N, SHIFT, SATP)                                   \
    mve_do_sqrshl_bhs((int8_t)(N), (int8_t)(SHIFT), 8, false, SATP)
#define DO_SQSHLI_H(N, SHIFT, SATP)                                   \
    mve_do_sqrshl_bhs((int16_t)(N), (int8_t)(SHIFT), 16, false, SATP)
#define DO_SQSHLI_W(N, SHIFT, SATP)                                   \
    mve_do_sqrshl_bhs((int32_t)(N), (int8_t)(SHIFT), 32, false, SATP)
#define DO_UQSHLI_B(N, SHIFT, SATP)                                   \
    mve_do_uqrshl_bhs((uint8_t)(N), (int8_t)(SHIFT), 8, false, SATP)
#define DO_UQSHLI_H(N, SHIFT, SATP)                                   \
    mve_do_uqrshl_bhs((uint16_t)(N), (int8_t)(SHIFT), 16, false, SATP)
#define DO_UQSHLI_W(N, SHIFT, SATP)                                   \
    mve_do_uqrshl_bhs((uint32_t)(N), (int8_t)(SHIFT), 32, false, SATP)
#define DO_SQRSHLI_B(N, SHIFT, SATP)                                  \
    mve_do_sqrshl_bhs((int8_t)(N), (int8_t)(SHIFT), 8, true, SATP)
#define DO_SQRSHLI_H(N, SHIFT, SATP)                                  \
    mve_do_sqrshl_bhs((int16_t)(N), (int8_t)(SHIFT), 16, true, SATP)
#define DO_SQRSHLI_W(N, SHIFT, SATP)                                  \
    mve_do_sqrshl_bhs((int32_t)(N), (int8_t)(SHIFT), 32, true, SATP)
#define DO_UQRSHLI_B(N, SHIFT, SATP)                                  \
    mve_do_uqrshl_bhs((uint8_t)(N), (int8_t)(SHIFT), 8, true, SATP)
#define DO_UQRSHLI_H(N, SHIFT, SATP)                                  \
    mve_do_uqrshl_bhs((uint16_t)(N), (int8_t)(SHIFT), 16, true, SATP)
#define DO_UQRSHLI_W(N, SHIFT, SATP)                                  \
    mve_do_uqrshl_bhs((uint32_t)(N), (int8_t)(SHIFT), 32, true, SATP)

#define DO_SUQSHLI_B(N, SHIFT, SATP)                                  \
    mve_do_suqrshl_bhs((int8_t)(N), (int8_t)(SHIFT), 8, false, SATP)
#define DO_SUQSHLI_H(N, SHIFT, SATP)                                  \
    mve_do_suqrshl_bhs((int16_t)(N), (int8_t)(SHIFT), 16, false, SATP)
#define DO_SUQSHLI_W(N, SHIFT, SATP)                                  \
    mve_do_suqrshl_bhs((int32_t)(N), (int8_t)(SHIFT), 32, false, SATP)

DO_2SHIFT_IMM_SAT_S(vqshli_s, DO_SQSHLI)
DO_2SHIFT_IMM_SAT_U(vqshli_u, DO_UQSHLI)
DO_2SHIFT_IMM_SAT_S(vqrshli_s, DO_SQRSHLI)
DO_2SHIFT_IMM_SAT_U(vqrshli_u, DO_UQRSHLI)
DO_2SHIFT_IMM_SAT_S(vqshlui_s, DO_SUQSHLI)

DO_2OP_SAT(vqshlsb, 1, int8_t, mve_mergemask_sb, DO_SQSHLI_B)
DO_2OP_SAT(vqshlsh, 2, int16_t, mve_mergemask_sh, DO_SQSHLI_H)
DO_2OP_SAT(vqshlsw, 4, int32_t, mve_mergemask_sw, DO_SQSHLI_W)
DO_2OP_SAT(vqshlub, 1, uint8_t, mve_mergemask_ub, DO_UQSHLI_B)
DO_2OP_SAT(vqshluh, 2, uint16_t, mve_mergemask_uh, DO_UQSHLI_H)
DO_2OP_SAT(vqshluw, 4, uint32_t, mve_mergemask_uw, DO_UQSHLI_W)
DO_2OP_SAT(vqrshlsb, 1, int8_t, mve_mergemask_sb, DO_SQRSHLI_B)
DO_2OP_SAT(vqrshlsh, 2, int16_t, mve_mergemask_sh, DO_SQRSHLI_H)
DO_2OP_SAT(vqrshlsw, 4, int32_t, mve_mergemask_sw, DO_SQRSHLI_W)
DO_2OP_SAT(vqrshlub, 1, uint8_t, mve_mergemask_ub, DO_UQRSHLI_B)
DO_2OP_SAT(vqrshluh, 2, uint16_t, mve_mergemask_uh, DO_UQRSHLI_H)
DO_2OP_SAT(vqrshluw, 4, uint32_t, mve_mergemask_uw, DO_UQRSHLI_W)

#define DO_VQDMLADH_OP(OP, ESIZE, TYPE, MERGE, XCHG, ROUND, FN)        \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vn, void *vm)                    \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *n = vn;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        bool qc = false;                                               \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            bool sat = false;                                          \
                                                                       \
            if ((e & 1) == XCHG) {                                     \
                TYPE r = FN(n[glue(H, ESIZE)(e)],                      \
                            m[glue(H, ESIZE)(e - XCHG)],               \
                            n[glue(H, ESIZE)(e + (1 - 2 * XCHG))],     \
                            m[glue(H, ESIZE)(e + (1 - XCHG))],         \
                            ROUND, &sat);                              \
                                                                       \
                MERGE(&d[glue(H, ESIZE)(e)], r, mask);                 \
                qc |= sat && (mask & 1);                               \
            }                                                          \
        }                                                              \
        if (qc) {                                                      \
            env->vfp.qc[0] = qc;                                       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

static int8_t do_vqdmladh_b(int8_t a, int8_t b, int8_t c, int8_t d,
                            int round, bool *sat)
{
    int64_t r = ((int64_t)a * b + (int64_t)c * d) * 2 +
        ((int64_t)round << 7);

    return mve_do_sat_bhs(r, INT16_MIN, INT16_MAX, sat) >> 8;
}

static int16_t do_vqdmladh_h(int16_t a, int16_t b, int16_t c, int16_t d,
                             int round, bool *sat)
{
    int64_t r = ((int64_t)a * b + (int64_t)c * d) * 2 +
        ((int64_t)round << 15);

    return mve_do_sat_bhs(r, INT32_MIN, INT32_MAX, sat) >> 16;
}

static int32_t do_vqdmladh_w(int32_t a, int32_t b, int32_t c, int32_t d,
                             int round, bool *sat)
{
    int64_t m1 = (int64_t)a * b;
    int64_t m2 = (int64_t)c * d;
    int64_t r;

    if (sadd64_overflow(m1, m2, &r) ||
        sadd64_overflow(r, (int64_t)round << 30, &r) ||
        sadd64_overflow(r, r, &r)) {
        *sat = true;
        return r < 0 ? INT32_MAX : INT32_MIN;
    }
    return r >> 32;
}

static int8_t do_vqdmlsdh_b(int8_t a, int8_t b, int8_t c, int8_t d,
                            int round, bool *sat)
{
    int64_t r = ((int64_t)a * b - (int64_t)c * d) * 2 +
        ((int64_t)round << 7);

    return mve_do_sat_bhs(r, INT16_MIN, INT16_MAX, sat) >> 8;
}

static int16_t do_vqdmlsdh_h(int16_t a, int16_t b, int16_t c, int16_t d,
                             int round, bool *sat)
{
    int64_t r = ((int64_t)a * b - (int64_t)c * d) * 2 +
        ((int64_t)round << 15);

    return mve_do_sat_bhs(r, INT32_MIN, INT32_MAX, sat) >> 16;
}

static int32_t do_vqdmlsdh_w(int32_t a, int32_t b, int32_t c, int32_t d,
                             int round, bool *sat)
{
    int64_t m1 = (int64_t)a * b;
    int64_t m2 = (int64_t)c * d;
    int64_t r;

    if (ssub64_overflow(m1, m2, &r) ||
        sadd64_overflow(r, (int64_t)round << 30, &r) ||
        sadd64_overflow(r, r, &r)) {
        *sat = true;
        return r < 0 ? INT32_MAX : INT32_MIN;
    }
    return r >> 32;
}

DO_VQDMLADH_OP(vqdmladhb, 1, int8_t, mve_mergemask_sb, 0, 0, do_vqdmladh_b)
DO_VQDMLADH_OP(vqdmladhh, 2, int16_t, mve_mergemask_sh, 0, 0,
               do_vqdmladh_h)
DO_VQDMLADH_OP(vqdmladhw, 4, int32_t, mve_mergemask_sw, 0, 0,
               do_vqdmladh_w)
DO_VQDMLADH_OP(vqdmladhxb, 1, int8_t, mve_mergemask_sb, 1, 0,
               do_vqdmladh_b)
DO_VQDMLADH_OP(vqdmladhxh, 2, int16_t, mve_mergemask_sh, 1, 0,
               do_vqdmladh_h)
DO_VQDMLADH_OP(vqdmladhxw, 4, int32_t, mve_mergemask_sw, 1, 0,
               do_vqdmladh_w)
DO_VQDMLADH_OP(vqrdmladhb, 1, int8_t, mve_mergemask_sb, 0, 1,
               do_vqdmladh_b)
DO_VQDMLADH_OP(vqrdmladhh, 2, int16_t, mve_mergemask_sh, 0, 1,
               do_vqdmladh_h)
DO_VQDMLADH_OP(vqrdmladhw, 4, int32_t, mve_mergemask_sw, 0, 1,
               do_vqdmladh_w)
DO_VQDMLADH_OP(vqrdmladhxb, 1, int8_t, mve_mergemask_sb, 1, 1,
               do_vqdmladh_b)
DO_VQDMLADH_OP(vqrdmladhxh, 2, int16_t, mve_mergemask_sh, 1, 1,
               do_vqdmladh_h)
DO_VQDMLADH_OP(vqrdmladhxw, 4, int32_t, mve_mergemask_sw, 1, 1,
               do_vqdmladh_w)
DO_VQDMLADH_OP(vqdmlsdhb, 1, int8_t, mve_mergemask_sb, 0, 0, do_vqdmlsdh_b)
DO_VQDMLADH_OP(vqdmlsdhh, 2, int16_t, mve_mergemask_sh, 0, 0,
               do_vqdmlsdh_h)
DO_VQDMLADH_OP(vqdmlsdhw, 4, int32_t, mve_mergemask_sw, 0, 0,
               do_vqdmlsdh_w)
DO_VQDMLADH_OP(vqdmlsdhxb, 1, int8_t, mve_mergemask_sb, 1, 0,
               do_vqdmlsdh_b)
DO_VQDMLADH_OP(vqdmlsdhxh, 2, int16_t, mve_mergemask_sh, 1, 0,
               do_vqdmlsdh_h)
DO_VQDMLADH_OP(vqdmlsdhxw, 4, int32_t, mve_mergemask_sw, 1, 0,
               do_vqdmlsdh_w)
DO_VQDMLADH_OP(vqrdmlsdhb, 1, int8_t, mve_mergemask_sb, 0, 1,
               do_vqdmlsdh_b)
DO_VQDMLADH_OP(vqrdmlsdhh, 2, int16_t, mve_mergemask_sh, 0, 1,
               do_vqdmlsdh_h)
DO_VQDMLADH_OP(vqrdmlsdhw, 4, int32_t, mve_mergemask_sw, 0, 1,
               do_vqdmlsdh_w)
DO_VQDMLADH_OP(vqrdmlsdhxb, 1, int8_t, mve_mergemask_sb, 1, 1,
               do_vqdmlsdh_b)
DO_VQDMLADH_OP(vqrdmlsdhxh, 2, int16_t, mve_mergemask_sh, 1, 1,
               do_vqdmlsdh_h)
DO_VQDMLADH_OP(vqrdmlsdhxw, 4, int32_t, mve_mergemask_sw, 1, 1,
               do_vqdmlsdh_w)

#define DO_VSHLL(OP, TOP, ESIZE, TYPE, LESIZE, LTYPE, MERGE, FN)      \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,           \
                                void *vm, uint32_t shift)             \
    {                                                                 \
        LTYPE *d = vd;                                                \
        TYPE *m = vm;                                                 \
        uint16_t mask = mve_element_mask(env);                        \
        unsigned le;                                                  \
                                                                      \
        for (le = 0; le < 16 / LESIZE; le++, mask >>= LESIZE) {       \
            LTYPE r = (LTYPE)FN(m[glue(H, ESIZE)(le * 2 + TOP)],      \
                                shift);                               \
                                                                      \
            MERGE(&d[glue(H, LESIZE)(le)], r, mask);                  \
        }                                                             \
        mve_advance_vpt(env);                                         \
    }

#define DO_SHLL_S(N, SHIFT) ((int64_t)(N) * (1LL << (SHIFT)))
#define DO_SHLL_U(N, SHIFT) ((uint64_t)(N) << (SHIFT))

DO_VSHLL(vshllbsb, 0, 1, int8_t, 2, int16_t, mve_mergemask_sh,
         DO_SHLL_S)
DO_VSHLL(vshllbsh, 0, 2, int16_t, 4, int32_t, mve_mergemask_sw,
         DO_SHLL_S)
DO_VSHLL(vshllbub, 0, 1, uint8_t, 2, uint16_t, mve_mergemask_uh,
         DO_SHLL_U)
DO_VSHLL(vshllbuh, 0, 2, uint16_t, 4, uint32_t, mve_mergemask_uw,
         DO_SHLL_U)
DO_VSHLL(vshlltsb, 1, 1, int8_t, 2, int16_t, mve_mergemask_sh,
         DO_SHLL_S)
DO_VSHLL(vshlltsh, 1, 2, int16_t, 4, int32_t, mve_mergemask_sw,
         DO_SHLL_S)
DO_VSHLL(vshlltub, 1, 1, uint8_t, 2, uint16_t, mve_mergemask_uh,
         DO_SHLL_U)
DO_VSHLL(vshlltuh, 1, 2, uint16_t, 4, uint32_t, mve_mergemask_uw,
         DO_SHLL_U)

#define DO_SHRN(N, SHIFT) ((N) >> (SHIFT))

#define DO_VSHRN(OP, TOP, ESIZE, TYPE, LESIZE, LTYPE, MERGE, FN)       \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,           \
                                void *vm, uint32_t shift)             \
    {                                                                 \
        TYPE *d = vd;                                                 \
        LTYPE *m = vm;                                                \
        uint16_t mask = mve_element_mask(env) >> (ESIZE * TOP);       \
        unsigned le;                                                  \
                                                                      \
        for (le = 0; le < 16 / LESIZE; le++, mask >>= LESIZE) {       \
            TYPE r = (TYPE)FN(m[glue(H, LESIZE)(le)], shift);         \
                                                                      \
            MERGE(&d[glue(H, ESIZE)(le * 2 + TOP)], r, mask);         \
        }                                                             \
        mve_advance_vpt(env);                                         \
    }

static inline uint64_t do_urshr(uint64_t n, uint32_t shift)
{
    return (n >> shift) + ((n >> (shift - 1)) & 1);
}

DO_VSHRN(vshrnbb, 0, 1, uint8_t, 2, uint16_t, mve_mergemask_ub, DO_SHRN)
DO_VSHRN(vshrnbh, 0, 2, uint16_t, 4, uint32_t, mve_mergemask_uh, DO_SHRN)
DO_VSHRN(vshrntb, 1, 1, uint8_t, 2, uint16_t, mve_mergemask_ub, DO_SHRN)
DO_VSHRN(vshrnth, 1, 2, uint16_t, 4, uint32_t, mve_mergemask_uh, DO_SHRN)
DO_VSHRN(vrshrnbb, 0, 1, uint8_t, 2, uint16_t, mve_mergemask_ub,
         do_urshr)
DO_VSHRN(vrshrnbh, 0, 2, uint16_t, 4, uint32_t, mve_mergemask_uh,
         do_urshr)
DO_VSHRN(vrshrntb, 1, 1, uint8_t, 2, uint16_t, mve_mergemask_ub,
         do_urshr)
DO_VSHRN(vrshrnth, 1, 2, uint16_t, 4, uint32_t, mve_mergemask_uh,
         do_urshr)

static inline int64_t do_srshr(int64_t n, uint32_t shift)
{
    return (n >> shift) + ((n >> (shift - 1)) & 1);
}

#define DO_VSHRN_SAT(OP, TOP, ESIZE, TYPE, LESIZE, LTYPE, MERGE, FN)  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,           \
                                void *vm, uint32_t shift)             \
    {                                                                 \
        TYPE *d = vd;                                                 \
        LTYPE *m = vm;                                                \
        uint16_t mask = mve_element_mask(env) >> (ESIZE * TOP);       \
        bool qc = false;                                              \
        unsigned le;                                                  \
                                                                      \
        for (le = 0; le < 16 / LESIZE; le++, mask >>= LESIZE) {       \
            bool sat = false;                                         \
            TYPE r = (TYPE)FN(m[glue(H, LESIZE)(le)], shift, &sat);   \
                                                                      \
            MERGE(&d[glue(H, ESIZE)(le * 2 + TOP)], r, mask);         \
            qc |= sat && (mask & 1);                                  \
        }                                                             \
        if (qc) {                                                     \
            env->vfp.qc[0] = qc;                                      \
        }                                                             \
        mve_advance_vpt(env);                                         \
    }

#define DO_SHRN_SB(N, SHIFT, SATP)                                    \
    mve_do_sat_bhs((int64_t)(N) >> (SHIFT), INT8_MIN, INT8_MAX, SATP)
#define DO_SHRN_SH(N, SHIFT, SATP)                                    \
    mve_do_sat_bhs((int64_t)(N) >> (SHIFT), INT16_MIN, INT16_MAX, SATP)
#define DO_SHRN_UB(N, SHIFT, SATP)                                    \
    mve_do_sat_bhs((uint64_t)(N) >> (SHIFT), 0, UINT8_MAX, SATP)
#define DO_SHRN_UH(N, SHIFT, SATP)                                    \
    mve_do_sat_bhs((uint64_t)(N) >> (SHIFT), 0, UINT16_MAX, SATP)
#define DO_SHRUN_B(N, SHIFT, SATP)                                    \
    mve_do_sat_bhs((int64_t)(N) >> (SHIFT), 0, UINT8_MAX, SATP)
#define DO_SHRUN_H(N, SHIFT, SATP)                                    \
    mve_do_sat_bhs((int64_t)(N) >> (SHIFT), 0, UINT16_MAX, SATP)
#define DO_RSHRN_SB(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs(do_srshr(N, SHIFT), INT8_MIN, INT8_MAX, SATP)
#define DO_RSHRN_SH(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs(do_srshr(N, SHIFT), INT16_MIN, INT16_MAX, SATP)
#define DO_RSHRN_UB(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs(do_urshr(N, SHIFT), 0, UINT8_MAX, SATP)
#define DO_RSHRN_UH(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs(do_urshr(N, SHIFT), 0, UINT16_MAX, SATP)
#define DO_RSHRUN_B(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs(do_srshr(N, SHIFT), 0, UINT8_MAX, SATP)
#define DO_RSHRUN_H(N, SHIFT, SATP)                                   \
    mve_do_sat_bhs(do_srshr(N, SHIFT), 0, UINT16_MAX, SATP)

#define DO_VSHRN_SAT_B(OPB, OPT, TYPE, LTYPE, MERGE, FN)              \
    DO_VSHRN_SAT(OPB, 0, 1, TYPE, 2, LTYPE, MERGE, FN)                \
    DO_VSHRN_SAT(OPT, 1, 1, TYPE, 2, LTYPE, MERGE, FN)

#define DO_VSHRN_SAT_H(OPB, OPT, TYPE, LTYPE, MERGE, FN)              \
    DO_VSHRN_SAT(OPB, 0, 2, TYPE, 4, LTYPE, MERGE, FN)                \
    DO_VSHRN_SAT(OPT, 1, 2, TYPE, 4, LTYPE, MERGE, FN)

DO_VSHRN_SAT_B(vqshrnb_sb, vqshrnt_sb, int8_t, int16_t,
               mve_mergemask_sb, DO_SHRN_SB)
DO_VSHRN_SAT_H(vqshrnb_sh, vqshrnt_sh, int16_t, int32_t,
               mve_mergemask_sh, DO_SHRN_SH)
DO_VSHRN_SAT_B(vqshrnb_ub, vqshrnt_ub, uint8_t, uint16_t,
               mve_mergemask_ub, DO_SHRN_UB)
DO_VSHRN_SAT_H(vqshrnb_uh, vqshrnt_uh, uint16_t, uint32_t,
               mve_mergemask_uh, DO_SHRN_UH)
DO_VSHRN_SAT_B(vqshrunbb, vqshruntb, uint8_t, int16_t,
               mve_mergemask_ub, DO_SHRUN_B)
DO_VSHRN_SAT_H(vqshrunbh, vqshrunth, uint16_t, int32_t,
               mve_mergemask_uh, DO_SHRUN_H)
DO_VSHRN_SAT_B(vqrshrnb_sb, vqrshrnt_sb, int8_t, int16_t,
               mve_mergemask_sb, DO_RSHRN_SB)
DO_VSHRN_SAT_H(vqrshrnb_sh, vqrshrnt_sh, int16_t, int32_t,
               mve_mergemask_sh, DO_RSHRN_SH)
DO_VSHRN_SAT_B(vqrshrnb_ub, vqrshrnt_ub, uint8_t, uint16_t,
               mve_mergemask_ub, DO_RSHRN_UB)
DO_VSHRN_SAT_H(vqrshrnb_uh, vqrshrnt_uh, uint16_t, uint32_t,
               mve_mergemask_uh, DO_RSHRN_UH)
DO_VSHRN_SAT_B(vqrshrunbb, vqrshruntb, uint8_t, int16_t,
               mve_mergemask_ub, DO_RSHRUN_B)
DO_VSHRN_SAT_H(vqrshrunbh, vqrshrunth, uint16_t, int32_t,
               mve_mergemask_uh, DO_RSHRUN_H)

#define DO_VMOVN(OP, TOP, ESIZE, TYPE, LESIZE, LTYPE, MERGE)           \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd, void *vm)  \
    {                                                                  \
        TYPE *d = vd;                                                  \
        LTYPE *m = vm;                                                 \
        uint16_t mask = mve_element_mask(env) >> (ESIZE * TOP);        \
        unsigned le;                                                   \
                                                                       \
        for (le = 0; le < 16 / LESIZE; le++, mask >>= LESIZE) {        \
            TYPE r = (TYPE)m[glue(H, LESIZE)(le)];                     \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(le * 2 + TOP)], r, mask);          \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_VMOVN(vmovnbb, 0, 1, uint8_t, 2, uint16_t, mve_mergemask_ub)
DO_VMOVN(vmovnbh, 0, 2, uint16_t, 4, uint32_t, mve_mergemask_uh)
DO_VMOVN(vmovntb, 1, 1, uint8_t, 2, uint16_t, mve_mergemask_ub)
DO_VMOVN(vmovnth, 1, 2, uint16_t, 4, uint32_t, mve_mergemask_uh)

#define DO_VMOVN_SAT(OP, TOP, ESIZE, TYPE, LESIZE, LTYPE, MERGE, FN)   \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd, void *vm)  \
    {                                                                  \
        TYPE *d = vd;                                                  \
        LTYPE *m = vm;                                                 \
        uint16_t mask = mve_element_mask(env) >> (ESIZE * TOP);        \
        bool qc = false;                                               \
        unsigned le;                                                   \
                                                                       \
        for (le = 0; le < 16 / LESIZE; le++, mask >>= LESIZE) {        \
            bool sat = false;                                          \
            TYPE r = (TYPE)FN(m[glue(H, LESIZE)(le)], &sat);           \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(le * 2 + TOP)], r, mask);          \
            qc |= sat && (mask & 1);                                   \
        }                                                              \
        if (qc) {                                                      \
            env->vfp.qc[0] = qc;                                       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_MOVN_SB(N, SATP)                                            \
    mve_do_sat_bhs((int64_t)(N), INT8_MIN, INT8_MAX, SATP)
#define DO_MOVN_SH(N, SATP)                                            \
    mve_do_sat_bhs((int64_t)(N), INT16_MIN, INT16_MAX, SATP)
#define DO_MOVN_UB(N, SATP)                                            \
    mve_do_sat_bhs((uint64_t)(N), 0, UINT8_MAX, SATP)
#define DO_MOVN_UH(N, SATP)                                            \
    mve_do_sat_bhs((uint64_t)(N), 0, UINT16_MAX, SATP)
#define DO_MOVUN_B(N, SATP)                                            \
    mve_do_sat_bhs((int64_t)(N), 0, UINT8_MAX, SATP)
#define DO_MOVUN_H(N, SATP)                                            \
    mve_do_sat_bhs((int64_t)(N), 0, UINT16_MAX, SATP)

#define DO_VMOVN_SAT_B(OPB, OPT, TYPE, LTYPE, MERGE, FN)               \
    DO_VMOVN_SAT(OPB, 0, 1, TYPE, 2, LTYPE, MERGE, FN)                 \
    DO_VMOVN_SAT(OPT, 1, 1, TYPE, 2, LTYPE, MERGE, FN)

#define DO_VMOVN_SAT_H(OPB, OPT, TYPE, LTYPE, MERGE, FN)               \
    DO_VMOVN_SAT(OPB, 0, 2, TYPE, 4, LTYPE, MERGE, FN)                 \
    DO_VMOVN_SAT(OPT, 1, 2, TYPE, 4, LTYPE, MERGE, FN)

DO_VMOVN_SAT_B(vqmovnbsb, vqmovntsb, int8_t, int16_t,
               mve_mergemask_sb, DO_MOVN_SB)
DO_VMOVN_SAT_H(vqmovnbsh, vqmovntsh, int16_t, int32_t,
               mve_mergemask_sh, DO_MOVN_SH)
DO_VMOVN_SAT_B(vqmovnbub, vqmovntub, uint8_t, uint16_t,
               mve_mergemask_ub, DO_MOVN_UB)
DO_VMOVN_SAT_H(vqmovnbuh, vqmovntuh, uint16_t, uint32_t,
               mve_mergemask_uh, DO_MOVN_UH)
DO_VMOVN_SAT_B(vqmovunbb, vqmovuntb, uint8_t, int16_t,
               mve_mergemask_ub, DO_MOVUN_B)
DO_VMOVN_SAT_H(vqmovunbh, vqmovunth, uint16_t, int32_t,
               mve_mergemask_uh, DO_MOVUN_H)

uint32_t HELPER(mve_vshlc)(CPUARMState *env, void *vd, uint32_t rdm,
                           uint32_t shift)
{
    uint32_t *d = vd;
    uint16_t mask = mve_element_mask(env);
    unsigned e;
    uint32_t r;

    if (shift == 0) {
        for (e = 0; e < 16 / 4; e++, mask >>= 4) {
            r = rdm;
            if (mask & 1) {
                rdm = d[H4(e)];
            }
            mve_mergemask_uw(&d[H4(e)], r, mask);
        }
    } else {
        uint32_t shiftmask = MAKE_64BIT_MASK(0, shift);

        for (e = 0; e < 16 / 4; e++, mask >>= 4) {
            r = (d[H4(e)] << shift) | (rdm & shiftmask);
            if (mask & 1) {
                rdm = d[H4(e)] >> (32 - shift);
            }
            mve_mergemask_uw(&d[H4(e)], r, mask);
        }
    }
    mve_advance_vpt(env);
    return rdm;
}

#define DO_2SHIFT_INSERT(OP, ESIZE, SHIFTFN, MASKFN)                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,           \
                                void *vm, uint32_t shift)             \
    {                                                                 \
        uint64_t *d = vd;                                             \
        uint64_t *m = vm;                                             \
        uint16_t mask;                                                \
        uint64_t shiftmask;                                           \
        unsigned e;                                                   \
                                                                      \
        if (shift == ESIZE * 8) {                                     \
            mve_advance_vpt(env);                                     \
            return;                                                   \
        }                                                             \
        mask = mve_element_mask(env);                                 \
        shiftmask = dup_const(ESIZE / 2, MASKFN(ESIZE * 8, shift));   \
        for (e = 0; e < 16 / 8; e++, mask >>= 8) {                    \
            uint64_t r = (SHIFTFN(m[H8(e)], shift) & shiftmask) |     \
                         (d[H8(e)] & ~shiftmask);                    \
                                                                      \
            mve_mergemask_uq(&d[H8(e)], r, mask);                    \
        }                                                             \
        mve_advance_vpt(env);                                         \
    }

#define DO_SHL(N, SHIFT) ((N) << (SHIFT))
#define DO_SHR(N, SHIFT) ((N) >> (SHIFT))
#define SHL_MASK(EBITS, SHIFT) MAKE_64BIT_MASK((SHIFT), (EBITS) - (SHIFT))
#define SHR_MASK(EBITS, SHIFT) MAKE_64BIT_MASK(0, (EBITS) - (SHIFT))

DO_2SHIFT_INSERT(vsrib, 1, DO_SHR, SHR_MASK)
DO_2SHIFT_INSERT(vsrih, 2, DO_SHR, SHR_MASK)
DO_2SHIFT_INSERT(vsriw, 4, DO_SHR, SHR_MASK)
DO_2SHIFT_INSERT(vslib, 1, DO_SHL, SHL_MASK)
DO_2SHIFT_INSERT(vslih, 2, DO_SHL, SHL_MASK)
DO_2SHIFT_INSERT(vsliw, 4, DO_SHL, SHL_MASK)

#define DO_1OP_SAT(OP, ESIZE, TYPE, MERGE, FN)                         \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd, void *vm)  \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        bool qc = false;                                               \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE) {             \
            bool sat = false;                                          \
            TYPE r = FN(m[glue(H, ESIZE)(e)], &sat);                   \
                                                                       \
            MERGE(&d[glue(H, ESIZE)(e)], r, mask);                     \
            qc |= sat && (mask & 1);                                   \
        }                                                              \
        if (qc) {                                                      \
            env->vfp.qc[0] = qc;                                       \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_VQABS_B(N, SATP) \
    mve_do_sat_bhs(DO_ABS((int64_t)N), INT8_MIN, INT8_MAX, SATP)
#define DO_VQABS_H(N, SATP) \
    mve_do_sat_bhs(DO_ABS((int64_t)N), INT16_MIN, INT16_MAX, SATP)
#define DO_VQABS_W(N, SATP) \
    mve_do_sat_bhs(DO_ABS((int64_t)N), INT32_MIN, INT32_MAX, SATP)
#define DO_VQNEG_B(N, SATP) \
    mve_do_sat_bhs(-(int64_t)N, INT8_MIN, INT8_MAX, SATP)
#define DO_VQNEG_H(N, SATP) \
    mve_do_sat_bhs(-(int64_t)N, INT16_MIN, INT16_MAX, SATP)
#define DO_VQNEG_W(N, SATP) \
    mve_do_sat_bhs(-(int64_t)N, INT32_MIN, INT32_MAX, SATP)

DO_1OP_SAT(vqabsb, 1, int8_t, mve_mergemask_sb, DO_VQABS_B)
DO_1OP_SAT(vqabsh, 2, int16_t, mve_mergemask_sh, DO_VQABS_H)
DO_1OP_SAT(vqabsw, 4, int32_t, mve_mergemask_sw, DO_VQABS_W)
DO_1OP_SAT(vqnegb, 1, int8_t, mve_mergemask_sb, DO_VQNEG_B)
DO_1OP_SAT(vqnegh, 2, int16_t, mve_mergemask_sh, DO_VQNEG_H)
DO_1OP_SAT(vqnegw, 4, int32_t, mve_mergemask_sw, DO_VQNEG_W)

#undef DO_1OP
#undef DO_CLS_B
#undef DO_CLS_H
#undef DO_CLZ_B
#undef DO_CLZ_H
#undef DO_NOT
#undef DO_ABS
#undef DO_NEG
#undef DO_VMAXMINA
#undef DO_LDAV
#undef DO_LDAVH
#undef DO_DAV
#undef DO_DAV_S
#undef DO_DAV_U
#undef DO_VADDV
#undef DO_VMAXMINV
#undef DO_VMAXMINV_U
#undef DO_VMAXMINV_S
#undef DO_FP_VMAXMINV
#undef DO_VADDLV
#undef DO_VABAV
#undef DO_VCADD
#undef DO_VCADD_ALL
#undef DO_2OP_SAT
#undef DO_VQDMLADH_OP
#undef DO_2OP_SCALAR_ACC
#undef DO_2OP_SCALAR_SAT_ACC
#undef DO_2OP_SAT_L
#undef DO_2OP_SCALAR_SAT_L
#undef DO_VMLA
#undef DO_VMLAS
#undef DO_VQDMLAH_B
#undef DO_VQDMLAH_H
#undef DO_VQDMLAH_W
#undef DO_VQRDMLAH_B
#undef DO_VQRDMLAH_H
#undef DO_VQRDMLAH_W
#undef DO_VQDMLASH_B
#undef DO_VQDMLASH_H
#undef DO_VQDMLASH_W
#undef DO_VQRDMLASH_B
#undef DO_VQRDMLASH_H
#undef DO_VQRDMLASH_W
#undef DO_SQADD_B
#undef DO_SQADD_H
#undef DO_SQADD_W
#undef DO_UQADD_B
#undef DO_UQADD_H
#undef DO_UQADD_W
#undef DO_SQSUB_B
#undef DO_SQSUB_H
#undef DO_SQSUB_W
#undef DO_UQSUB_B
#undef DO_UQSUB_H
#undef DO_UQSUB_W
#undef DO_QDMULH_B
#undef DO_QDMULH_H
#undef DO_QDMULH_W
#undef DO_QRDMULH_B
#undef DO_QRDMULH_H
#undef DO_QRDMULH_W
#undef SATMASK16B
#undef SATMASK16T
#undef SATMASK32
#undef DO_1OP_SAT
#undef DO_VQABS_B
#undef DO_VQABS_H
#undef DO_VQABS_W
#undef DO_VQNEG_B
#undef DO_VQNEG_H
#undef DO_VQNEG_W
#undef DO_2SHIFT_IMM
#undef DO_2SHIFT_IMM_U
#undef DO_2SHIFT_IMM_S
#undef DO_2SHIFT_IMM_SAT
#undef DO_2SHIFT_IMM_SAT_U
#undef DO_2SHIFT_IMM_SAT_S
#undef DO_SQSHLI_B
#undef DO_SQSHLI_H
#undef DO_SQSHLI_W
#undef DO_UQSHLI_B
#undef DO_UQSHLI_H
#undef DO_UQSHLI_W
#undef DO_SQRSHLI_B
#undef DO_SQRSHLI_H
#undef DO_SQRSHLI_W
#undef DO_UQRSHLI_B
#undef DO_UQRSHLI_H
#undef DO_UQRSHLI_W
#undef DO_SUQSHLI_B
#undef DO_SUQSHLI_H
#undef DO_SUQSHLI_W
#undef DO_VSHLL
#undef DO_SHLL_S
#undef DO_SHLL_U
#undef DO_VSHRN
#undef DO_SHRN
#undef DO_VSHRN_SAT
#undef DO_SHRN_SB
#undef DO_SHRN_SH
#undef DO_SHRN_UB
#undef DO_SHRN_UH
#undef DO_SHRUN_B
#undef DO_SHRUN_H
#undef DO_RSHRN_SB
#undef DO_RSHRN_SH
#undef DO_RSHRN_UB
#undef DO_RSHRN_UH
#undef DO_RSHRUN_B
#undef DO_RSHRUN_H
#undef DO_VSHRN_SAT_B
#undef DO_VSHRN_SAT_H
#undef DO_VMOVN
#undef DO_VMOVN_SAT
#undef DO_MOVN_SB
#undef DO_MOVN_SH
#undef DO_MOVN_UB
#undef DO_MOVN_UH
#undef DO_MOVUN_B
#undef DO_MOVUN_H
#undef DO_VMOVN_SAT_B
#undef DO_VMOVN_SAT_H
#undef DO_2SHIFT_INSERT
#undef DO_SHL
#undef DO_SHR
#undef SHL_MASK
#undef SHR_MASK
#undef DO_VCMP
#undef DO_VCMP_SCALAR
#undef DO_VCMP_S
#undef DO_VCMP_U
#undef DO_EQ
#undef DO_NE
#undef DO_GE
#undef DO_LT
#undef DO_GT
#undef DO_LE
#undef DO_1OP_IMM
#undef DO_MOVI
#undef DO_ANDI
#undef DO_ORRI

void HELPER(mve_vldrb)(CPUARMState *env, void *vd, uint32_t addr)
{
    uint8_t *d = vd;
    uint16_t mask = mve_element_mask(env);
    uint16_t eci_mask = mve_eci_mask(env);
    unsigned b;

    for (b = 0; b < 16; b++) {
        if (eci_mask & (1U << b)) {
            d[H1(b)] = (mask & (1U << b)) ?
                cpu_ldub_data_ra(env, addr, GETPC()) : 0;
        }
        addr++;
    }
    mve_advance_vpt(env);
}

void HELPER(mve_vldrh)(CPUARMState *env, void *vd, uint32_t addr)
{
    uint16_t *d = vd;
    uint16_t mask = mve_element_mask(env);
    uint16_t eci_mask = mve_eci_mask(env);
    unsigned b;
    unsigned e;

    for (b = 0, e = 0; b < 16; b += 2, e++) {
        if (eci_mask & (1U << b)) {
            d[H2(e)] = (mask & (1U << b)) ?
                cpu_lduw_data_ra(env, addr, GETPC()) : 0;
        }
        addr += 2;
    }
    mve_advance_vpt(env);
}

void HELPER(mve_vldrw)(CPUARMState *env, void *vd, uint32_t addr)
{
    uint32_t *d = vd;
    uint16_t mask = mve_element_mask(env);
    uint16_t eci_mask = mve_eci_mask(env);
    unsigned b;
    unsigned e;

    for (b = 0, e = 0; b < 16; b += 4, e++) {
        if (eci_mask & (1U << b)) {
            d[H4(e)] = (mask & (1U << b)) ?
                cpu_ldl_data_ra(env, addr, GETPC()) : 0;
        }
        addr += 4;
    }
    mve_advance_vpt(env);
}

void HELPER(mve_vstrb)(CPUARMState *env, void *vd, uint32_t addr)
{
    uint8_t *d = vd;
    uint16_t mask = mve_element_mask(env);
    unsigned b;

    for (b = 0; b < 16; b++) {
        if (mask & (1U << b)) {
            cpu_stb_data_ra(env, addr, d[H1(b)], GETPC());
        }
        addr++;
    }
    mve_advance_vpt(env);
}

void HELPER(mve_vstrh)(CPUARMState *env, void *vd, uint32_t addr)
{
    uint16_t *d = vd;
    uint16_t mask = mve_element_mask(env);
    unsigned b;
    unsigned e;

    for (b = 0, e = 0; b < 16; b += 2, e++) {
        if (mask & (1U << b)) {
            cpu_stw_data_ra(env, addr, d[H2(e)], GETPC());
        }
        addr += 2;
    }
    mve_advance_vpt(env);
}

void HELPER(mve_vstrw)(CPUARMState *env, void *vd, uint32_t addr)
{
    uint32_t *d = vd;
    uint16_t mask = mve_element_mask(env);
    unsigned b;
    unsigned e;

    for (b = 0, e = 0; b < 16; b += 4, e++) {
        if (mask & (1U << b)) {
            cpu_stl_data_ra(env, addr, d[H4(e)], GETPC());
        }
        addr += 4;
    }
    mve_advance_vpt(env);
}

#define DO_VLDR_WIDE(OP, MSIZE, LDTYPE, ESIZE, TYPE)                   \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                uint32_t addr)                         \
    {                                                                  \
        TYPE *d = vd;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        uint16_t eci_mask = mve_eci_mask(env);                         \
        unsigned b;                                                    \
        unsigned e;                                                    \
                                                                       \
        for (b = 0, e = 0; b < 16; b += ESIZE, e++) {                  \
            if (eci_mask & (1U << b)) {                                \
                d[glue(H, ESIZE)(e)] = (mask & (1U << b)) ?            \
                    cpu_##LDTYPE##_data_ra(env, addr, GETPC()) : 0;    \
            }                                                          \
            addr += MSIZE;                                             \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_VSTR_NARROW(OP, MSIZE, STTYPE, ESIZE, TYPE)                 \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                uint32_t addr)                         \
    {                                                                  \
        TYPE *d = vd;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        unsigned b;                                                    \
        unsigned e;                                                    \
                                                                       \
        for (b = 0, e = 0; b < 16; b += ESIZE, e++) {                  \
            if (mask & (1U << b)) {                                    \
                cpu_##STTYPE##_data_ra(env, addr,                      \
                                       d[glue(H, ESIZE)(e)], GETPC()); \
            }                                                          \
            addr += MSIZE;                                             \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_VLDR_WIDE(vldrb_sh, 1, ldsb, 2, int16_t)
DO_VLDR_WIDE(vldrb_uh, 1, ldub, 2, uint16_t)
DO_VLDR_WIDE(vldrb_sw, 1, ldsb, 4, int32_t)
DO_VLDR_WIDE(vldrb_uw, 1, ldub, 4, uint32_t)
DO_VLDR_WIDE(vldrh_sw, 2, ldsw, 4, int32_t)
DO_VLDR_WIDE(vldrh_uw, 2, lduw, 4, uint32_t)

DO_VSTR_NARROW(vstrb_h, 1, stb, 2, int16_t)
DO_VSTR_NARROW(vstrb_w, 1, stb, 4, int32_t)
DO_VSTR_NARROW(vstrh_w, 2, stw, 4, int32_t)

#undef DO_VLDR_WIDE
#undef DO_VSTR_NARROW

#define ADDR_ADD(BASE, OFFSET) ((BASE) + (OFFSET))
#define ADDR_ADD_OSH(BASE, OFFSET) ((BASE) + ((OFFSET) << 1))
#define ADDR_ADD_OSW(BASE, OFFSET) ((BASE) + ((OFFSET) << 2))
#define ADDR_ADD_OSD(BASE, OFFSET) ((BASE) + ((OFFSET) << 3))

#define DO_VLDR_SG(OP, LDTYPE, ESIZE, TYPE, OFFTYPE, ADDRFN, WB)       \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vm, uint32_t base)               \
    {                                                                  \
        TYPE *d = vd;                                                  \
        OFFTYPE *m = vm;                                               \
        uint16_t mask = mve_element_mask(env);                         \
        uint16_t eci_mask = mve_eci_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE,               \
             eci_mask >>= ESIZE) {                                     \
            uint32_t addr;                                             \
                                                                       \
            if (!(eci_mask & 1)) {                                     \
                continue;                                              \
            }                                                          \
            addr = ADDRFN(base, m[glue(H, ESIZE)(e)]);                 \
            d[glue(H, ESIZE)(e)] = (mask & 1) ?                        \
                cpu_##LDTYPE##_data_ra(env, addr, GETPC()) : 0;        \
            if (WB) {                                                  \
                m[glue(H, ESIZE)(e)] = addr;                           \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_VSTR_SG(OP, STTYPE, ESIZE, TYPE, ADDRFN, WB)                \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vm, uint32_t base)               \
    {                                                                  \
        TYPE *d = vd;                                                  \
        TYPE *m = vm;                                                  \
        uint16_t mask = mve_element_mask(env);                         \
        uint16_t eci_mask = mve_eci_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / ESIZE; e++, mask >>= ESIZE,               \
             eci_mask >>= ESIZE) {                                     \
            uint32_t addr;                                             \
                                                                       \
            if (!(eci_mask & 1)) {                                     \
                continue;                                              \
            }                                                          \
            addr = ADDRFN(base, m[glue(H, ESIZE)(e)]);                 \
            if (mask & 1) {                                            \
                cpu_##STTYPE##_data_ra(env, addr,                      \
                                       d[glue(H, ESIZE)(e)], GETPC()); \
            }                                                          \
            if (WB) {                                                  \
                m[glue(H, ESIZE)(e)] = addr;                           \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_VLDR64_SG(OP, ADDRFN, WB)                                   \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vm, uint32_t base)               \
    {                                                                  \
        uint32_t *d = vd;                                              \
        uint32_t *m = vm;                                              \
        uint16_t mask = mve_element_mask(env);                         \
        uint16_t eci_mask = mve_eci_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / 4; e++, mask >>= 4, eci_mask >>= 4) {     \
            uint32_t addr;                                             \
                                                                       \
            if (!(eci_mask & 1)) {                                     \
                continue;                                              \
            }                                                          \
            addr = ADDRFN(base, m[H4(e & ~1)]);                        \
            addr += 4 * (e & 1);                                       \
            d[H4(e)] = (mask & 1) ?                                    \
                cpu_ldl_data_ra(env, addr, GETPC()) : 0;               \
            if (WB && (e & 1)) {                                       \
                m[H4(e & ~1)] = addr - 4;                              \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

#define DO_VSTR64_SG(OP, ADDRFN, WB)                                   \
    void HELPER(glue(mve_, OP))(CPUARMState *env, void *vd,            \
                                void *vm, uint32_t base)               \
    {                                                                  \
        uint32_t *d = vd;                                              \
        uint32_t *m = vm;                                              \
        uint16_t mask = mve_element_mask(env);                         \
        uint16_t eci_mask = mve_eci_mask(env);                         \
        unsigned e;                                                    \
                                                                       \
        for (e = 0; e < 16 / 4; e++, mask >>= 4, eci_mask >>= 4) {     \
            uint32_t addr;                                             \
                                                                       \
            if (!(eci_mask & 1)) {                                     \
                continue;                                              \
            }                                                          \
            addr = ADDRFN(base, m[H4(e & ~1)]);                        \
            addr += 4 * (e & 1);                                       \
            if (mask & 1) {                                            \
                cpu_stl_data_ra(env, addr, d[H4(e)], GETPC());         \
            }                                                          \
            if (WB && (e & 1)) {                                       \
                m[H4(e & ~1)] = addr - 4;                              \
            }                                                          \
        }                                                              \
        mve_advance_vpt(env);                                          \
    }

DO_VLDR_SG(vldrb_sg_sh, ldsb, 2, int16_t, uint16_t, ADDR_ADD, false)
DO_VLDR_SG(vldrb_sg_sw, ldsb, 4, int32_t, uint32_t, ADDR_ADD, false)
DO_VLDR_SG(vldrh_sg_sw, ldsw, 4, int32_t, uint32_t, ADDR_ADD, false)

DO_VLDR_SG(vldrb_sg_ub, ldub, 1, uint8_t, uint8_t, ADDR_ADD, false)
DO_VLDR_SG(vldrb_sg_uh, ldub, 2, uint16_t, uint16_t, ADDR_ADD, false)
DO_VLDR_SG(vldrb_sg_uw, ldub, 4, uint32_t, uint32_t, ADDR_ADD, false)
DO_VLDR_SG(vldrh_sg_uh, lduw, 2, uint16_t, uint16_t, ADDR_ADD, false)
DO_VLDR_SG(vldrh_sg_uw, lduw, 4, uint32_t, uint32_t, ADDR_ADD, false)
DO_VLDR_SG(vldrw_sg_uw, ldl, 4, uint32_t, uint32_t, ADDR_ADD, false)
DO_VLDR64_SG(vldrd_sg_ud, ADDR_ADD, false)

DO_VLDR_SG(vldrh_sg_os_sw, ldsw, 4, int32_t, uint32_t, ADDR_ADD_OSH, false)
DO_VLDR_SG(vldrh_sg_os_uh, lduw, 2, uint16_t, uint16_t, ADDR_ADD_OSH, false)
DO_VLDR_SG(vldrh_sg_os_uw, lduw, 4, uint32_t, uint32_t, ADDR_ADD_OSH, false)
DO_VLDR_SG(vldrw_sg_os_uw, ldl, 4, uint32_t, uint32_t, ADDR_ADD_OSW, false)
DO_VLDR64_SG(vldrd_sg_os_ud, ADDR_ADD_OSD, false)

DO_VSTR_SG(vstrb_sg_ub, stb, 1, uint8_t, ADDR_ADD, false)
DO_VSTR_SG(vstrb_sg_uh, stb, 2, uint16_t, ADDR_ADD, false)
DO_VSTR_SG(vstrb_sg_uw, stb, 4, uint32_t, ADDR_ADD, false)
DO_VSTR_SG(vstrh_sg_uh, stw, 2, uint16_t, ADDR_ADD, false)
DO_VSTR_SG(vstrh_sg_uw, stw, 4, uint32_t, ADDR_ADD, false)
DO_VSTR_SG(vstrw_sg_uw, stl, 4, uint32_t, ADDR_ADD, false)
DO_VSTR64_SG(vstrd_sg_ud, ADDR_ADD, false)

DO_VSTR_SG(vstrh_sg_os_uh, stw, 2, uint16_t, ADDR_ADD_OSH, false)
DO_VSTR_SG(vstrh_sg_os_uw, stw, 4, uint32_t, ADDR_ADD_OSH, false)
DO_VSTR_SG(vstrw_sg_os_uw, stl, 4, uint32_t, ADDR_ADD_OSW, false)
DO_VSTR64_SG(vstrd_sg_os_ud, ADDR_ADD_OSD, false)

DO_VLDR_SG(vldrw_sg_wb_uw, ldl, 4, uint32_t, uint32_t, ADDR_ADD, true)
DO_VLDR64_SG(vldrd_sg_wb_ud, ADDR_ADD, true)
DO_VSTR_SG(vstrw_sg_wb_uw, stl, 4, uint32_t, ADDR_ADD, true)
DO_VSTR64_SG(vstrd_sg_wb_ud, ADDR_ADD, true)

#undef DO_VLDR_SG
#undef DO_VSTR_SG
#undef DO_VLDR64_SG
#undef DO_VSTR64_SG
#undef ADDR_ADD
#undef ADDR_ADD_OSH
#undef ADDR_ADD_OSW
#undef ADDR_ADD_OSD

static uint32_t mve_ldl_le_data_ra(CPUARMState *env, uint32_t addr,
                                   uintptr_t ra)
{
    uint32_t data = cpu_ldl_data_ra(env, addr, ra);

    return arm_cpu_data_is_big_endian(env) ? bswap32(data) : data;
}

static void mve_stl_le_data_ra(CPUARMState *env, uint32_t addr,
                               uint32_t data, uintptr_t ra)
{
    if (arm_cpu_data_is_big_endian(env)) {
        data = bswap32(data);
    }
    cpu_stl_data_ra(env, addr, data, ra);
}

/*
 * Deinterleaving loads/interleaving stores.
 *
 * For these helpers we are passed the index of the first Qreg.
 * VLD2/VST2 also access Qn+1; VLD4/VST4 access Qn..Qn+3.
 * The helpers are specialized for pattern and element size, so
 * vld42h is VLD4 with pattern 2 and halfword elements.
 *
 * These instructions are beatwise but not predicated, so they honour ECI
 * but do not use mve_element_mask().
 */
#define DO_VLD4B(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat, e;                                                   \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 4;                               \
            data = mve_ldl_le_data_ra(env, addr, GETPC());             \
            for (e = 0; e < 4; e++, data >>= 8) {                     \
                uint8_t *qd = (uint8_t *)aa32_vfp_qreg(env, qnidx + e);\
                                                                      \
                qd[H1(off[beat])] = data;                              \
            }                                                         \
        }                                                             \
    }

#define DO_VLD4H(OP, O1, O2)                                          \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat;                                                      \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O1, O2, O2 };              \
        uint32_t addr, data;                                           \
        int y;                                                         \
        uint16_t *qd;                                                  \
                                                                      \
        for (beat = 0, y = 0; beat < 4; beat++, mask >>= 4, y ^= 2) {  \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 8 + (beat & 1) * 4;              \
            data = mve_ldl_le_data_ra(env, addr, GETPC());             \
            qd = (uint16_t *)aa32_vfp_qreg(env, qnidx + y);            \
            qd[H2(off[beat])] = data;                                  \
            data >>= 16;                                               \
            qd = (uint16_t *)aa32_vfp_qreg(env, qnidx + y + 1);        \
            qd[H2(off[beat])] = data;                                  \
        }                                                             \
    }

#define DO_VLD4W(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat;                                                      \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
        uint32_t *qd;                                                  \
        int y;                                                         \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 4;                               \
            data = mve_ldl_le_data_ra(env, addr, GETPC());             \
            y = (beat + (O1 & 2)) & 3;                                 \
            qd = (uint32_t *)aa32_vfp_qreg(env, qnidx + y);            \
            qd[H4(off[beat] >> 2)] = data;                             \
        }                                                             \
    }

DO_VLD4B(vld40b, 0, 1, 10, 11)
DO_VLD4B(vld41b, 2, 3, 12, 13)
DO_VLD4B(vld42b, 4, 5, 14, 15)
DO_VLD4B(vld43b, 6, 7, 8, 9)

DO_VLD4H(vld40h, 0, 5)
DO_VLD4H(vld41h, 1, 6)
DO_VLD4H(vld42h, 2, 7)
DO_VLD4H(vld43h, 3, 4)

DO_VLD4W(vld40w, 0, 1, 10, 11)
DO_VLD4W(vld41w, 2, 3, 12, 13)
DO_VLD4W(vld42w, 4, 5, 14, 15)
DO_VLD4W(vld43w, 6, 7, 8, 9)

#define DO_VLD2B(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat, e;                                                   \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
        uint8_t *qd;                                                   \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 2;                               \
            data = mve_ldl_le_data_ra(env, addr, GETPC());             \
            for (e = 0; e < 4; e++, data >>= 8) {                     \
                qd = (uint8_t *)aa32_vfp_qreg(env, qnidx + (e & 1));   \
                qd[H1(off[beat] + (e >> 1))] = data;                   \
            }                                                         \
        }                                                             \
    }

#define DO_VLD2H(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat;                                                      \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
        int e;                                                         \
        uint16_t *qd;                                                  \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 4;                               \
            data = mve_ldl_le_data_ra(env, addr, GETPC());             \
            for (e = 0; e < 2; e++, data >>= 16) {                    \
                qd = (uint16_t *)aa32_vfp_qreg(env, qnidx + e);        \
                qd[H2(off[beat])] = data;                              \
            }                                                         \
        }                                                             \
    }

#define DO_VLD2W(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat;                                                      \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
        uint32_t *qd;                                                  \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat];                                   \
            data = mve_ldl_le_data_ra(env, addr, GETPC());             \
            qd = (uint32_t *)aa32_vfp_qreg(env, qnidx + (beat & 1));   \
            qd[H4(off[beat] >> 3)] = data;                             \
        }                                                             \
    }

DO_VLD2B(vld20b, 0, 2, 12, 14)
DO_VLD2B(vld21b, 4, 6, 8, 10)

DO_VLD2H(vld20h, 0, 1, 6, 7)
DO_VLD2H(vld21h, 2, 3, 4, 5)

DO_VLD2W(vld20w, 0, 4, 24, 28)
DO_VLD2W(vld21w, 8, 12, 16, 20)

#define DO_VST4B(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat, e;                                                   \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 4;                               \
            data = 0;                                                  \
            for (e = 3; e >= 0; e--) {                                 \
                uint8_t *qd = (uint8_t *)aa32_vfp_qreg(env, qnidx + e);\
                                                                      \
                data = (data << 8) | qd[H1(off[beat])];                \
            }                                                         \
            mve_stl_le_data_ra(env, addr, data, GETPC());              \
        }                                                             \
    }

#define DO_VST4H(OP, O1, O2)                                          \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat;                                                      \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O1, O2, O2 };              \
        uint32_t addr, data;                                           \
        int y;                                                         \
        uint16_t *qd;                                                  \
                                                                      \
        for (beat = 0, y = 0; beat < 4; beat++, mask >>= 4, y ^= 2) {  \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 8 + (beat & 1) * 4;              \
            qd = (uint16_t *)aa32_vfp_qreg(env, qnidx + y);            \
            data = qd[H2(off[beat])];                                  \
            qd = (uint16_t *)aa32_vfp_qreg(env, qnidx + y + 1);        \
            data |= qd[H2(off[beat])] << 16;                           \
            mve_stl_le_data_ra(env, addr, data, GETPC());              \
        }                                                             \
    }

#define DO_VST4W(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat;                                                      \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
        uint32_t *qd;                                                  \
        int y;                                                         \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 4;                               \
            y = (beat + (O1 & 2)) & 3;                                 \
            qd = (uint32_t *)aa32_vfp_qreg(env, qnidx + y);            \
            data = qd[H4(off[beat] >> 2)];                             \
            mve_stl_le_data_ra(env, addr, data, GETPC());              \
        }                                                             \
    }

DO_VST4B(vst40b, 0, 1, 10, 11)
DO_VST4B(vst41b, 2, 3, 12, 13)
DO_VST4B(vst42b, 4, 5, 14, 15)
DO_VST4B(vst43b, 6, 7, 8, 9)

DO_VST4H(vst40h, 0, 5)
DO_VST4H(vst41h, 1, 6)
DO_VST4H(vst42h, 2, 7)
DO_VST4H(vst43h, 3, 4)

DO_VST4W(vst40w, 0, 1, 10, 11)
DO_VST4W(vst41w, 2, 3, 12, 13)
DO_VST4W(vst42w, 4, 5, 14, 15)
DO_VST4W(vst43w, 6, 7, 8, 9)

#define DO_VST2B(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat, e;                                                   \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
        uint8_t *qd;                                                   \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 2;                               \
            data = 0;                                                  \
            for (e = 3; e >= 0; e--) {                                 \
                qd = (uint8_t *)aa32_vfp_qreg(env, qnidx + (e & 1));   \
                data = (data << 8) | qd[H1(off[beat] + (e >> 1))];     \
            }                                                         \
            mve_stl_le_data_ra(env, addr, data, GETPC());              \
        }                                                             \
    }

#define DO_VST2H(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat;                                                      \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
        int e;                                                         \
        uint16_t *qd;                                                  \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat] * 4;                               \
            data = 0;                                                  \
            for (e = 1; e >= 0; e--) {                                 \
                qd = (uint16_t *)aa32_vfp_qreg(env, qnidx + e);        \
                data = (data << 16) | qd[H2(off[beat])];               \
            }                                                         \
            mve_stl_le_data_ra(env, addr, data, GETPC());              \
        }                                                             \
    }

#define DO_VST2W(OP, O1, O2, O3, O4)                                  \
    void HELPER(glue(mve_, OP))(CPUARMState *env, uint32_t qnidx,     \
                                uint32_t base)                        \
    {                                                                 \
        int beat;                                                      \
        uint16_t mask = mve_eci_mask(env);                             \
        static const uint8_t off[4] = { O1, O2, O3, O4 };              \
        uint32_t addr, data;                                           \
        uint32_t *qd;                                                  \
                                                                      \
        for (beat = 0; beat < 4; beat++, mask >>= 4) {                \
            if ((mask & 1) == 0) {                                     \
                continue;                                             \
            }                                                         \
            addr = base + off[beat];                                   \
            qd = (uint32_t *)aa32_vfp_qreg(env, qnidx + (beat & 1));   \
            data = qd[H4(off[beat] >> 3)];                             \
            mve_stl_le_data_ra(env, addr, data, GETPC());              \
        }                                                             \
    }

DO_VST2B(vst20b, 0, 2, 12, 14)
DO_VST2B(vst21b, 4, 6, 8, 10)

DO_VST2H(vst20h, 0, 1, 6, 7)
DO_VST2H(vst21h, 2, 3, 4, 5)

DO_VST2W(vst20w, 0, 4, 24, 28)
DO_VST2W(vst21w, 8, 12, 16, 20)

#undef DO_VLD4B
#undef DO_VLD4H
#undef DO_VLD4W
#undef DO_VLD2B
#undef DO_VLD2H
#undef DO_VLD2W
#undef DO_VST4B
#undef DO_VST4H
#undef DO_VST4W
#undef DO_VST2B
#undef DO_VST2H
#undef DO_VST2W

void HELPER(mve_vpsel)(CPUARMState *env, void *vd, void *vn, void *vm)
{
    uint64_t *d = vd;
    uint64_t *n = vn;
    uint64_t *m = vm;
    uint16_t mask = mve_element_mask(env);
    uint16_t p0 = FIELD_EX32(env->v7m.vpr, V7M_VPR, P0);
    unsigned e;

    for (e = 0; e < 16 / 8; e++, mask >>= 8, p0 >>= 8) {
        uint64_t r = m[H8(e)];

        mve_mergemask_uq(&r, n[H8(e)], p0);
        mve_mergemask_uq(&d[H8(e)], r, mask);
    }
    mve_advance_vpt(env);
}
