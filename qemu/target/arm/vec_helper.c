/*
 * ARM AdvSIMD / SVE Vector Operations
 *
 * Copyright (c) 2018 Linaro
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
#include "exec/helper-proto.h"
#include "tcg/tcg-gvec-desc.h"
#include "fpu/softfloat.h"


/* Note that vector data is stored in host-endian 64-bit chunks,
   so addressing units smaller than that needs a host-endian fixup.  */
#ifdef HOST_WORDS_BIGENDIAN
#define H1(x)  ((x) ^ 7)
#define H2(x)  ((x) ^ 3)
#define H4(x)  ((x) ^ 1)
#else
#define H1(x)  (x)
#define H2(x)  (x)
#define H4(x)  (x)
#endif
#define H8(x)  (x)

#define SET_QC() env->vfp.qc[0] = 1

static void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = (uint64_t *)((char *)vd + opr_sz);
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

/* Signed saturating rounding doubling multiply-accumulate high half, 16-bit */
static uint16_t inl_qrdmlah_s16(CPUARMState *env, int16_t src1,
                                int16_t src2, int16_t src3)
{
    /* Simplify:
     * = ((a3 << 16) + ((e1 * e2) << 1) + (1 << 15)) >> 16
     * = ((a3 << 15) + (e1 * e2) + (1 << 14)) >> 15
     */
    int32_t ret = (int32_t)src1 * src2;
    ret = ((int32_t)src3 << 15) + ret + (1 << 14);
    ret >>= 15;
    if (ret != (int16_t)ret) {
        SET_QC();
        ret = (ret < 0 ? -0x8000 : 0x7fff);
    }
    return ret;
}

uint32_t HELPER(neon_qrdmlah_s16)(CPUARMState *env, uint32_t src1,
                                  uint32_t src2, uint32_t src3)
{
    uint16_t e1 = inl_qrdmlah_s16(env, src1, src2, src3);
    uint16_t e2 = inl_qrdmlah_s16(env, src1 >> 16, src2 >> 16, src3 >> 16);
    return deposit32(e1, 16, 16, e2);
}

void HELPER(gvec_qrdmlah_s16)(void *vd, void *vn, void *vm,
                              void *ve, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    int16_t *d = vd;
    int16_t *n = vn;
    int16_t *m = vm;
    CPUARMState *env = ve;
    uintptr_t i;

    for (i = 0; i < opr_sz / 2; ++i) {
        d[i] = inl_qrdmlah_s16(env, n[i], m[i], d[i]);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

/* Signed saturating rounding doubling multiply-subtract high half, 16-bit */
static uint16_t inl_qrdmlsh_s16(CPUARMState *env, int16_t src1,
                                int16_t src2, int16_t src3)
{
    /* Similarly, using subtraction:
     * = ((a3 << 16) - ((e1 * e2) << 1) + (1 << 15)) >> 16
     * = ((a3 << 15) - (e1 * e2) + (1 << 14)) >> 15
     */
    int32_t ret = (int32_t)src1 * src2;
    ret = ((int32_t)src3 << 15) - ret + (1 << 14);
    ret >>= 15;
    if (ret != (int16_t)ret) {
        SET_QC();
        ret = (ret < 0 ? -0x8000 : 0x7fff);
    }
    return ret;
}

uint32_t HELPER(neon_qrdmlsh_s16)(CPUARMState *env, uint32_t src1,
                                  uint32_t src2, uint32_t src3)
{
    uint16_t e1 = inl_qrdmlsh_s16(env, src1, src2, src3);
    uint16_t e2 = inl_qrdmlsh_s16(env, src1 >> 16, src2 >> 16, src3 >> 16);
    return deposit32(e1, 16, 16, e2);
}

void HELPER(gvec_qrdmlsh_s16)(void *vd, void *vn, void *vm,
                              void *ve, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    int16_t *d = vd;
    int16_t *n = vn;
    int16_t *m = vm;
    CPUARMState *env = ve;
    uintptr_t i;

    for (i = 0; i < opr_sz / 2; ++i) {
        d[i] = inl_qrdmlsh_s16(env, n[i], m[i], d[i]);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

/* Signed saturating rounding doubling multiply-accumulate high half, 32-bit */
uint32_t HELPER(neon_qrdmlah_s32)(CPUARMState *env, int32_t src1,
                                  int32_t src2, int32_t src3)
{
    /* Simplify similarly to int_qrdmlah_s16 above.  */
    int64_t ret = (int64_t)src1 * src2;
    ret = ((int64_t)src3 << 31) + ret + (1 << 30);
    ret >>= 31;
    if (ret != (int32_t)ret) {
        SET_QC();
        ret = (ret < 0 ? INT32_MIN : INT32_MAX);
    }
    return ret;
}

void HELPER(gvec_qrdmlah_s32)(void *vd, void *vn, void *vm,
                              void *ve, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    int32_t *d = vd;
    int32_t *n = vn;
    int32_t *m = vm;
    CPUARMState *env = ve;
    uintptr_t i;

    for (i = 0; i < opr_sz / 4; ++i) {
        d[i] = helper_neon_qrdmlah_s32(env, n[i], m[i], d[i]);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

/* Signed saturating rounding doubling multiply-subtract high half, 32-bit */
uint32_t HELPER(neon_qrdmlsh_s32)(CPUARMState *env, int32_t src1,
                                  int32_t src2, int32_t src3)
{
    /* Simplify similarly to int_qrdmlsh_s16 above.  */
    int64_t ret = (int64_t)src1 * src2;
    ret = ((int64_t)src3 << 31) - ret + (1 << 30);
    ret >>= 31;
    if (ret != (int32_t)ret) {
        SET_QC();
        ret = (ret < 0 ? INT32_MIN : INT32_MAX);
    }
    return ret;
}

void HELPER(gvec_qrdmlsh_s32)(void *vd, void *vn, void *vm,
                              void *ve, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    int32_t *d = vd;
    int32_t *n = vn;
    int32_t *m = vm;
    CPUARMState *env = ve;
    uintptr_t i;

    for (i = 0; i < opr_sz / 4; ++i) {
        d[i] = helper_neon_qrdmlsh_s32(env, n[i], m[i], d[i]);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

/* Integer 8 and 16-bit dot-product.
 *
 * Note that for the loops herein, host endianness does not matter
 * with respect to the ordering of data within the 64-bit lanes.
 * All elements are treated equally, no matter where they are.
 */

#define DO_DOT(NAME, TYPED, TYPEN, TYPEM)                              \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc) \
{                                                                       \
    intptr_t i, oprsz = simd_oprsz(desc);                               \
    TYPED *d = vd, *a = va;                                             \
    TYPEN *n = vn;                                                      \
    TYPEM *m = vm;                                                      \
                                                                        \
    for (i = 0; i < oprsz / sizeof(TYPED); i++) {                       \
        d[i] = a[i] +                                                   \
               (TYPED)n[i * 4 + 0] * m[i * 4 + 0] +                    \
               (TYPED)n[i * 4 + 1] * m[i * 4 + 1] +                    \
               (TYPED)n[i * 4 + 2] * m[i * 4 + 2] +                    \
               (TYPED)n[i * 4 + 3] * m[i * 4 + 3];                     \
    }                                                                   \
    clear_tail(d, oprsz, simd_maxsz(desc));                             \
}

DO_DOT(gvec_sdot_b, int32_t, int8_t, int8_t)
DO_DOT(gvec_udot_b, uint32_t, uint8_t, uint8_t)
DO_DOT(gvec_usdot_b, uint32_t, uint8_t, int8_t)
DO_DOT(gvec_sdot_h, int64_t, int16_t, int16_t)
DO_DOT(gvec_udot_h, uint64_t, uint16_t, uint16_t)

#define DO_DOT_IDX(NAME, TYPED, TYPEN, TYPEM, H)                       \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc) \
{                                                                       \
    intptr_t i = 0, oprsz = simd_oprsz(desc);                           \
    intptr_t oprsz_n = oprsz / sizeof(TYPED);                           \
    intptr_t segend = MIN(16 / sizeof(TYPED), oprsz_n);                 \
    intptr_t index = simd_data(desc);                                   \
    TYPED *d = vd, *a = va;                                             \
    TYPEN *n = vn;                                                      \
    TYPEM *m_indexed = (TYPEM *)vm + H(index) * 4;                      \
                                                                        \
    do {                                                                \
        TYPED m0 = m_indexed[i * 4 + 0];                                \
        TYPED m1 = m_indexed[i * 4 + 1];                                \
        TYPED m2 = m_indexed[i * 4 + 2];                                \
        TYPED m3 = m_indexed[i * 4 + 3];                                \
                                                                        \
        do {                                                            \
            d[i] = a[i] +                                               \
                   n[i * 4 + 0] * m0 +                                  \
                   n[i * 4 + 1] * m1 +                                  \
                   n[i * 4 + 2] * m2 +                                  \
                   n[i * 4 + 3] * m3;                                   \
        } while (++i < segend);                                         \
        segend = i + (16 / sizeof(TYPED));                              \
    } while (i < oprsz_n);                                              \
    clear_tail(d, oprsz, simd_maxsz(desc));                             \
}

DO_DOT_IDX(gvec_sdot_idx_b, int32_t, int8_t, int8_t, H4)
DO_DOT_IDX(gvec_udot_idx_b, uint32_t, uint8_t, uint8_t, H4)
DO_DOT_IDX(gvec_sudot_idx_b, int32_t, int8_t, uint8_t, H4)
DO_DOT_IDX(gvec_usdot_idx_b, int32_t, uint8_t, int8_t, H4)
DO_DOT_IDX(gvec_sdot_idx_h, int64_t, int16_t, int16_t, H8)
DO_DOT_IDX(gvec_udot_idx_h, uint64_t, uint16_t, uint16_t, H8)

#undef DO_DOT
#undef DO_DOT_IDX

static uint32_t do_smmla_b(uint32_t sum, void *vn, void *vm)
{
    int8_t *n = vn, *m = vm;
    intptr_t k;

    for (k = 0; k < 8; k++) {
        sum += n[H1(k)] * m[H1(k)];
    }
    return sum;
}

static uint32_t do_ummla_b(uint32_t sum, void *vn, void *vm)
{
    uint8_t *n = vn, *m = vm;
    intptr_t k;

    for (k = 0; k < 8; k++) {
        sum += n[H1(k)] * m[H1(k)];
    }
    return sum;
}

static uint32_t do_usmmla_b(uint32_t sum, void *vn, void *vm)
{
    uint8_t *n = vn;
    int8_t *m = vm;
    intptr_t k;

    for (k = 0; k < 8; k++) {
        sum += n[H1(k)] * m[H1(k)];
    }
    return sum;
}

static void do_mmla_b(void *vd, void *vn, void *vm, void *va, uint32_t desc,
                      uint32_t (*inner_loop)(uint32_t, void *, void *))
{
    intptr_t seg, oprsz = simd_oprsz(desc);
    char *n = vn, *m = vm;

    for (seg = 0; seg < oprsz; seg += 16) {
        uint32_t *d = (uint32_t *)((char *)vd + seg);
        uint32_t *a = (uint32_t *)((char *)va + seg);
        uint32_t sum0, sum1, sum2, sum3;

        sum0 = a[H4(0)];
        sum0 = inner_loop(sum0, n + seg, m + seg);
        sum1 = a[H4(1)];
        sum1 = inner_loop(sum1, n + seg, m + seg + 8);
        sum2 = a[H4(2)];
        sum2 = inner_loop(sum2, n + seg + 8, m + seg);
        sum3 = a[H4(3)];
        sum3 = inner_loop(sum3, n + seg + 8, m + seg + 8);

        d[H4(0)] = sum0;
        d[H4(1)] = sum1;
        d[H4(2)] = sum2;
        d[H4(3)] = sum3;
    }
    clear_tail(vd, oprsz, simd_maxsz(desc));
}

#define DO_MMLA_B(NAME, INNER)                                          \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc) \
{                                                                       \
    do_mmla_b(vd, vn, vm, va, desc, INNER);                             \
}

DO_MMLA_B(gvec_smmla_b, do_smmla_b)
DO_MMLA_B(gvec_ummla_b, do_ummla_b)
DO_MMLA_B(gvec_usmmla_b, do_usmmla_b)

#undef DO_MMLA_B

static float32 bfdotadd(float32 sum, uint32_t e1, uint32_t e2)
{
    float_status bf_status = {
        .tininess_before_rounding = float_tininess_before_rounding,
        .float_rounding_mode = float_round_to_odd_inf,
        .flush_to_zero = true,
        .flush_inputs_to_zero = true,
        .default_nan_mode = true,
    };
    float32 t1;
    float32 t2;

    t1 = float32_mul(e1 << 16, e2 << 16, &bf_status);
    t2 = float32_mul(e1 & 0xffff0000u, e2 & 0xffff0000u, &bf_status);
    t1 = float32_add(t1, t2, &bf_status);
    return float32_add(sum, t1, &bf_status);
}

void HELPER(gvec_bfdot)(void *vd, void *vn, void *vm, void *va, uint32_t desc)
{
    intptr_t i;
    intptr_t oprsz = simd_oprsz(desc);
    float32 *d = vd;
    float32 *a = va;
    uint32_t *n = vn;
    uint32_t *m = vm;

    for (i = 0; i < oprsz / 4; ++i) {
        d[i] = bfdotadd(a[i], n[i], m[i]);
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_bfdot_idx)(void *vd, void *vn, void *vm,
                            void *va, uint32_t desc)
{
    intptr_t i;
    intptr_t j;
    intptr_t oprsz = simd_oprsz(desc);
    intptr_t index = simd_data(desc);
    intptr_t elements = oprsz / 4;
    intptr_t eltspersegment = MIN(16 / 4, elements);
    float32 *d = vd;
    float32 *a = va;
    uint32_t *n = vn;
    uint32_t *m = vm;

    for (i = 0; i < elements; i += eltspersegment) {
        uint32_t m_idx = m[i + H4(index)];

        for (j = i; j < i + eltspersegment; j++) {
            d[j] = bfdotadd(a[j], n[j], m_idx);
        }
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_bfmmla)(void *vd, void *vn, void *vm, void *va, uint32_t desc)
{
    intptr_t s;
    intptr_t oprsz = simd_oprsz(desc);
    float32 *d = vd;
    float32 *a = va;
    uint32_t *n = vn;
    uint32_t *m = vm;

    for (s = 0; s < oprsz / 4; s += 4) {
        float32 sum00;
        float32 sum01;
        float32 sum10;
        float32 sum11;

        sum00 = a[s + H4(0)];
        sum00 = bfdotadd(sum00, n[s + H4(0)], m[s + H4(0)]);
        sum00 = bfdotadd(sum00, n[s + H4(1)], m[s + H4(1)]);

        sum01 = a[s + H4(1)];
        sum01 = bfdotadd(sum01, n[s + H4(0)], m[s + H4(2)]);
        sum01 = bfdotadd(sum01, n[s + H4(1)], m[s + H4(3)]);

        sum10 = a[s + H4(2)];
        sum10 = bfdotadd(sum10, n[s + H4(2)], m[s + H4(0)]);
        sum10 = bfdotadd(sum10, n[s + H4(3)], m[s + H4(1)]);

        sum11 = a[s + H4(3)];
        sum11 = bfdotadd(sum11, n[s + H4(2)], m[s + H4(2)]);
        sum11 = bfdotadd(sum11, n[s + H4(3)], m[s + H4(3)]);

        d[s + H4(0)] = sum00;
        d[s + H4(1)] = sum01;
        d[s + H4(2)] = sum10;
        d[s + H4(3)] = sum11;
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_bfmlal)(void *vd, void *vn, void *vm, void *va,
                         void *stat, uint32_t desc)
{
    intptr_t i;
    intptr_t oprsz = simd_oprsz(desc);
    intptr_t sel = simd_data(desc);
    float32 *d = vd;
    float32 *a = va;
    bfloat16 *n = vn;
    bfloat16 *m = vm;

    for (i = 0; i < oprsz / 4; ++i) {
        float32 nn = n[H2(i * 2 + sel)] << 16;
        float32 mm = m[H2(i * 2 + sel)] << 16;

        d[H4(i)] = float32_muladd(nn, mm, a[H4(i)], 0, stat);
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_bfmlal_idx)(void *vd, void *vn, void *vm,
                             void *va, void *stat, uint32_t desc)
{
    intptr_t i;
    intptr_t j;
    intptr_t oprsz = simd_oprsz(desc);
    intptr_t sel = extract32(desc, SIMD_DATA_SHIFT, 1);
    intptr_t index = extract32(desc, SIMD_DATA_SHIFT + 1, 3);
    intptr_t elements = oprsz / 4;
    intptr_t eltspersegment = MIN(16 / 4, elements);
    float32 *d = vd;
    float32 *a = va;
    bfloat16 *n = vn;
    bfloat16 *m = vm;

    for (i = 0; i < elements; i += eltspersegment) {
        float32 m_idx = m[H2(2 * i + index)] << 16;

        for (j = i; j < i + eltspersegment; j++) {
            float32 n_j = n[H2(2 * j + sel)] << 16;

            d[H4(j)] = float32_muladd(n_j, m_idx, a[H4(j)], 0, stat);
        }
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_fcaddh)(void *vd, void *vn, void *vm,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float16 *d = vd;
    float16 *n = vn;
    float16 *m = vm;
    float_status *fpst = vfpst;
    uint32_t neg_real = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint32_t neg_imag = neg_real ^ 1;
    uintptr_t i;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 15;
    neg_imag <<= 15;

    for (i = 0; i < opr_sz / 2; i += 2) {
        float16 e0 = n[H2(i)];
        float16 e1 = m[H2(i + 1)] ^ neg_imag;
        float16 e2 = n[H2(i + 1)];
        float16 e3 = m[H2(i)] ^ neg_real;

        d[H2(i)] = float16_add(e0, e1, fpst);
        d[H2(i + 1)] = float16_add(e2, e3, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_fcadds)(void *vd, void *vn, void *vm,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float32 *d = vd;
    float32 *n = vn;
    float32 *m = vm;
    float_status *fpst = vfpst;
    uint32_t neg_real = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint32_t neg_imag = neg_real ^ 1;
    uintptr_t i;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 31;
    neg_imag <<= 31;

    for (i = 0; i < opr_sz / 4; i += 2) {
        float32 e0 = n[H4(i)];
        float32 e1 = m[H4(i + 1)] ^ neg_imag;
        float32 e2 = n[H4(i + 1)];
        float32 e3 = m[H4(i)] ^ neg_real;

        d[H4(i)] = float32_add(e0, e1, fpst);
        d[H4(i + 1)] = float32_add(e2, e3, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_fcaddd)(void *vd, void *vn, void *vm,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float64 *d = vd;
    float64 *n = vn;
    float64 *m = vm;
    float_status *fpst = vfpst;
    uint64_t neg_real = extract64(desc, SIMD_DATA_SHIFT, 1);
    uint64_t neg_imag = neg_real ^ 1;
    uintptr_t i;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 63;
    neg_imag <<= 63;

    for (i = 0; i < opr_sz / 8; i += 2) {
        float64 e0 = n[i];
        float64 e1 = m[i + 1] ^ neg_imag;
        float64 e2 = n[i + 1];
        float64 e3 = m[i] ^ neg_real;

        d[i] = float64_add(e0, e1, fpst);
        d[i + 1] = float64_add(e2, e3, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_fcmlah)(void *vd, void *vn, void *vm,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float16 *d = vd;
    float16 *n = vn;
    float16 *m = vm;
    float_status *fpst = vfpst;
    intptr_t flip = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint32_t neg_imag = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    uint32_t neg_real = flip ^ neg_imag;
    uintptr_t i;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 15;
    neg_imag <<= 15;

    for (i = 0; i < opr_sz / 2; i += 2) {
        float16 e2 = n[H2(i + flip)];
        float16 e1 = m[H2(i + flip)] ^ neg_real;
        float16 e4 = e2;
        float16 e3 = m[H2(i + 1 - flip)] ^ neg_imag;

        d[H2(i)] = float16_muladd(e2, e1, d[H2(i)], 0, fpst);
        d[H2(i + 1)] = float16_muladd(e4, e3, d[H2(i + 1)], 0, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_fcmlah_idx)(void *vd, void *vn, void *vm,
                             void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float16 *d = vd;
    float16 *n = vn;
    float16 *m = vm;
    float_status *fpst = vfpst;
    intptr_t flip = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint32_t neg_imag = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    intptr_t index = extract32(desc, SIMD_DATA_SHIFT + 2, 2);
    uint32_t neg_real = flip ^ neg_imag;
    intptr_t elements = opr_sz / sizeof(float16);
    intptr_t eltspersegment = 16 / sizeof(float16);
    intptr_t i, j;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 15;
    neg_imag <<= 15;

    for (i = 0; i < elements; i += eltspersegment) {
        float16 mr = m[H2(i + 2 * index + 0)];
        float16 mi = m[H2(i + 2 * index + 1)];
        float16 e1 = neg_real ^ (flip ? mi : mr);
        float16 e3 = neg_imag ^ (flip ? mr : mi);

        for (j = i; j < i + eltspersegment; j += 2) {
            float16 e2 = n[H2(j + flip)];
            float16 e4 = e2;

            d[H2(j)] = float16_muladd(e2, e1, d[H2(j)], 0, fpst);
            d[H2(j + 1)] = float16_muladd(e4, e3, d[H2(j + 1)], 0, fpst);
        }
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_fcmlas)(void *vd, void *vn, void *vm,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float32 *d = vd;
    float32 *n = vn;
    float32 *m = vm;
    float_status *fpst = vfpst;
    intptr_t flip = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint32_t neg_imag = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    uint32_t neg_real = flip ^ neg_imag;
    uintptr_t i;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 31;
    neg_imag <<= 31;

    for (i = 0; i < opr_sz / 4; i += 2) {
        float32 e2 = n[H4(i + flip)];
        float32 e1 = m[H4(i + flip)] ^ neg_real;
        float32 e4 = e2;
        float32 e3 = m[H4(i + 1 - flip)] ^ neg_imag;

        d[H4(i)] = float32_muladd(e2, e1, d[H4(i)], 0, fpst);
        d[H4(i + 1)] = float32_muladd(e4, e3, d[H4(i + 1)], 0, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_fcmlas_idx)(void *vd, void *vn, void *vm,
                             void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float32 *d = vd;
    float32 *n = vn;
    float32 *m = vm;
    float_status *fpst = vfpst;
    intptr_t flip = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint32_t neg_imag = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    intptr_t index = extract32(desc, SIMD_DATA_SHIFT + 2, 2);
    uint32_t neg_real = flip ^ neg_imag;
    intptr_t elements = opr_sz / sizeof(float32);
    intptr_t eltspersegment = 16 / sizeof(float32);
    intptr_t i, j;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 31;
    neg_imag <<= 31;

    for (i = 0; i < elements; i += eltspersegment) {
        float32 mr = m[H4(i + 2 * index + 0)];
        float32 mi = m[H4(i + 2 * index + 1)];
        float32 e1 = neg_real ^ (flip ? mi : mr);
        float32 e3 = neg_imag ^ (flip ? mr : mi);

        for (j = i; j < i + eltspersegment; j += 2) {
            float32 e2 = n[H4(j + flip)];
            float32 e4 = e2;

            d[H4(j)] = float32_muladd(e2, e1, d[H4(j)], 0, fpst);
            d[H4(j + 1)] = float32_muladd(e4, e3, d[H4(j + 1)], 0, fpst);
        }
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_fcmlad)(void *vd, void *vn, void *vm,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float64 *d = vd;
    float64 *n = vn;
    float64 *m = vm;
    float_status *fpst = vfpst;
    intptr_t flip = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint64_t neg_imag = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    uint64_t neg_real = flip ^ neg_imag;
    uintptr_t i;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 63;
    neg_imag <<= 63;

    for (i = 0; i < opr_sz / 8; i += 2) {
        float64 e2 = n[i + flip];
        float64 e1 = m[i + flip] ^ neg_real;
        float64 e4 = e2;
        float64 e3 = m[i + 1 - flip] ^ neg_imag;

        d[i] = float64_muladd(e2, e1, d[i], 0, fpst);
        d[i + 1] = float64_muladd(e4, e3, d[i + 1], 0, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

#define DO_2OP(NAME, FUNC, TYPE) \
void HELPER(NAME)(void *vd, void *vn, void *stat, uint32_t desc)  \
{                                                                 \
    intptr_t i, oprsz = simd_oprsz(desc);                         \
    TYPE *d = vd, *n = vn;                                        \
    for (i = 0; i < oprsz / sizeof(TYPE); i++) {                  \
        d[i] = FUNC(n[i], stat);                                  \
    }                                                             \
    clear_tail(d, oprsz, simd_maxsz(desc));                       \
}

DO_2OP(gvec_frecpe_h, helper_recpe_f16, float16)
DO_2OP(gvec_frecpe_s, helper_recpe_f32, float32)
DO_2OP(gvec_frecpe_d, helper_recpe_f64, float64)

DO_2OP(gvec_frsqrte_h, helper_rsqrte_f16, float16)
DO_2OP(gvec_frsqrte_s, helper_rsqrte_f32, float32)
DO_2OP(gvec_frsqrte_d, helper_rsqrte_f64, float64)

#undef DO_2OP

/* Floating-point trigonometric starting value.
 * See the ARM ARM pseudocode function FPTrigSMul.
 */
static float16 float16_ftsmul(float16 op1, uint16_t op2, float_status *stat)
{
    float16 result = float16_mul(op1, op1, stat);
    if (!float16_is_any_nan(result)) {
        result = float16_set_sign(result, op2 & 1);
    }
    return result;
}

static float32 float32_ftsmul(float32 op1, uint32_t op2, float_status *stat)
{
    float32 result = float32_mul(op1, op1, stat);
    if (!float32_is_any_nan(result)) {
        result = float32_set_sign(result, op2 & 1);
    }
    return result;
}

static float64 float64_ftsmul(float64 op1, uint64_t op2, float_status *stat)
{
    float64 result = float64_mul(op1, op1, stat);
    if (!float64_is_any_nan(result)) {
        result = float64_set_sign(result, op2 & 1);
    }
    return result;
}

#define DO_3OP(NAME, FUNC, TYPE) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *stat, uint32_t desc) \
{                                                                          \
    intptr_t i, oprsz = simd_oprsz(desc);                                  \
    TYPE *d = vd, *n = vn, *m = vm;                                        \
    for (i = 0; i < oprsz / sizeof(TYPE); i++) {                           \
        d[i] = FUNC(n[i], m[i], stat);                                     \
    }                                                                      \
    clear_tail(d, oprsz, simd_maxsz(desc));                                \
}

DO_3OP(gvec_fadd_h, float16_add, float16)
DO_3OP(gvec_fadd_s, float32_add, float32)
DO_3OP(gvec_fadd_d, float64_add, float64)

DO_3OP(gvec_fsub_h, float16_sub, float16)
DO_3OP(gvec_fsub_s, float32_sub, float32)
DO_3OP(gvec_fsub_d, float64_sub, float64)

DO_3OP(gvec_fmul_h, float16_mul, float16)
DO_3OP(gvec_fmul_s, float32_mul, float32)
DO_3OP(gvec_fmul_d, float64_mul, float64)

DO_3OP(gvec_ftsmul_h, float16_ftsmul, float16)
DO_3OP(gvec_ftsmul_s, float32_ftsmul, float32)
DO_3OP(gvec_ftsmul_d, float64_ftsmul, float64)

#ifdef TARGET_AARCH64

DO_3OP(gvec_recps_h, helper_recpsf_f16, float16)
DO_3OP(gvec_recps_s, helper_recpsf_f32, float32)
DO_3OP(gvec_recps_d, helper_recpsf_f64, float64)

DO_3OP(gvec_rsqrts_h, helper_rsqrtsf_f16, float16)
DO_3OP(gvec_rsqrts_s, helper_rsqrtsf_f32, float32)
DO_3OP(gvec_rsqrts_d, helper_rsqrtsf_f64, float64)

#endif
#undef DO_3OP

/* For the indexed ops, SVE applies the index per 128-bit vector segment.
 * For AdvSIMD, there is of course only one such vector segment.
 */

#define DO_MUL_IDX(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *stat, uint32_t desc) \
{                                                                          \
    intptr_t i, j, oprsz = simd_oprsz(desc), segment = 16 / sizeof(TYPE);  \
    intptr_t idx = simd_data(desc);                                        \
    TYPE *d = vd, *n = vn, *m = vm;                                        \
    for (i = 0; i < oprsz / sizeof(TYPE); i += segment) {                  \
        TYPE mm = m[H(i + idx)];                                           \
        for (j = 0; j < segment; j++) {                                    \
            d[i + j] = TYPE##_mul(n[i + j], mm, stat);                     \
        }                                                                  \
    }                                                                      \
    clear_tail(d, oprsz, simd_maxsz(desc));                                \
}

DO_MUL_IDX(gvec_fmul_idx_h, float16, H2)
DO_MUL_IDX(gvec_fmul_idx_s, float32, H4)
DO_MUL_IDX(gvec_fmul_idx_d, float64, )

#undef DO_MUL_IDX

#define DO_FMLA_IDX(NAME, TYPE, H)                                         \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va,                  \
                  void *stat, uint32_t desc)                               \
{                                                                          \
    intptr_t i, j, oprsz = simd_oprsz(desc), segment = 16 / sizeof(TYPE);  \
    TYPE op1_neg = extract32(desc, SIMD_DATA_SHIFT, 1);                    \
    intptr_t idx = desc >> (SIMD_DATA_SHIFT + 1);                          \
    TYPE *d = vd, *n = vn, *m = vm, *a = va;                               \
    op1_neg <<= (8 * sizeof(TYPE) - 1);                                    \
    for (i = 0; i < oprsz / sizeof(TYPE); i += segment) {                  \
        TYPE mm = m[H(i + idx)];                                           \
        for (j = 0; j < segment; j++) {                                    \
            d[i + j] = TYPE##_muladd(n[i + j] ^ op1_neg,                   \
                                     mm, a[i + j], 0, stat);               \
        }                                                                  \
    }                                                                      \
    clear_tail(d, oprsz, simd_maxsz(desc));                                \
}

DO_FMLA_IDX(gvec_fmla_idx_h, float16, H2)
DO_FMLA_IDX(gvec_fmla_idx_s, float32, H4)
DO_FMLA_IDX(gvec_fmla_idx_d, float64, )

#undef DO_FMLA_IDX

#define DO_SAT(NAME, WTYPE, TYPEN, TYPEM, OP, MIN, MAX) \
void HELPER(NAME)(void *vd, void *vq, void *vn, void *vm, uint32_t desc)   \
{                                                                          \
    intptr_t i, oprsz = simd_oprsz(desc);                                  \
    TYPEN *d = vd, *n = vn; TYPEM *m = vm;                                 \
    bool q = false;                                                        \
    for (i = 0; i < oprsz / sizeof(TYPEN); i++) {                          \
        WTYPE dd = (WTYPE)n[i] OP m[i];                                    \
        if (dd < MIN) {                                                    \
            dd = MIN;                                                      \
            q = true;                                                      \
        } else if (dd > MAX) {                                             \
            dd = MAX;                                                      \
            q = true;                                                      \
        }                                                                  \
        d[i] = dd;                                                         \
    }                                                                      \
    if (q) {                                                               \
        uint32_t *qc = vq;                                                 \
        qc[0] = 1;                                                         \
    }                                                                      \
    clear_tail(d, oprsz, simd_maxsz(desc));                                \
}

DO_SAT(gvec_uqadd_b, int, uint8_t, uint8_t, +, 0, UINT8_MAX)
DO_SAT(gvec_uqadd_h, int, uint16_t, uint16_t, +, 0, UINT16_MAX)
DO_SAT(gvec_uqadd_s, int64_t, uint32_t, uint32_t, +, 0, UINT32_MAX)

DO_SAT(gvec_sqadd_b, int, int8_t, int8_t, +, INT8_MIN, INT8_MAX)
DO_SAT(gvec_sqadd_h, int, int16_t, int16_t, +, INT16_MIN, INT16_MAX)
DO_SAT(gvec_sqadd_s, int64_t, int32_t, int32_t, +, INT32_MIN, INT32_MAX)

DO_SAT(gvec_uqsub_b, int, uint8_t, uint8_t, -, 0, UINT8_MAX)
DO_SAT(gvec_uqsub_h, int, uint16_t, uint16_t, -, 0, UINT16_MAX)
DO_SAT(gvec_uqsub_s, int64_t, uint32_t, uint32_t, -, 0, UINT32_MAX)

DO_SAT(gvec_sqsub_b, int, int8_t, int8_t, -, INT8_MIN, INT8_MAX)
DO_SAT(gvec_sqsub_h, int, int16_t, int16_t, -, INT16_MIN, INT16_MAX)
DO_SAT(gvec_sqsub_s, int64_t, int32_t, int32_t, -, INT32_MIN, INT32_MAX)

#undef DO_SAT

void HELPER(gvec_uqadd_d)(void *vd, void *vq, void *vn,
                          void *vm, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);
    uint64_t *d = vd, *n = vn, *m = vm;
    bool q = false;

    for (i = 0; i < oprsz / 8; i++) {
        uint64_t nn = n[i], mm = m[i], dd = nn + mm;
        if (dd < nn) {
            dd = UINT64_MAX;
            q = true;
        }
        d[i] = dd;
    }
    if (q) {
        uint32_t *qc = vq;
        qc[0] = 1;
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_uqsub_d)(void *vd, void *vq, void *vn,
                          void *vm, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);
    uint64_t *d = vd, *n = vn, *m = vm;
    bool q = false;

    for (i = 0; i < oprsz / 8; i++) {
        uint64_t nn = n[i], mm = m[i], dd = nn - mm;
        if (nn < mm) {
            dd = 0;
            q = true;
        }
        d[i] = dd;
    }
    if (q) {
        uint32_t *qc = vq;
        qc[0] = 1;
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_sqadd_d)(void *vd, void *vq, void *vn,
                          void *vm, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);
    int64_t *d = vd, *n = vn, *m = vm;
    bool q = false;

    for (i = 0; i < oprsz / 8; i++) {
        int64_t nn = n[i], mm = m[i], dd = nn + mm;
        if (((dd ^ nn) & ~(nn ^ mm)) & INT64_MIN) {
            dd = (nn >> 63) ^ ~INT64_MIN;
            q = true;
        }
        d[i] = dd;
    }
    if (q) {
        uint32_t *qc = vq;
        qc[0] = 1;
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_sqsub_d)(void *vd, void *vq, void *vn,
                          void *vm, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);
    int64_t *d = vd, *n = vn, *m = vm;
    bool q = false;

    for (i = 0; i < oprsz / 8; i++) {
        int64_t nn = n[i], mm = m[i], dd = nn - mm;
        if (((dd ^ nn) & (nn ^ mm)) & INT64_MIN) {
            dd = (nn >> 63) ^ ~INT64_MIN;
            q = true;
        }
        d[i] = dd;
    }
    if (q) {
        uint32_t *qc = vq;
        qc[0] = 1;
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

/*
 * Convert float16 to float32, raising no exceptions and
 * preserving exceptional values, including SNaN.
 * This is effectively an unpack+repack operation.
 */
static float32 float16_to_float32_by_bits(uint32_t f16, bool fz16)
{
    const int f16_bias = 15;
    const int f32_bias = 127;
    uint32_t sign = extract32(f16, 15, 1);
    uint32_t exp = extract32(f16, 10, 5);
    uint32_t frac = extract32(f16, 0, 10);

    if (exp == 0x1f) {
        /* Inf or NaN */
        exp = 0xff;
    } else if (exp == 0) {
        /* Zero or denormal.  */
        if (frac != 0) {
            if (fz16) {
                frac = 0;
            } else {
                /*
                 * Denormal; these are all normal float32.
                 * Shift the fraction so that the msb is at bit 11,
                 * then remove bit 11 as the implicit bit of the
                 * normalized float32.  Note that we still go through
                 * the shift for normal numbers below, to put the
                 * float32 fraction at the right place.
                 */
                int shift = clz32(frac) - 21;
                frac = (frac << shift) & 0x3ff;
                exp = f32_bias - f16_bias - shift + 1;
            }
        }
    } else {
        /* Normal number; adjust the bias.  */
        exp += f32_bias - f16_bias;
    }
    sign <<= 31;
    exp <<= 23;
    frac <<= 23 - 10;

    return sign | exp | frac;
}

static uint64_t load4_f16(uint64_t *ptr, int is_q, int is_2)
{
    /*
     * Branchless load of u32[0], u64[0], u32[1], or u64[1].
     * Load the 2nd qword iff is_q & is_2.
     * Shift to the 2nd dword iff !is_q & is_2.
     * For !is_q & !is_2, the upper bits of the result are garbage.
     */
    return ptr[is_q & is_2] >> ((is_2 & ~is_q) << 5);
}

/*
 * Note that FMLAL requires oprsz == 8 or oprsz == 16,
 * as there is not yet SVE versions that might use blocking.
 */

static void do_fmlal(float32 *d, void *vn, void *vm, float_status *fpst,
                     uint32_t desc, bool fz16)
{
    intptr_t i, oprsz = simd_oprsz(desc);
    int is_s = extract32(desc, SIMD_DATA_SHIFT, 1);
    int is_2 = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    int is_q = oprsz == 16;
    uint64_t n_4, m_4;

    /* Pre-load all of the f16 data, avoiding overlap issues.  */
    n_4 = load4_f16(vn, is_q, is_2);
    m_4 = load4_f16(vm, is_q, is_2);

    /* Negate all inputs for FMLSL at once.  */
    if (is_s) {
        n_4 ^= 0x8000800080008000ull;
    }

    for (i = 0; i < oprsz / 4; i++) {
        float32 n_1 = float16_to_float32_by_bits(n_4 >> (i * 16), fz16);
        float32 m_1 = float16_to_float32_by_bits(m_4 >> (i * 16), fz16);
        d[H4(i)] = float32_muladd(n_1, m_1, d[H4(i)], 0, fpst);
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_fmlal_a32)(void *vd, void *vn, void *vm,
                            void *venv, uint32_t desc)
{
    CPUARMState *env = venv;
    do_fmlal(vd, vn, vm, &env->vfp.standard_fp_status, desc,
             get_flush_inputs_to_zero(&env->vfp.fp_status_f16));
}

void HELPER(gvec_fmlal_a64)(void *vd, void *vn, void *vm,
                            void *venv, uint32_t desc)
{
    CPUARMState *env = venv;
    do_fmlal(vd, vn, vm, &env->vfp.fp_status, desc,
             get_flush_inputs_to_zero(&env->vfp.fp_status_f16));
}

void HELPER(sve2_fmlal_zzzw_s)(void *vd, void *vn, void *vm, void *va,
                               void *venv, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc) / sizeof(float32);
    uint16_t negn = extract32(desc, SIMD_DATA_SHIFT, 1) << 15;
    intptr_t sel = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    float16 *n = vn, *m = vm;
    float32 *d = vd, *a = va;
    CPUARMState *env = venv;
    float_status *status = &env->vfp.fp_status;
    bool fz16 = get_flush_inputs_to_zero(&env->vfp.fp_status_f16);

    for (i = 0; i < oprsz; i++) {
        intptr_t idx = i * 2 + sel;
        float16 nn_16 = n[H2(idx)] ^ negn;
        float16 mm_16 = m[H2(idx)];
        float32 nn = float16_to_float32_by_bits(nn_16, fz16);
        float32 mm = float16_to_float32_by_bits(mm_16, fz16);
        float32 aa = a[H4(i)];

        d[H4(i)] = float32_muladd(nn, mm, aa, 0, status);
    }
}

static void do_fmlal_idx(float32 *d, void *vn, void *vm, float_status *fpst,
                         uint32_t desc, bool fz16)
{
    intptr_t i, oprsz = simd_oprsz(desc);
    int is_s = extract32(desc, SIMD_DATA_SHIFT, 1);
    int is_2 = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    int index = extract32(desc, SIMD_DATA_SHIFT + 2, 3);
    int is_q = oprsz == 16;
    uint64_t n_4;
    float32 m_1;

    /* Pre-load all of the f16 data, avoiding overlap issues.  */
    n_4 = load4_f16(vn, is_q, is_2);

    /* Negate all inputs for FMLSL at once.  */
    if (is_s) {
        n_4 ^= 0x8000800080008000ull;
    }

    m_1 = float16_to_float32_by_bits(((float16 *)vm)[H2(index)], fz16);

    for (i = 0; i < oprsz / 4; i++) {
        float32 n_1 = float16_to_float32_by_bits(n_4 >> (i * 16), fz16);
        d[H4(i)] = float32_muladd(n_1, m_1, d[H4(i)], 0, fpst);
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

void HELPER(gvec_fmlal_idx_a32)(void *vd, void *vn, void *vm,
                                void *venv, uint32_t desc)
{
    CPUARMState *env = venv;
    do_fmlal_idx(vd, vn, vm, &env->vfp.standard_fp_status, desc,
                 get_flush_inputs_to_zero(&env->vfp.fp_status_f16));
}

void HELPER(gvec_fmlal_idx_a64)(void *vd, void *vn, void *vm,
                                void *venv, uint32_t desc)
{
    CPUARMState *env = venv;
    do_fmlal_idx(vd, vn, vm, &env->vfp.fp_status, desc,
                 get_flush_inputs_to_zero(&env->vfp.fp_status_f16));
}

void HELPER(sve2_fmlal_zzxw_s)(void *vd, void *vn, void *vm, void *va,
                               void *venv, uint32_t desc)
{
    intptr_t i, j, oprsz = simd_oprsz(desc);
    uint16_t negn = extract32(desc, SIMD_DATA_SHIFT, 1) << 15;
    intptr_t sel = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    intptr_t idx = extract32(desc, SIMD_DATA_SHIFT + 2, 3);
    float16 *n = vn, *m = vm;
    float32 *d = vd, *a = va;
    CPUARMState *env = venv;
    float_status *status = &env->vfp.fp_status;
    bool fz16 = get_flush_inputs_to_zero(&env->vfp.fp_status_f16);

    for (i = 0; i < oprsz; i += 16) {
        intptr_t hbase = i / sizeof(float16);
        intptr_t sbase = i / sizeof(float32);
        float16 mm_16 = m[H2(hbase + idx)];
        float32 mm = float16_to_float32_by_bits(mm_16, fz16);

        for (j = 0; j < 4; j++) {
            float16 nn_16 = n[H2(hbase + j * 2 + sel)] ^ negn;
            float32 nn = float16_to_float32_by_bits(nn_16, fz16);
            float32 aa = a[H4(sbase + j)];

            d[H4(sbase + j)] = float32_muladd(nn, mm, aa, 0, status);
        }
    }
}

void HELPER(gvec_sshl_b)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    int8_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz; ++i) {
        int8_t mm = m[i];
        int8_t nn = n[i];
        int8_t res = 0;
        if (mm >= 0) {
            if (mm < 8) {
                res = nn << mm;
            }
        } else {
            res = nn >> (mm > -8 ? -mm : 7);
        }
        d[i] = res;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_sshl_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    int16_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 2; ++i) {
        int8_t mm = m[i];   /* only 8 bits of shift are significant */
        int16_t nn = n[i];
        int16_t res = 0;
        if (mm >= 0) {
            if (mm < 16) {
                res = nn << mm;
            }
        } else {
            res = nn >> (mm > -16 ? -mm : 15);
        }
        d[i] = res;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_ushl_b)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    uint8_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz; ++i) {
        int8_t mm = m[i];
        uint8_t nn = n[i];
        uint8_t res = 0;
        if (mm >= 0) {
            if (mm < 8) {
                res = nn << mm;
            }
        } else {
            if (mm > -8) {
                res = nn >> -mm;
            }
        }
        d[i] = res;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

void HELPER(gvec_ushl_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    uint16_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 2; ++i) {
        int8_t mm = m[i];   /* only 8 bits of shift are significant */
        uint16_t nn = n[i];
        uint16_t res = 0;
        if (mm >= 0) {
            if (mm < 16) {
                res = nn << mm;
            }
        } else {
            if (mm > -16) {
                res = nn >> -mm;
            }
        }
        d[i] = res;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

/*
 * 8x8->8 polynomial multiply.
 *
 * Polynomial multiplication is like integer multiplication except the
 * partial products are XORed, not added.
 *
 * TODO: expose this as a generic vector operation, as it is a common
 * crypto building block.
 */
void HELPER(gvec_pmul_b)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    uint64_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 8; ++i) {
        uint64_t nn = n[i];
        uint64_t mm = m[i];
        uint64_t rr = 0;

        for (j = 0; j < 8; ++j) {
            uint64_t mask = (nn & 0x0101010101010101ull) * 0xff;
            rr ^= mm & mask;
            mm = (mm << 1) & 0xfefefefefefefefeull;
            nn >>= 1;
        }
        d[i] = rr;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

/*
 * 64x64->128 polynomial multiply.
 * Because of the lanes are not accessed in strict columns,
 * this probably cannot be turned into a generic helper.
 */
void HELPER(gvec_pmull_q)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    intptr_t hi = simd_data(desc);
    uint64_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 8; i += 2) {
        uint64_t nn = n[i + hi];
        uint64_t mm = m[i + hi];
        uint64_t rhi = 0;
        uint64_t rlo = 0;

        /* Bit 0 can only influence the low 64-bit result.  */
        if (nn & 1) {
            rlo = mm;
        }

        for (j = 1; j < 64; ++j) {
#ifdef _MSC_VER
            uint64_t mask = 0 - ((nn >> j) & 1);
#else
            uint64_t mask = -((nn >> j) & 1);
#endif
            rlo ^= (mm << j) & mask;
            rhi ^= (mm >> (64 - j)) & mask;
        }
        d[i] = rlo;
        d[i + 1] = rhi;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

/*
 * 8x8->16 polynomial multiply.
 *
 * The byte inputs are expanded to (or extracted from) half-words.
 * Note that neon and sve2 get the inputs from different positions.
 * This allows 4 bytes to be processed in parallel with uint64_t.
 */

static uint64_t expand_byte_to_half(uint64_t x)
{
    return  (x & 0x000000ff)
         | ((x & 0x0000ff00) << 8)
         | ((x & 0x00ff0000) << 16)
         | ((x & 0xff000000) << 24);
}

static uint64_t pmull_h(uint64_t op1, uint64_t op2)
{
    uint64_t result = 0;
    int i;

    for (i = 0; i < 8; ++i) {
        uint64_t mask = (op1 & 0x0001000100010001ull) * 0xffff;
        result ^= op2 & mask;
        op1 >>= 1;
        op2 <<= 1;
    }
    return result;
}

void HELPER(neon_pmull_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    int hi = simd_data(desc);
    uint64_t *d = vd, *n = vn, *m = vm;
    uint64_t nn = n[hi], mm = m[hi];

    d[0] = pmull_h(expand_byte_to_half(nn), expand_byte_to_half(mm));
    nn >>= 32;
    mm >>= 32;
    d[1] = pmull_h(expand_byte_to_half(nn), expand_byte_to_half(mm));

    clear_tail(d, 16, simd_maxsz(desc));
}

#ifdef TARGET_AARCH64
void HELPER(sve2_pmull_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    int shift = simd_data(desc) * 8;
    intptr_t i, opr_sz = simd_oprsz(desc);
    uint64_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 8; ++i) {
        uint64_t nn = (n[i] >> shift) & 0x00ff00ff00ff00ffull;
        uint64_t mm = (m[i] >> shift) & 0x00ff00ff00ff00ffull;

        d[i] = pmull_h(nn, mm);
    }
}

static uint64_t pmull_d(uint64_t op1, uint64_t op2)
{
    uint64_t result = 0;
    int i;

    for (i = 0; i < 32; i++) {
#ifdef _MSC_VER
        uint64_t mask = 0 - ((op1 >> i) & 1);
#else
        uint64_t mask = -((op1 >> i) & 1);
#endif
        result ^= (op2 << i) & mask;
    }
    return result;
}

void HELPER(sve2_pmull_d)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t sel = H4(simd_data(desc));
    intptr_t i, opr_sz = simd_oprsz(desc);
    uint32_t *n = vn, *m = vm;
    uint64_t *d = vd;

    for (i = 0; i < opr_sz / 8; i++) {
        d[i] = pmull_d(n[2 * i + sel], m[2 * i + sel]);
    }
}
#endif

#define DO_SABA(NAME, STYPE, UTYPE)                                     \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)          \
{                                                                       \
    intptr_t i, opr_sz = simd_oprsz(desc);                              \
    STYPE *d = vd, *n = vn, *m = vm;                                     \
                                                                        \
    for (i = 0; i < opr_sz / sizeof(STYPE); i++) {                      \
        UTYPE diff = n[i] < m[i] ? (UTYPE)m[i] - (UTYPE)n[i] :          \
                     (UTYPE)n[i] - (UTYPE)m[i];                         \
                                                                        \
        d[i] = (STYPE)((UTYPE)d[i] + diff);                             \
    }                                                                   \
    clear_tail(d, opr_sz, simd_maxsz(desc));                            \
}

DO_SABA(gvec_saba_b, int8_t, uint8_t)
DO_SABA(gvec_saba_h, int16_t, uint16_t)
DO_SABA(gvec_saba_s, int32_t, uint32_t)
DO_SABA(gvec_saba_d, int64_t, uint64_t)

#undef DO_SABA

#define DO_UABA(NAME, TYPE)                                             \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)          \
{                                                                       \
    intptr_t i, opr_sz = simd_oprsz(desc);                              \
    TYPE *d = vd, *n = vn, *m = vm;                                      \
                                                                        \
    for (i = 0; i < opr_sz / sizeof(TYPE); i++) {                       \
        TYPE diff = n[i] < m[i] ? m[i] - n[i] : n[i] - m[i];            \
                                                                        \
        d[i] += diff;                                                   \
    }                                                                   \
    clear_tail(d, opr_sz, simd_maxsz(desc));                            \
}

DO_UABA(gvec_uaba_b, uint8_t)
DO_UABA(gvec_uaba_h, uint16_t)
DO_UABA(gvec_uaba_s, uint32_t)
DO_UABA(gvec_uaba_d, uint64_t)

#undef DO_UABA
