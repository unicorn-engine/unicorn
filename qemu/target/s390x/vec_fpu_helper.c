/*
 * QEMU TCG support -- s390x vector floating point instruction support
 *
 * Copyright (C) 2019 Red Hat Inc
 *
 * Authors:
 *   David Hildenbrand <david@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "internal.h"
#include "vec.h"
#include "tcg_s390x.h"
#include "tcg/tcg-gvec-desc.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "fpu/softfloat.h"

#define VIC_INVALID         0x1
#define VIC_DIVBYZERO       0x2
#define VIC_OVERFLOW        0x3
#define VIC_UNDERFLOW       0x4
#define VIC_INEXACT         0x5

/* returns the VEX. If the VEX is 0, there is no trap */
static uint8_t check_ieee_exc(CPUS390XState *env, uint8_t enr, bool XxC,
                              uint8_t *vec_exc)
{
    uint8_t vece_exc = 0, trap_exc;
    unsigned qemu_exc;

    /* Retrieve and clear the softfloat exceptions */
    qemu_exc = env->fpu_status.float_exception_flags;
    if (qemu_exc == 0) {
        return 0;
    }
    env->fpu_status.float_exception_flags = 0;

    vece_exc = s390_softfloat_exc_to_ieee(qemu_exc);

    /* Add them to the vector-wide s390x exception bits */
    *vec_exc |= vece_exc;

    /* Check for traps and construct the VXC */
    trap_exc = vece_exc & env->fpc >> 24;
    if (trap_exc) {
        if (trap_exc & S390_IEEE_MASK_INVALID) {
            return enr << 4 | VIC_INVALID;
        } else if (trap_exc & S390_IEEE_MASK_DIVBYZERO) {
            return enr << 4 | VIC_DIVBYZERO;
        } else if (trap_exc & S390_IEEE_MASK_OVERFLOW) {
            return enr << 4 | VIC_OVERFLOW;
        } else if (trap_exc & S390_IEEE_MASK_UNDERFLOW) {
            return enr << 4 | VIC_UNDERFLOW;
        } else if (!XxC) {
            g_assert(trap_exc & S390_IEEE_MASK_INEXACT);
            /* inexact has lowest priority on traps */
            return enr << 4 | VIC_INEXACT;
        }
    }
    return 0;
}

static void handle_ieee_exc(CPUS390XState *env, uint8_t vxc, uint8_t vec_exc,
                            uintptr_t retaddr)
{
    if (vxc) {
        /* on traps, the fpc flags are not updated, instruction is suppressed */
        tcg_s390_vector_exception(env, vxc, retaddr);
    }
    if (vec_exc) {
        /* indicate exceptions for all elements combined */
        env->fpc |= vec_exc << 16;
    }
}

static float32 s390_vec_read_float32(const S390Vector *v, uint8_t enr)
{
    return make_float32(s390_vec_read_element32(v, enr));
}

static float64 s390_vec_read_float64(const S390Vector *v, uint8_t enr)
{
    return make_float64(s390_vec_read_element64(v, enr));
}

static float128 s390_vec_read_float128(const S390Vector *v)
{
    return make_float128(s390_vec_read_element64(v, 0),
                         s390_vec_read_element64(v, 1));
}

static void s390_vec_write_float32(S390Vector *v, uint8_t enr, float32 data)
{
    s390_vec_write_element32(v, enr, data);
}

static void s390_vec_write_float64(S390Vector *v, uint8_t enr, float64 data)
{
    s390_vec_write_element64(v, enr, data);
}

static void s390_vec_write_float128(S390Vector *v, float128 data)
{
    s390_vec_write_element64(v, 0, data.high);
    s390_vec_write_element64(v, 1, data.low);
}

typedef float32 (*vop32_2_fn)(float32 a, float_status *s);
static void vop32_2(S390Vector *v1, const S390Vector *v2, CPUS390XState *env,
                    bool s, bool XxC, uint8_t erm, vop32_2_fn fn,
                    uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i, old_mode;

    old_mode = s390_swap_bfp_rounding_mode(env, erm);
    for (i = 0; i < 4; i++) {
        const float32 a = s390_vec_read_float32(v2, i);

        s390_vec_write_float32(&tmp, i, fn(a, &env->fpu_status));
        vxc = check_ieee_exc(env, i, XxC, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    s390_restore_bfp_rounding_mode(env, old_mode);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

typedef uint64_t (*vop64_2_fn)(uint64_t a, float_status *s);
static void vop64_2(S390Vector *v1, const S390Vector *v2, CPUS390XState *env,
                    bool s, bool XxC, uint8_t erm, vop64_2_fn fn,
                    uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i, old_mode;

    old_mode = s390_swap_bfp_rounding_mode(env, erm);
    for (i = 0; i < 2; i++) {
        const uint64_t a = s390_vec_read_element64(v2, i);

        s390_vec_write_element64(&tmp, i, fn(a, &env->fpu_status));
        vxc = check_ieee_exc(env, i, XxC, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    s390_restore_bfp_rounding_mode(env, old_mode);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

typedef float128 (*vop128_2_fn)(float128 a, float_status *s);
static void vop128_2(S390Vector *v1, const S390Vector *v2, CPUS390XState *env,
                     bool s, bool XxC, uint8_t erm, vop128_2_fn fn,
                     uintptr_t retaddr)
{
    const float128 a = s390_vec_read_float128(v2);
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int old_mode;

    old_mode = s390_swap_bfp_rounding_mode(env, erm);
    s390_vec_write_float128(&tmp, fn(a, &env->fpu_status));
    vxc = check_ieee_exc(env, 0, XxC, &vec_exc);
    s390_restore_bfp_rounding_mode(env, old_mode);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

typedef float32 (*vop32_3_fn)(float32 a, float32 b, float_status *s);
static void vop32_3(S390Vector *v1, const S390Vector *v2,
                    const S390Vector *v3, CPUS390XState *env, bool s,
                    vop32_3_fn fn, uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i;

    for (i = 0; i < 4; i++) {
        const float32 a = s390_vec_read_float32(v2, i);
        const float32 b = s390_vec_read_float32(v3, i);

        s390_vec_write_float32(&tmp, i, fn(a, b, &env->fpu_status));
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

typedef uint64_t (*vop64_3_fn)(uint64_t a, uint64_t b, float_status *s);
static void vop64_3(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                    CPUS390XState *env, bool s, vop64_3_fn fn,
                    uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i;

    for (i = 0; i < 2; i++) {
        const uint64_t a = s390_vec_read_element64(v2, i);
        const uint64_t b = s390_vec_read_element64(v3, i);

        s390_vec_write_element64(&tmp, i, fn(a, b, &env->fpu_status));
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

typedef float128 (*vop128_3_fn)(float128 a, float128 b, float_status *s);
static void vop128_3(S390Vector *v1, const S390Vector *v2,
                     const S390Vector *v3, CPUS390XState *env, bool s,
                     vop128_3_fn fn, uintptr_t retaddr)
{
    const float128 a = s390_vec_read_float128(v2);
    const float128 b = s390_vec_read_float128(v3);
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };

    s390_vec_write_float128(&tmp, fn(a, b, &env->fpu_status));
    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

static float32 vfa32(float32 a, float32 b, float_status *s)
{
    return float32_add(a, b, s);
}

static uint64_t vfa64(uint64_t a, uint64_t b, float_status *s)
{
    return float64_add(a, b, s);
}

static float128 vfa128(float128 a, float128 b, float_status *s)
{
    return float128_add(a, b, s);
}

void HELPER(gvec_vfa32)(void *v1, const void *v2, const void *v3,
                        CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop32_3(v1, v2, v3, env, se, vfa32, GETPC());
}

void HELPER(gvec_vfa64)(void *v1, const void *v2, const void *v3,
                        CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop64_3(v1, v2, v3, env, se, vfa64, GETPC());
}

void HELPER(gvec_vfa128)(void *v1, const void *v2, const void *v3,
                         CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop128_3(v1, v2, v3, env, se, vfa128, GETPC());
}

static int wfc32(const S390Vector *v1, const S390Vector *v2,
                 CPUS390XState *env, bool signal, uintptr_t retaddr)
{
    const float32 a = s390_vec_read_float32(v1, 0);
    const float32 b = s390_vec_read_float32(v2, 0);
    uint8_t vxc, vec_exc = 0;
    int cmp;

    if (signal) {
        cmp = float32_compare(a, b, &env->fpu_status);
    } else {
        cmp = float32_compare_quiet(a, b, &env->fpu_status);
    }
    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);

    return float_comp_to_cc(env, cmp);
}

static int wfc64(const S390Vector *v1, const S390Vector *v2,
                 CPUS390XState *env, bool signal, uintptr_t retaddr)
{
    /* only the zero-indexed elements are compared */
    const float64 a = s390_vec_read_element64(v1, 0);
    const float64 b = s390_vec_read_element64(v2, 0);
    uint8_t vxc, vec_exc = 0;
    int cmp;

    if (signal) {
        cmp = float64_compare(a, b, &env->fpu_status);
    } else {
        cmp = float64_compare_quiet(a, b, &env->fpu_status);
    }
    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);

    return float_comp_to_cc(env, cmp);
}

static int wfc128(const S390Vector *v1, const S390Vector *v2,
                  CPUS390XState *env, bool signal, uintptr_t retaddr)
{
    const float128 a = s390_vec_read_float128(v1);
    const float128 b = s390_vec_read_float128(v2);
    uint8_t vxc, vec_exc = 0;
    int cmp;

    if (signal) {
        cmp = float128_compare(a, b, &env->fpu_status);
    } else {
        cmp = float128_compare_quiet(a, b, &env->fpu_status);
    }
    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);

    return float_comp_to_cc(env, cmp);
}

void HELPER(gvec_wfc32)(const void *v1, const void *v2, CPUS390XState *env,
                        uint32_t desc)
{
    env->cc_op = wfc32(v1, v2, env, false, GETPC());
}

void HELPER(gvec_wfk32)(const void *v1, const void *v2, CPUS390XState *env,
                        uint32_t desc)
{
    env->cc_op = wfc32(v1, v2, env, true, GETPC());
}

void HELPER(gvec_wfc64)(const void *v1, const void *v2, CPUS390XState *env,
                        uint32_t desc)
{
    env->cc_op = wfc64(v1, v2, env, false, GETPC());
}

void HELPER(gvec_wfk64)(const void *v1, const void *v2, CPUS390XState *env,
                        uint32_t desc)
{
    env->cc_op = wfc64(v1, v2, env, true, GETPC());
}

void HELPER(gvec_wfc128)(const void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    env->cc_op = wfc128(v1, v2, env, false, GETPC());
}

void HELPER(gvec_wfk128)(const void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    env->cc_op = wfc128(v1, v2, env, true, GETPC());
}

typedef bool (*vfc32_fn)(float32 a, float32 b, float_status *status);
static int vfc32(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                 CPUS390XState *env, bool s, vfc32_fn fn, uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int match = 0;
    int i;

    for (i = 0; i < 4; i++) {
        const float32 a = s390_vec_read_float32(v2, i);
        const float32 b = s390_vec_read_float32(v3, i);

        if (fn(b, a, &env->fpu_status)) {
            match++;
            s390_vec_write_element32(&tmp, i, -1u);
        }
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }

    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
    if (match) {
        return s || match == 4 ? 0 : 1;
    }
    return 3;
}

typedef bool (*vfc64_fn)(float64 a, float64 b, float_status *status);
static int vfc64(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                 CPUS390XState *env, bool s, vfc64_fn fn, uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int match = 0;
    int i;

    for (i = 0; i < 2; i++) {
        const float64 a = s390_vec_read_element64(v2, i);
        const float64 b = s390_vec_read_element64(v3, i);

        /* swap the order of the parameters, so we can use existing functions */
        if (fn(b, a, &env->fpu_status)) {
            match++;
            s390_vec_write_element64(&tmp, i, -1ull);
        }
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }

    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
    if (match) {
        return s || match == 2 ? 0 : 1;
    }
    return 3;
}

typedef bool (*vfc128_fn)(float128 a, float128 b, float_status *status);
static int vfc128(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                  CPUS390XState *env, bool s, vfc128_fn fn, uintptr_t retaddr)
{
    const float128 a = s390_vec_read_float128(v2);
    const float128 b = s390_vec_read_float128(v3);
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    bool match = false;

    if (fn(b, a, &env->fpu_status)) {
        match = true;
        s390_vec_write_element64(&tmp, 0, -1ull);
        s390_vec_write_element64(&tmp, 1, -1ull);
    }
    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
    return match ? 0 : 3;
}

void HELPER(gvec_vfce32)(void *v1, const void *v2, const void *v3,
                         CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc32_fn fn = sq ? float32_eq : float32_eq_quiet;

    vfc32(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfce32_cc)(void *v1, const void *v2, const void *v3,
                            CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc32_fn fn = sq ? float32_eq : float32_eq_quiet;

    env->cc_op = vfc32(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfce64)(void *v1, const void *v2, const void *v3,
                         CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc64_fn fn = sq ? float64_eq : float64_eq_quiet;

    vfc64(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfce64_cc)(void *v1, const void *v2, const void *v3,
                            CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc64_fn fn = sq ? float64_eq : float64_eq_quiet;

    env->cc_op = vfc64(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfch64)(void *v1, const void *v2, const void *v3,
                         CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc64_fn fn = sq ? float64_lt : float64_lt_quiet;

    vfc64(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfch64_cc)(void *v1, const void *v2, const void *v3,
                            CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc64_fn fn = sq ? float64_lt : float64_lt_quiet;

    env->cc_op = vfc64(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfche64)(void *v1, const void *v2, const void *v3,
                          CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc64_fn fn = sq ? float64_le : float64_le_quiet;

    vfc64(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfche64_cc)(void *v1, const void *v2, const void *v3,
                             CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc64_fn fn = sq ? float64_le : float64_le_quiet;

    env->cc_op = vfc64(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfce128)(void *v1, const void *v2, const void *v3,
                          CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc128_fn fn = sq ? float128_eq : float128_eq_quiet;

    vfc128(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfce128_cc)(void *v1, const void *v2, const void *v3,
                             CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc128_fn fn = sq ? float128_eq : float128_eq_quiet;

    env->cc_op = vfc128(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfch32)(void *v1, const void *v2, const void *v3,
                         CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc32_fn fn = sq ? float32_lt : float32_lt_quiet;

    vfc32(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfch32_cc)(void *v1, const void *v2, const void *v3,
                            CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc32_fn fn = sq ? float32_lt : float32_lt_quiet;

    env->cc_op = vfc32(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfch128)(void *v1, const void *v2, const void *v3,
                          CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc128_fn fn = sq ? float128_lt : float128_lt_quiet;

    vfc128(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfch128_cc)(void *v1, const void *v2, const void *v3,
                             CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc128_fn fn = sq ? float128_lt : float128_lt_quiet;

    env->cc_op = vfc128(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfche32)(void *v1, const void *v2, const void *v3,
                          CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc32_fn fn = sq ? float32_le : float32_le_quiet;

    vfc32(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfche32_cc)(void *v1, const void *v2, const void *v3,
                             CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc32_fn fn = sq ? float32_le : float32_le_quiet;

    env->cc_op = vfc32(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfche128)(void *v1, const void *v2, const void *v3,
                           CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc128_fn fn = sq ? float128_le : float128_le_quiet;

    vfc128(v1, v2, v3, env, se, fn, GETPC());
}

void HELPER(gvec_vfche128_cc)(void *v1, const void *v2, const void *v3,
                              CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool sq = extract32(simd_data(desc), 2, 1);
    vfc128_fn fn = sq ? float128_le : float128_le_quiet;

    env->cc_op = vfc128(v1, v2, v3, env, se, fn, GETPC());
}

static float32 vcdg32(float32 a, float_status *s)
{
    return int32_to_float32(a, s);
}

static float32 vcdlg32(float32 a, float_status *s)
{
    return uint32_to_float32(a, s);
}

static float32 vcgd32(float32 a, float_status *s)
{
    const float32 tmp = float32_to_int32(a, s);

    return float32_is_any_nan(a) ? INT32_MIN : tmp;
}

static float32 vclgd32(float32 a, float_status *s)
{
    const float32 tmp = float32_to_uint32(a, s);

    return float32_is_any_nan(a) ? 0 : tmp;
}

void HELPER(gvec_vcdg32)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop32_2(v1, v2, env, se, XxC, erm, vcdg32, GETPC());
}

void HELPER(gvec_vcdlg32)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop32_2(v1, v2, env, se, XxC, erm, vcdlg32, GETPC());
}

void HELPER(gvec_vcgd32)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop32_2(v1, v2, env, se, XxC, erm, vcgd32, GETPC());
}

void HELPER(gvec_vclgd32)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop32_2(v1, v2, env, se, XxC, erm, vclgd32, GETPC());
}

static uint64_t vcdg64(uint64_t a, float_status *s)
{
    return int64_to_float64(a, s);
}

void HELPER(gvec_vcdg64)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop64_2(v1, v2, env, se, XxC, erm, vcdg64, GETPC());
}

static uint64_t vcdlg64(uint64_t a, float_status *s)
{
    return uint64_to_float64(a, s);
}

void HELPER(gvec_vcdlg64)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop64_2(v1, v2, env, se, XxC, erm, vcdlg64, GETPC());
}

static uint64_t vcgd64(uint64_t a, float_status *s)
{
    const uint64_t tmp = float64_to_int64(a, s);

    return float64_is_any_nan(a) ? INT64_MIN : tmp;
}

void HELPER(gvec_vcgd64)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop64_2(v1, v2, env, se, XxC, erm, vcgd64, GETPC());
}

static uint64_t vclgd64(uint64_t a, float_status *s)
{
    const uint64_t tmp = float64_to_uint64(a, s);

    return float64_is_any_nan(a) ? 0 : tmp;
}

void HELPER(gvec_vclgd64)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop64_2(v1, v2, env, se, XxC, erm, vclgd64, GETPC());
}

static float32 vfd32(float32 a, float32 b, float_status *s)
{
    return float32_div(a, b, s);
}

static uint64_t vfd64(uint64_t a, uint64_t b, float_status *s)
{
    return float64_div(a, b, s);
}

static float128 vfd128(float128 a, float128 b, float_status *s)
{
    return float128_div(a, b, s);
}

void HELPER(gvec_vfd32)(void *v1, const void *v2, const void *v3,
                        CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop32_3(v1, v2, v3, env, se, vfd32, GETPC());
}

void HELPER(gvec_vfd64)(void *v1, const void *v2, const void *v3,
                        CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop64_3(v1, v2, v3, env, se, vfd64, GETPC());
}

void HELPER(gvec_vfd128)(void *v1, const void *v2, const void *v3,
                         CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop128_3(v1, v2, v3, env, se, vfd128, GETPC());
}

static float32 vfi32(float32 a, float_status *s)
{
    return float32_round_to_int(a, s);
}

static uint64_t vfi64(uint64_t a, float_status *s)
{
    return float64_round_to_int(a, s);
}

static float128 vfi128(float128 a, float_status *s)
{
    return float128_round_to_int(a, s);
}

void HELPER(gvec_vfi32)(void *v1, const void *v2, CPUS390XState *env,
                        uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop32_2(v1, v2, env, se, XxC, erm, vfi32, GETPC());
}

void HELPER(gvec_vfi64)(void *v1, const void *v2, CPUS390XState *env,
                        uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop64_2(v1, v2, env, se, XxC, erm, vfi64, GETPC());
}

void HELPER(gvec_vfi128)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vop128_2(v1, v2, env, se, XxC, erm, vfi128, GETPC());
}

static void vfll32(S390Vector *v1, const S390Vector *v2, CPUS390XState *env,
                   bool s, uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i;

    for (i = 0; i < 2; i++) {
        /* load from even element */
        const float32 a = s390_vec_read_element32(v2, i * 2);
        const uint64_t ret = float32_to_float64(a, &env->fpu_status);

        s390_vec_write_element64(&tmp, i, ret);
        /* indicate the source element */
        vxc = check_ieee_exc(env, i * 2, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

void HELPER(gvec_vfll32)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vfll32(v1, v2, env, se, GETPC());
}

void HELPER(gvec_vfll64)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const float128 ret = float64_to_float128(s390_vec_read_float64(v2, 0),
                                             &env->fpu_status);
    uint8_t vxc, vec_exc = 0;

    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, GETPC());
    s390_vec_write_float128(v1, ret);
}

static void vflr64(S390Vector *v1, const S390Vector *v2, CPUS390XState *env,
                   bool s, bool XxC, uint8_t erm, uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i, old_mode;

    old_mode = s390_swap_bfp_rounding_mode(env, erm);
    for (i = 0; i < 2; i++) {
        float64 a = s390_vec_read_element64(v2, i);
        uint32_t ret = float64_to_float32(a, &env->fpu_status);

        /* place at even element */
        s390_vec_write_element32(&tmp, i * 2, ret);
        /* indicate the source element */
        vxc = check_ieee_exc(env, i, XxC, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    s390_restore_bfp_rounding_mode(env, old_mode);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

void HELPER(gvec_vflr64)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool se = extract32(simd_data(desc), 3, 1);
    const bool XxC = extract32(simd_data(desc), 2, 1);

    vflr64(v1, v2, env, se, XxC, erm, GETPC());
}

void HELPER(gvec_vflr128)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const uint8_t erm = extract32(simd_data(desc), 4, 4);
    const bool XxC = extract32(simd_data(desc), 2, 1);
    uint8_t vxc, vec_exc = 0;
    int old_mode;
    float64 ret;

    old_mode = s390_swap_bfp_rounding_mode(env, erm);
    ret = float128_to_float64(s390_vec_read_float128(v2), &env->fpu_status);
    vxc = check_ieee_exc(env, 0, XxC, &vec_exc);
    s390_restore_bfp_rounding_mode(env, old_mode);
    handle_ieee_exc(env, vxc, vec_exc, GETPC());
    s390_vec_write_float64(v1, 0, ret);
}

static float32 vfm32(float32 a, float32 b, float_status *s)
{
    return float32_mul(a, b, s);
}

static uint64_t vfm64(uint64_t a, uint64_t b, float_status *s)
{
    return float64_mul(a, b, s);
}

static float128 vfm128(float128 a, float128 b, float_status *s)
{
    return float128_mul(a, b, s);
}

void HELPER(gvec_vfm32)(void *v1, const void *v2, const void *v3,
                        CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop32_3(v1, v2, v3, env, se, vfm32, GETPC());
}

void HELPER(gvec_vfm64)(void *v1, const void *v2, const void *v3,
                        CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop64_3(v1, v2, v3, env, se, vfm64, GETPC());
}

void HELPER(gvec_vfm128)(void *v1, const void *v2, const void *v3,
                         CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop128_3(v1, v2, v3, env, se, vfm128, GETPC());
}

static void vfma32(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                   const S390Vector *v4, CPUS390XState *env, bool s, int flags,
                   uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i;

    for (i = 0; i < 4; i++) {
        const float32 a = s390_vec_read_float32(v2, i);
        const float32 b = s390_vec_read_float32(v3, i);
        const float32 c = s390_vec_read_float32(v4, i);
        float32 ret = float32_muladd(a, b, c, flags, &env->fpu_status);

        s390_vec_write_float32(&tmp, i, ret);
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

static void vfma64(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                   const S390Vector *v4, CPUS390XState *env, bool s, int flags,
                   uintptr_t retaddr)
{
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i;

    for (i = 0; i < 2; i++) {
        const float64 a = s390_vec_read_float64(v2, i);
        const float64 b = s390_vec_read_float64(v3, i);
        const float64 c = s390_vec_read_float64(v4, i);
        const float64 ret = float64_muladd(a, b, c, flags,
                                           &env->fpu_status);

        s390_vec_write_float64(&tmp, i, ret);
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (s || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

static void vfma128(S390Vector *v1, const S390Vector *v2, const S390Vector *v3,
                    const S390Vector *v4, CPUS390XState *env, bool s,
                    int flags, uintptr_t retaddr)
{
    const float128 a = s390_vec_read_float128(v2);
    const float128 b = s390_vec_read_float128(v3);
    const float128 c = s390_vec_read_float128(v4);
    uint8_t vxc, vec_exc = 0;
    float128 ret;

    ret = float128_muladd(a, b, c, flags, &env->fpu_status);
    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    s390_vec_write_float128(v1, ret);
}

#define DEF_GVEC_VFMA_B(NAME, FLAGS, BITS)                               \
void HELPER(gvec_##NAME##BITS)(void *v1, const void *v2, const void *v3, \
                               const void *v4, CPUS390XState *env,       \
                               uint32_t desc)                            \
{                                                                        \
    const bool se = extract32(simd_data(desc), 3, 1);                    \
                                                                         \
    vfma##BITS(v1, v2, v3, v4, env, se, FLAGS, GETPC());                 \
}

#define DEF_GVEC_VFMA(NAME, FLAGS)                                       \
    DEF_GVEC_VFMA_B(NAME, FLAGS, 32)                                     \
    DEF_GVEC_VFMA_B(NAME, FLAGS, 64)                                     \
    DEF_GVEC_VFMA_B(NAME, FLAGS, 128)

DEF_GVEC_VFMA(vfma, 0)
DEF_GVEC_VFMA(vfms, float_muladd_negate_c)
DEF_GVEC_VFMA(vfnma, float_muladd_negate_result)
DEF_GVEC_VFMA(vfnms, float_muladd_negate_c | float_muladd_negate_result)

typedef enum S390MinMaxType {
    S390_MINMAX_TYPE_IEEE = 0,
    S390_MINMAX_TYPE_JAVA,
    S390_MINMAX_TYPE_C_MACRO,
    S390_MINMAX_TYPE_CPP,
    S390_MINMAX_TYPE_F,
} S390MinMaxType;

typedef enum S390MinMaxRes {
    S390_MINMAX_RES_MINMAX = 0,
    S390_MINMAX_RES_A,
    S390_MINMAX_RES_B,
    S390_MINMAX_RES_SILENCE_A,
    S390_MINMAX_RES_SILENCE_B,
} S390MinMaxRes;

static S390MinMaxRes vfmin_res(uint16_t dcmask_a, uint16_t dcmask_b,
                               S390MinMaxType type, float_status *s)
{
    const bool neg_a = dcmask_a & DCMASK_NEGATIVE;
    const bool nan_a = dcmask_a & DCMASK_NAN;
    const bool nan_b = dcmask_b & DCMASK_NAN;

    g_assert(type > S390_MINMAX_TYPE_IEEE && type <= S390_MINMAX_TYPE_F);

    if (unlikely((dcmask_a | dcmask_b) & DCMASK_NAN)) {
        const bool sig_a = dcmask_a & DCMASK_SIGNALING_NAN;
        const bool sig_b = dcmask_b & DCMASK_SIGNALING_NAN;

        if ((dcmask_a | dcmask_b) & DCMASK_SIGNALING_NAN) {
            s->float_exception_flags |= float_flag_invalid;
        }
        switch (type) {
        case S390_MINMAX_TYPE_JAVA:
            if (sig_a) {
                return S390_MINMAX_RES_SILENCE_A;
            } else if (sig_b) {
                return S390_MINMAX_RES_SILENCE_B;
            }
            return nan_a ? S390_MINMAX_RES_A : S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_F:
            return nan_b ? S390_MINMAX_RES_A : S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_C_MACRO:
            s->float_exception_flags |= float_flag_invalid;
            return S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_CPP:
            s->float_exception_flags |= float_flag_invalid;
            return S390_MINMAX_RES_A;
        default:
            g_assert_not_reached();
        }
    } else if (unlikely((dcmask_a & DCMASK_ZERO) && (dcmask_b & DCMASK_ZERO))) {
        switch (type) {
        case S390_MINMAX_TYPE_JAVA:
            return neg_a ? S390_MINMAX_RES_A : S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_C_MACRO:
            return S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_F:
            return !neg_a ? S390_MINMAX_RES_B : S390_MINMAX_RES_A;
        case S390_MINMAX_TYPE_CPP:
            return S390_MINMAX_RES_A;
        default:
            g_assert_not_reached();
        }
    }
    return S390_MINMAX_RES_MINMAX;
}

static S390MinMaxRes vfmax_res(uint16_t dcmask_a, uint16_t dcmask_b,
                               S390MinMaxType type, float_status *s)
{
    g_assert(type > S390_MINMAX_TYPE_IEEE && type <= S390_MINMAX_TYPE_F);

    if (unlikely((dcmask_a | dcmask_b) & DCMASK_NAN)) {
        const bool sig_a = dcmask_a & DCMASK_SIGNALING_NAN;
        const bool sig_b = dcmask_b & DCMASK_SIGNALING_NAN;
        const bool nan_a = dcmask_a & DCMASK_NAN;
        const bool nan_b = dcmask_b & DCMASK_NAN;

        if ((dcmask_a | dcmask_b) & DCMASK_SIGNALING_NAN) {
            s->float_exception_flags |= float_flag_invalid;
        }
        switch (type) {
        case S390_MINMAX_TYPE_JAVA:
            if (sig_a) {
                return S390_MINMAX_RES_SILENCE_A;
            } else if (sig_b) {
                return S390_MINMAX_RES_SILENCE_B;
            }
            return nan_a ? S390_MINMAX_RES_A : S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_F:
            return nan_b ? S390_MINMAX_RES_A : S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_C_MACRO:
            s->float_exception_flags |= float_flag_invalid;
            return S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_CPP:
            s->float_exception_flags |= float_flag_invalid;
            return S390_MINMAX_RES_A;
        default:
            g_assert_not_reached();
        }
    } else if (unlikely((dcmask_a & DCMASK_ZERO) && (dcmask_b & DCMASK_ZERO))) {
        const bool neg_a = dcmask_a & DCMASK_NEGATIVE;

        switch (type) {
        case S390_MINMAX_TYPE_JAVA:
        case S390_MINMAX_TYPE_F:
            return neg_a ? S390_MINMAX_RES_B : S390_MINMAX_RES_A;
        case S390_MINMAX_TYPE_C_MACRO:
            return S390_MINMAX_RES_B;
        case S390_MINMAX_TYPE_CPP:
            return S390_MINMAX_RES_A;
        default:
            g_assert_not_reached();
        }
    }
    return S390_MINMAX_RES_MINMAX;
}

static S390MinMaxRes vfminmax_res(uint16_t dcmask_a, uint16_t dcmask_b,
                                  S390MinMaxType type, bool is_min,
                                  float_status *s)
{
    return is_min ? vfmin_res(dcmask_a, dcmask_b, type, s) :
                    vfmax_res(dcmask_a, dcmask_b, type, s);
}

static void vfminmax32(S390Vector *v1, const S390Vector *v2,
                       const S390Vector *v3, CPUS390XState *env,
                       S390MinMaxType type, bool is_min, bool is_abs, bool se,
                       uintptr_t retaddr)
{
    float_status *s = &env->fpu_status;
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i;

    for (i = 0; i < 4; i++) {
        float32 a = s390_vec_read_float32(v2, i);
        float32 b = s390_vec_read_float32(v3, i);
        float32 result;

        if (type != S390_MINMAX_TYPE_IEEE) {
            S390MinMaxRes res;

            if (is_abs) {
                a = float32_abs(a);
                b = float32_abs(b);
            }

            res = vfminmax_res(float32_dcmask(env, a), float32_dcmask(env, b),
                               type, is_min, s);
            switch (res) {
            case S390_MINMAX_RES_MINMAX:
                result = is_min ? float32_min(a, b, s) : float32_max(a, b, s);
                break;
            case S390_MINMAX_RES_A:
                result = a;
                break;
            case S390_MINMAX_RES_B:
                result = b;
                break;
            case S390_MINMAX_RES_SILENCE_A:
                result = float32_silence_nan(a, s);
                break;
            case S390_MINMAX_RES_SILENCE_B:
                result = float32_silence_nan(b, s);
                break;
            default:
                g_assert_not_reached();
            }
        } else if (!is_abs) {
            result = is_min ? float32_minnum(a, b, &env->fpu_status) :
                              float32_maxnum(a, b, &env->fpu_status);
        } else {
            result = is_min ? float32_minnummag(a, b, &env->fpu_status) :
                              float32_maxnummag(a, b, &env->fpu_status);
        }

        s390_vec_write_float32(&tmp, i, result);
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (se || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

static void vfminmax64(S390Vector *v1, const S390Vector *v2,
                       const S390Vector *v3, CPUS390XState *env,
                       S390MinMaxType type, bool is_min, bool is_abs, bool se,
                       uintptr_t retaddr)
{
    float_status *s = &env->fpu_status;
    uint8_t vxc, vec_exc = 0;
    S390Vector tmp = { 0 };
    int i;

    for (i = 0; i < 2; i++) {
        float64 a = s390_vec_read_float64(v2, i);
        float64 b = s390_vec_read_float64(v3, i);
        float64 result;

        if (type != S390_MINMAX_TYPE_IEEE) {
            S390MinMaxRes res;

            if (is_abs) {
                a = float64_abs(a);
                b = float64_abs(b);
            }

            res = vfminmax_res(float64_dcmask(env, a), float64_dcmask(env, b),
                               type, is_min, s);
            switch (res) {
            case S390_MINMAX_RES_MINMAX:
                result = is_min ? float64_min(a, b, s) : float64_max(a, b, s);
                break;
            case S390_MINMAX_RES_A:
                result = a;
                break;
            case S390_MINMAX_RES_B:
                result = b;
                break;
            case S390_MINMAX_RES_SILENCE_A:
                result = float64_silence_nan(a, s);
                break;
            case S390_MINMAX_RES_SILENCE_B:
                result = float64_silence_nan(b, s);
                break;
            default:
                g_assert_not_reached();
            }
        } else if (!is_abs) {
            result = is_min ? float64_minnum(a, b, &env->fpu_status) :
                              float64_maxnum(a, b, &env->fpu_status);
        } else {
            result = is_min ? float64_minnummag(a, b, &env->fpu_status) :
                              float64_maxnummag(a, b, &env->fpu_status);
        }

        s390_vec_write_float64(&tmp, i, result);
        vxc = check_ieee_exc(env, i, false, &vec_exc);
        if (se || vxc) {
            break;
        }
    }
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    *v1 = tmp;
}

static void vfminmax128(S390Vector *v1, const S390Vector *v2,
                        const S390Vector *v3, CPUS390XState *env,
                        S390MinMaxType type, bool is_min, bool is_abs, bool se,
                        uintptr_t retaddr)
{
    float128 a = s390_vec_read_float128(v2);
    float128 b = s390_vec_read_float128(v3);
    float_status *s = &env->fpu_status;
    uint8_t vxc, vec_exc = 0;
    float128 result;

    if (type != S390_MINMAX_TYPE_IEEE) {
        S390MinMaxRes res;

        if (is_abs) {
            a = float128_abs(a);
            b = float128_abs(b);
        }

        res = vfminmax_res(float128_dcmask(env, a), float128_dcmask(env, b),
                           type, is_min, s);
        switch (res) {
        case S390_MINMAX_RES_MINMAX:
            result = is_min ? float128_min(a, b, s) : float128_max(a, b, s);
            break;
        case S390_MINMAX_RES_A:
            result = a;
            break;
        case S390_MINMAX_RES_B:
            result = b;
            break;
        case S390_MINMAX_RES_SILENCE_A:
            result = float128_silence_nan(a, s);
            break;
        case S390_MINMAX_RES_SILENCE_B:
            result = float128_silence_nan(b, s);
            break;
        default:
            g_assert_not_reached();
        }
    } else if (!is_abs) {
        result = is_min ? float128_minnum(a, b, &env->fpu_status) :
                          float128_maxnum(a, b, &env->fpu_status);
    } else {
        result = is_min ? float128_minnummag(a, b, &env->fpu_status) :
                          float128_maxnummag(a, b, &env->fpu_status);
    }

    vxc = check_ieee_exc(env, 0, false, &vec_exc);
    handle_ieee_exc(env, vxc, vec_exc, retaddr);
    s390_vec_write_float128(v1, result);
}

#define DEF_GVEC_VFMINMAX_B(NAME, IS_MIN, BITS)                          \
void HELPER(gvec_##NAME##BITS)(void *v1, const void *v2, const void *v3, \
                               CPUS390XState *env, uint32_t desc)        \
{                                                                        \
    const bool se = extract32(simd_data(desc), 3, 1);                    \
    uint8_t type = extract32(simd_data(desc), 4, 4);                     \
    bool is_abs = false;                                                 \
                                                                         \
    if (type >= 8) {                                                     \
        is_abs = true;                                                   \
        type -= 8;                                                       \
    }                                                                    \
                                                                         \
    vfminmax##BITS(v1, v2, v3, env, type, IS_MIN, is_abs, se, GETPC());  \
}

#define DEF_GVEC_VFMINMAX(NAME, IS_MIN)                                  \
    DEF_GVEC_VFMINMAX_B(NAME, IS_MIN, 32)                                \
    DEF_GVEC_VFMINMAX_B(NAME, IS_MIN, 64)                                \
    DEF_GVEC_VFMINMAX_B(NAME, IS_MIN, 128)

DEF_GVEC_VFMINMAX(vfmax, false)
DEF_GVEC_VFMINMAX(vfmin, true)

static float32 vfsq32(float32 a, float_status *s)
{
    return float32_sqrt(a, s);
}

static uint64_t vfsq64(uint64_t a, float_status *s)
{
    return float64_sqrt(a, s);
}

static float128 vfsq128(float128 a, float_status *s)
{
    return float128_sqrt(a, s);
}

void HELPER(gvec_vfsq32)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop32_2(v1, v2, env, se, false, 0, vfsq32, GETPC());
}

void HELPER(gvec_vfsq64)(void *v1, const void *v2, CPUS390XState *env,
                         uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop64_2(v1, v2, env, se, false, 0, vfsq64, GETPC());
}

void HELPER(gvec_vfsq128)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop128_2(v1, v2, env, se, false, 0, vfsq128, GETPC());
}

static float32 vfs32(float32 a, float32 b, float_status *s)
{
    return float32_sub(a, b, s);
}

static uint64_t vfs64(uint64_t a, uint64_t b, float_status *s)
{
    return float64_sub(a, b, s);
}

static float128 vfs128(float128 a, float128 b, float_status *s)
{
    return float128_sub(a, b, s);
}

void HELPER(gvec_vfs32)(void *v1, const void *v2, const void *v3,
                        CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop32_3(v1, v2, v3, env, se, vfs32, GETPC());
}

void HELPER(gvec_vfs64)(void *v1, const void *v2, const void *v3,
                        CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop64_3(v1, v2, v3, env, se, vfs64, GETPC());
}

void HELPER(gvec_vfs128)(void *v1, const void *v2, const void *v3,
                         CPUS390XState *env, uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);

    vop128_3(v1, v2, v3, env, se, vfs128, GETPC());
}

void HELPER(gvec_vftci32)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const uint16_t i3 = extract32(simd_data(desc), 4, 12);
    const bool se = extract32(simd_data(desc), 3, 1);
    int match = 0;
    int i;

    for (i = 0; i < 4; i++) {
        float32 a = s390_vec_read_float32(v2, i);

        if (float32_dcmask(env, a) & i3) {
            match++;
            s390_vec_write_element32(v1, i, -1u);
        } else {
            s390_vec_write_element32(v1, i, 0);
        }
        if (se) {
            break;
        }
    }

    if (match == 4 || (se && match)) {
        env->cc_op = 0;
    } else if (match) {
        env->cc_op = 1;
    } else {
        env->cc_op = 3;
    }
}

static int vftci64(S390Vector *v1, const S390Vector *v2, CPUS390XState *env,
                   bool s, uint16_t i3)
{
    int i, match = 0;

    for (i = 0; i < 2; i++) {
        float64 a = s390_vec_read_element64(v2, i);

        if (float64_dcmask(env, a) & i3) {
            match++;
            s390_vec_write_element64(v1, i, -1ull);
        } else {
            s390_vec_write_element64(v1, i, 0);
        }
        if (s) {
            break;
        }
    }

    if (match) {
        return s || match == 2 ? 0 : 1;
    }
    return 3;
}

void HELPER(gvec_vftci64)(void *v1, const void *v2, CPUS390XState *env,
                          uint32_t desc)
{
    const bool se = extract32(simd_data(desc), 3, 1);
    const uint16_t i3 = extract32(simd_data(desc), 4, 12);

    env->cc_op = vftci64(v1, v2, env, se, i3);
}

void HELPER(gvec_vftci128)(void *v1, const void *v2, CPUS390XState *env,
                           uint32_t desc)
{
    const float128 a = s390_vec_read_float128(v2);
    const uint16_t i3 = extract32(simd_data(desc), 4, 12);

    if (float128_dcmask(env, a) & i3) {
        env->cc_op = 0;
        s390_vec_write_element64(v1, 0, -1ull);
        s390_vec_write_element64(v1, 1, -1ull);
    } else {
        env->cc_op = 3;
        s390_vec_write_element64(v1, 0, 0);
        s390_vec_write_element64(v1, 1, 0);
    }
}
