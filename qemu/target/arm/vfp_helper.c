/*
 * ARM VFP floating-point operations
 *
 *  Copyright (c) 2003 Fabrice Bellard
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
#include "exec/helper-proto.h"
#include "internals.h"
#include "qemu/log.h"
#include "fpu/softfloat.h"

/* VFP support.  We follow the convention used for VFP instructions:
   Single precision routines have a "s" suffix, double precision a
   "d" suffix.  */

/* Convert host exception flags to vfp form.  */
static inline int vfp_exceptbits_from_host(int host_bits)
{
    int target_bits = 0;

    if (host_bits & float_flag_invalid) {
        target_bits |= 1;
    }
    if (host_bits & float_flag_divbyzero) {
        target_bits |= 2;
    }
    if (host_bits & float_flag_overflow) {
        target_bits |= 4;
    }
    if (host_bits & (float_flag_underflow | float_flag_output_denormal)) {
        target_bits |= 8;
    }
    if (host_bits & float_flag_inexact) {
        target_bits |= 0x10;
    }
    if (host_bits & float_flag_input_denormal) {
        target_bits |= 0x80;
    }
    return target_bits;
}

/* Convert vfp exception flags to target form.  */
static inline int vfp_exceptbits_to_host(int target_bits)
{
    int host_bits = 0;

    if (target_bits & 1) {
        host_bits |= float_flag_invalid;
    }
    if (target_bits & 2) {
        host_bits |= float_flag_divbyzero;
    }
    if (target_bits & 4) {
        host_bits |= float_flag_overflow;
    }
    if (target_bits & 8) {
        host_bits |= float_flag_underflow;
    }
    if (target_bits & 0x10) {
        host_bits |= float_flag_inexact;
    }
    if (target_bits & 0x80) {
        host_bits |= float_flag_input_denormal;
    }
    return host_bits;
}

static uint32_t vfp_get_fpscr_from_host(CPUARMState *env)
{
    uint32_t i;

    i = get_float_exception_flags(&env->vfp.fp_status);
    i |= get_float_exception_flags(&env->vfp.standard_fp_status);
    /* FZ16 does not generate an input denormal exception.  */
    i |= (get_float_exception_flags(&env->vfp.fp_status_f16)
          & ~float_flag_input_denormal);
    return vfp_exceptbits_from_host(i);
}

static void vfp_set_fpscr_to_host(CPUARMState *env, uint32_t val)
{
    int i;
    uint32_t changed = env->vfp.xregs[ARM_VFP_FPSCR];

    changed ^= val;
    if (changed & (3 << 22)) {
        i = (val >> 22) & 3;
        switch (i) {
        case FPROUNDING_TIEEVEN:
            i = float_round_nearest_even;
            break;
        case FPROUNDING_POSINF:
            i = float_round_up;
            break;
        case FPROUNDING_NEGINF:
            i = float_round_down;
            break;
        case FPROUNDING_ZERO:
            i = float_round_to_zero;
            break;
        }
        set_float_rounding_mode(i, &env->vfp.fp_status);
        set_float_rounding_mode(i, &env->vfp.fp_status_f16);
    }
    if (changed & FPCR_FZ16) {
        bool ftz_enabled = val & FPCR_FZ16;
        set_flush_to_zero(ftz_enabled, &env->vfp.fp_status_f16);
        set_flush_inputs_to_zero(ftz_enabled, &env->vfp.fp_status_f16);
    }
    if (changed & FPCR_FZ) {
        bool ftz_enabled = val & FPCR_FZ;
        set_flush_to_zero(ftz_enabled, &env->vfp.fp_status);
        set_flush_inputs_to_zero(ftz_enabled, &env->vfp.fp_status);
    }
    if (changed & FPCR_DN) {
        bool dnan_enabled = val & FPCR_DN;
        set_default_nan_mode(dnan_enabled, &env->vfp.fp_status);
        set_default_nan_mode(dnan_enabled, &env->vfp.fp_status_f16);
    }

    /*
     * The exception flags are ORed together when we read fpscr so we
     * only need to preserve the current state in one of our
     * float_status values.
     */
    i = vfp_exceptbits_to_host(val);
    set_float_exception_flags(i, &env->vfp.fp_status);
    set_float_exception_flags(0, &env->vfp.fp_status_f16);
    set_float_exception_flags(0, &env->vfp.standard_fp_status);
}

uint32_t HELPER(vfp_get_fpscr)(CPUARMState *env)
{
    uint32_t i, fpscr;

    fpscr = env->vfp.xregs[ARM_VFP_FPSCR]
            | (env->vfp.vec_len << 16)
            | (env->vfp.vec_stride << 20);

    fpscr |= vfp_get_fpscr_from_host(env);

    i = env->vfp.qc[0] | env->vfp.qc[1] | env->vfp.qc[2] | env->vfp.qc[3];
    fpscr |= i ? FPCR_QC : 0;

    return fpscr;
}

uint32_t vfp_get_fpscr(CPUARMState *env)
{
    return HELPER(vfp_get_fpscr)(env);
}

void HELPER(vfp_set_fpscr)(CPUARMState *env, uint32_t val)
{
    /* When ARMv8.2-FP16 is not supported, FZ16 is RES0.  */
    if (!cpu_isar_feature(any_fp16, env_archcpu(env))) {
        val &= ~FPCR_FZ16;
    }

    if (arm_feature(env, ARM_FEATURE_M)) {
        /*
         * M profile FPSCR is RES0 for the QC, STRIDE, FZ16, LEN bits
         * and also for the trapped-exception-handling bits IxE.
         */
        val &= 0xf7c0009f;
    }

    vfp_set_fpscr_to_host(env, val);

    /*
     * We don't implement trapped exception handling, so the
     * trap enable bits, IDE|IXE|UFE|OFE|DZE|IOE are all RAZ/WI (not RES0!)
     *
     * If we exclude the exception flags, IOC|DZC|OFC|UFC|IXC|IDC
     * (which are stored in fp_status), and the other RES0 bits
     * in between, then we clear all of the low 16 bits.
     */
    env->vfp.xregs[ARM_VFP_FPSCR] = val & 0xf7c80000;
    env->vfp.vec_len = (val >> 16) & 7;
    env->vfp.vec_stride = (val >> 20) & 3;

    /*
     * The bit we set within fpscr_q is arbitrary; the register as a
     * whole being zero/non-zero is what counts.
     */
    env->vfp.qc[0] = val & FPCR_QC;
    env->vfp.qc[1] = 0;
    env->vfp.qc[2] = 0;
    env->vfp.qc[3] = 0;
}

void vfp_set_fpscr(CPUARMState *env, uint32_t val)
{
    HELPER(vfp_set_fpscr)(env, val);
}

#define VFP_HELPER(name, p) HELPER(glue(glue(vfp_,name),p))

#define VFP_BINOP(name) \
float32 VFP_HELPER(name, s)(float32 a, float32 b, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return float32_ ## name(a, b, fpst); \
} \
float64 VFP_HELPER(name, d)(float64 a, float64 b, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return float64_ ## name(a, b, fpst); \
}
VFP_BINOP(add)
VFP_BINOP(sub)
VFP_BINOP(mul)
VFP_BINOP(div)
VFP_BINOP(min)
VFP_BINOP(max)
VFP_BINOP(minnum)
VFP_BINOP(maxnum)
#undef VFP_BINOP

float32 VFP_HELPER(neg, s)(float32 a)
{
    return float32_chs(a);
}

float64 VFP_HELPER(neg, d)(float64 a)
{
    return float64_chs(a);
}

float32 VFP_HELPER(abs, s)(float32 a)
{
    return float32_abs(a);
}

float64 VFP_HELPER(abs, d)(float64 a)
{
    return float64_abs(a);
}

float32 VFP_HELPER(sqrt, s)(float32 a, CPUARMState *env)
{
    return float32_sqrt(a, &env->vfp.fp_status);
}

float64 VFP_HELPER(sqrt, d)(float64 a, CPUARMState *env)
{
    return float64_sqrt(a, &env->vfp.fp_status);
}

static void softfloat_to_vfp_compare(CPUARMState *env, int cmp)
{
    uint32_t flags = 0;
    switch (cmp) {
    case float_relation_equal:
        flags = 0x6;
        break;
    case float_relation_less:
        flags = 0x8;
        break;
    case float_relation_greater:
        flags = 0x2;
        break;
    case float_relation_unordered:
        flags = 0x3;
        break;
    default:
        g_assert_not_reached();
        break;
    }
    env->vfp.xregs[ARM_VFP_FPSCR] =
        deposit32(env->vfp.xregs[ARM_VFP_FPSCR], 28, 4, flags);
}

/* XXX: check quiet/signaling case */
#define DO_VFP_cmp(p, type) \
void VFP_HELPER(cmp, p)(type a, type b, CPUARMState *env)  \
{ \
    softfloat_to_vfp_compare(env, \
        type ## _compare_quiet(a, b, &env->vfp.fp_status)); \
} \
void VFP_HELPER(cmpe, p)(type a, type b, CPUARMState *env) \
{ \
    softfloat_to_vfp_compare(env, \
        type ## _compare(a, b, &env->vfp.fp_status)); \
}
DO_VFP_cmp(s, float32)
DO_VFP_cmp(d, float64)
#undef DO_VFP_cmp

/* Integer to float and float to integer conversions */

#define CONV_ITOF(name, ftype, fsz, sign)                           \
ftype HELPER(name)(uint32_t x, void *fpstp)                         \
{                                                                   \
    float_status *fpst = fpstp;                                     \
    return sign##int32_to_##float##fsz((sign##int32_t)x, fpst);     \
}

#define CONV_FTOI(name, ftype, fsz, sign, round)                \
sign##int32_t HELPER(name)(ftype x, void *fpstp)                \
{                                                               \
    float_status *fpst = fpstp;                                 \
    if (float##fsz##_is_any_nan(x)) {                           \
        float_raise(float_flag_invalid, fpst);                  \
        return 0;                                               \
    }                                                           \
    return float##fsz##_to_##sign##int32##round(x, fpst);       \
}

#define FLOAT_CONVS(name, p, ftype, fsz, sign)            \
    CONV_ITOF(vfp_##name##to##p, ftype, fsz, sign)        \
    CONV_FTOI(vfp_to##name##p, ftype, fsz, sign, )        \
    CONV_FTOI(vfp_to##name##z##p, ftype, fsz, sign, _round_to_zero)

FLOAT_CONVS(si, h, uint32_t, 16, )
FLOAT_CONVS(si, s, float32, 32, )
FLOAT_CONVS(si, d, float64, 64, )
FLOAT_CONVS(ui, h, uint32_t, 16, u)
FLOAT_CONVS(ui, s, float32, 32, u)
FLOAT_CONVS(ui, d, float64, 64, u)

#undef CONV_ITOF
#undef CONV_FTOI
#undef FLOAT_CONVS

/* floating point conversion */
float64 VFP_HELPER(fcvtd, s)(float32 x, CPUARMState *env)
{
    return float32_to_float64(x, &env->vfp.fp_status);
}

float32 VFP_HELPER(fcvts, d)(float64 x, CPUARMState *env)
{
    return float64_to_float32(x, &env->vfp.fp_status);
}

/* VFP3 fixed point conversion.  */
#ifdef _MSC_VER
#define VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype) \
float##fsz HELPER(vfp_##name##to##p)(uint##isz##_t  x, uint32_t shift, \
                                     void *fpstp) \
{ return itype##_to_##float##fsz##_scalbn(x, 0 - shift, fpstp); }
#else
#define VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype) \
float##fsz HELPER(vfp_##name##to##p)(uint##isz##_t  x, uint32_t shift, \
                                     void *fpstp) \
{ return itype##_to_##float##fsz##_scalbn(x, -shift, fpstp); }
#endif

#define VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, ROUND, suff)   \
uint##isz##_t HELPER(vfp_to##name##p##suff)(float##fsz x, uint32_t shift, \
                                            void *fpst)                   \
{                                                                         \
    if (unlikely(float##fsz##_is_any_nan(x))) {                           \
        float_raise(float_flag_invalid, fpst);                            \
        return 0;                                                         \
    }                                                                     \
    return float##fsz##_to_##itype##_scalbn(x, ROUND, shift, fpst);       \
}

#define VFP_CONV_FIX(name, p, fsz, isz, itype)                   \
VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype)                     \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype,               \
                         float_round_to_zero, _round_to_zero)    \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype,               \
                         get_float_rounding_mode(fpst), )

#define VFP_CONV_FIX_A64(name, p, fsz, isz, itype)               \
VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype)                     \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype,               \
                         get_float_rounding_mode(fpst), )

VFP_CONV_FIX(sh, d, 64, 64, int16)
VFP_CONV_FIX(sl, d, 64, 64, int32)
VFP_CONV_FIX_A64(sq, d, 64, 64, int64)
VFP_CONV_FIX(uh, d, 64, 64, uint16)
VFP_CONV_FIX(ul, d, 64, 64, uint32)
VFP_CONV_FIX_A64(uq, d, 64, 64, uint64)
VFP_CONV_FIX(sh, s, 32, 32, int16)
VFP_CONV_FIX(sl, s, 32, 32, int32)
VFP_CONV_FIX_A64(sq, s, 32, 64, int64)
VFP_CONV_FIX(uh, s, 32, 32, uint16)
VFP_CONV_FIX(ul, s, 32, 32, uint32)
VFP_CONV_FIX_A64(uq, s, 32, 64, uint64)

#undef VFP_CONV_FIX
#undef VFP_CONV_FIX_FLOAT
#undef VFP_CONV_FLOAT_FIX_ROUND
#undef VFP_CONV_FIX_A64

uint32_t HELPER(vfp_sltoh)(uint32_t x, uint32_t shift, void *fpst)
{
#ifdef _MSC_VER
    return int32_to_float16_scalbn(x, 0 - shift, fpst);
#else
    return int32_to_float16_scalbn(x, -shift, fpst);
#endif
}

uint32_t HELPER(vfp_ultoh)(uint32_t x, uint32_t shift, void *fpst)
{
#ifdef _MSC_VER
    return uint32_to_float16_scalbn(x, 0 - shift, fpst);
#else
    return uint32_to_float16_scalbn(x, -shift, fpst);
#endif
}

uint32_t HELPER(vfp_sqtoh)(uint64_t x, uint32_t shift, void *fpst)
{
#ifdef _MSC_VER
    return int64_to_float16_scalbn(x, 0 - shift, fpst);
#else
    return int64_to_float16_scalbn(x, -shift, fpst);
#endif
}

uint32_t HELPER(vfp_uqtoh)(uint64_t x, uint32_t shift, void *fpst)
{
#ifdef _MSC_VER
    return uint64_to_float16_scalbn(x, 0 - shift, fpst);
#else
    return uint64_to_float16_scalbn(x, -shift, fpst);
#endif
}

uint32_t HELPER(vfp_toshh)(uint32_t x, uint32_t shift, void *fpst)
{
    if (unlikely(float16_is_any_nan(x))) {
        float_raise(float_flag_invalid, fpst);
        return 0;
    }
    return float16_to_int16_scalbn(x, get_float_rounding_mode(fpst),
                                   shift, fpst);
}

uint32_t HELPER(vfp_touhh)(uint32_t x, uint32_t shift, void *fpst)
{
    if (unlikely(float16_is_any_nan(x))) {
        float_raise(float_flag_invalid, fpst);
        return 0;
    }
    return float16_to_uint16_scalbn(x, get_float_rounding_mode(fpst),
                                    shift, fpst);
}

uint32_t HELPER(vfp_toslh)(uint32_t x, uint32_t shift, void *fpst)
{
    if (unlikely(float16_is_any_nan(x))) {
        float_raise(float_flag_invalid, fpst);
        return 0;
    }
    return float16_to_int32_scalbn(x, get_float_rounding_mode(fpst),
                                   shift, fpst);
}

uint32_t HELPER(vfp_toulh)(uint32_t x, uint32_t shift, void *fpst)
{
    if (unlikely(float16_is_any_nan(x))) {
        float_raise(float_flag_invalid, fpst);
        return 0;
    }
    return float16_to_uint32_scalbn(x, get_float_rounding_mode(fpst),
                                    shift, fpst);
}

uint64_t HELPER(vfp_tosqh)(uint32_t x, uint32_t shift, void *fpst)
{
    if (unlikely(float16_is_any_nan(x))) {
        float_raise(float_flag_invalid, fpst);
        return 0;
    }
    return float16_to_int64_scalbn(x, get_float_rounding_mode(fpst),
                                   shift, fpst);
}

uint64_t HELPER(vfp_touqh)(uint32_t x, uint32_t shift, void *fpst)
{
    if (unlikely(float16_is_any_nan(x))) {
        float_raise(float_flag_invalid, fpst);
        return 0;
    }
    return float16_to_uint64_scalbn(x, get_float_rounding_mode(fpst),
                                    shift, fpst);
}

/* Set the current fp rounding mode and return the old one.
 * The argument is a softfloat float_round_ value.
 */
uint32_t HELPER(set_rmode)(uint32_t rmode, void *fpstp)
{
    float_status *fp_status = fpstp;

    uint32_t prev_rmode = get_float_rounding_mode(fp_status);
    set_float_rounding_mode(rmode, fp_status);

    return prev_rmode;
}

/* Set the current fp rounding mode in the standard fp status and return
 * the old one. This is for NEON instructions that need to change the
 * rounding mode but wish to use the standard FPSCR values for everything
 * else. Always set the rounding mode back to the correct value after
 * modifying it.
 * The argument is a softfloat float_round_ value.
 */
uint32_t HELPER(set_neon_rmode)(uint32_t rmode, CPUARMState *env)
{
    float_status *fp_status = &env->vfp.standard_fp_status;

    uint32_t prev_rmode = get_float_rounding_mode(fp_status);
    set_float_rounding_mode(rmode, fp_status);

    return prev_rmode;
}

/* Half precision conversions.  */
float32 HELPER(vfp_fcvt_f16_to_f32)(uint32_t a, void *fpstp, uint32_t ahp_mode)
{
    /* Squash FZ16 to 0 for the duration of conversion.  In this case,
     * it would affect flushing input denormals.
     */
    float_status *fpst = fpstp;
    flag save = get_flush_inputs_to_zero(fpst);
    set_flush_inputs_to_zero(false, fpst);
    float32 r = float16_to_float32(a, !ahp_mode, fpst);
    set_flush_inputs_to_zero(save, fpst);
    return r;
}

uint32_t HELPER(vfp_fcvt_f32_to_f16)(float32 a, void *fpstp, uint32_t ahp_mode)
{
    /* Squash FZ16 to 0 for the duration of conversion.  In this case,
     * it would affect flushing output denormals.
     */
    float_status *fpst = fpstp;
    flag save = get_flush_to_zero(fpst);
    set_flush_to_zero(false, fpst);
    float16 r = float32_to_float16(a, !ahp_mode, fpst);
    set_flush_to_zero(save, fpst);
    return r;
}

float64 HELPER(vfp_fcvt_f16_to_f64)(uint32_t a, void *fpstp, uint32_t ahp_mode)
{
    /* Squash FZ16 to 0 for the duration of conversion.  In this case,
     * it would affect flushing input denormals.
     */
    float_status *fpst = fpstp;
    flag save = get_flush_inputs_to_zero(fpst);
    set_flush_inputs_to_zero(false, fpst);
    float64 r = float16_to_float64(a, !ahp_mode, fpst);
    set_flush_inputs_to_zero(save, fpst);
    return r;
}

uint32_t HELPER(vfp_fcvt_f64_to_f16)(float64 a, void *fpstp, uint32_t ahp_mode)
{
    /* Squash FZ16 to 0 for the duration of conversion.  In this case,
     * it would affect flushing output denormals.
     */
    float_status *fpst = fpstp;
    flag save = get_flush_to_zero(fpst);
    set_flush_to_zero(false, fpst);
    float16 r = float64_to_float16(a, !ahp_mode, fpst);
    set_flush_to_zero(save, fpst);
    return r;
}

#define float32_two make_float32(0x40000000)
#define float32_three make_float32(0x40400000)
#define float32_one_point_five make_float32(0x3fc00000)

float32 HELPER(recps_f32)(float32 a, float32 b, CPUARMState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    if ((float32_is_infinity(a) && float32_is_zero_or_denormal(b)) ||
        (float32_is_infinity(b) && float32_is_zero_or_denormal(a))) {
        if (!(float32_is_zero(a) || float32_is_zero(b))) {
            float_raise(float_flag_input_denormal, s);
        }
        return float32_two;
    }
    return float32_sub(float32_two, float32_mul(a, b, s), s);
}

float32 HELPER(rsqrts_f32)(float32 a, float32 b, CPUARMState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    float32 product;
    if ((float32_is_infinity(a) && float32_is_zero_or_denormal(b)) ||
        (float32_is_infinity(b) && float32_is_zero_or_denormal(a))) {
        if (!(float32_is_zero(a) || float32_is_zero(b))) {
            float_raise(float_flag_input_denormal, s);
        }
        return float32_one_point_five;
    }
    product = float32_mul(a, b, s);
    return float32_div(float32_sub(float32_three, product, s), float32_two, s);
}

/* NEON helpers.  */

/* Constants 256 and 512 are used in some helpers; we avoid relying on
 * int->float conversions at run-time.  */
#define float64_256 make_float64(0x4070000000000000LL)
#define float64_512 make_float64(0x4080000000000000LL)
#define float16_maxnorm make_float16(0x7bff)
#define float32_maxnorm make_float32(0x7f7fffff)
#define float64_maxnorm make_float64(0x7fefffffffffffffLL)

/* Reciprocal functions
 *
 * The algorithm that must be used to calculate the estimate
 * is specified by the ARM ARM, see FPRecipEstimate()/RecipEstimate
 */

/* See RecipEstimate()
 *
 * input is a 9 bit fixed point number
 * input range 256 .. 511 for a number from 0.5 <= x < 1.0.
 * result range 256 .. 511 for a number from 1.0 to 511/256.
 */

static int recip_estimate(int input)
{
    int a, b, r;
    assert(256 <= input && input < 512);
    a = (input * 2) + 1;
    b = (1 << 19) / a;
    r = (b + 1) >> 1;
    assert(256 <= r && r < 512);
    return r;
}

/*
 * Common wrapper to call recip_estimate
 *
 * The parameters are exponent and 64 bit fraction (without implicit
 * bit) where the binary point is nominally at bit 52. Returns a
 * float64 which can then be rounded to the appropriate size by the
 * callee.
 */

static uint64_t call_recip_estimate(int *exp, int exp_off, uint64_t frac)
{
    uint32_t scaled, estimate;
    uint64_t result_frac;
    int result_exp;

    /* Handle sub-normals */
    if (*exp == 0) {
        if (extract64(frac, 51, 1) == 0) {
            *exp = -1;
            frac <<= 2;
        } else {
            frac <<= 1;
        }
    }

    /* scaled = UInt('1':fraction<51:44>) */
    scaled = deposit32(1 << 8, 0, 8, extract64(frac, 44, 8));
    estimate = recip_estimate(scaled);

    result_exp = exp_off - *exp;
    result_frac = deposit64(0, 44, 8, estimate);
    if (result_exp == 0) {
        result_frac = deposit64(result_frac >> 1, 51, 1, 1);
    } else if (result_exp == -1) {
        result_frac = deposit64(result_frac >> 2, 50, 2, 1);
        result_exp = 0;
    }

    *exp = result_exp;

    return result_frac;
}

static bool round_to_inf(float_status *fpst, bool sign_bit)
{
    switch (fpst->float_rounding_mode) {
    case float_round_nearest_even: /* Round to Nearest */
        return true;
    case float_round_up: /* Round to +Inf */
        return !sign_bit;
    case float_round_down: /* Round to -Inf */
        return sign_bit;
    case float_round_to_zero: /* Round to Zero */
        return false;
    }

    g_assert_not_reached();
    // never reach here
    return false;
}

uint32_t HELPER(recpe_f16)(uint32_t input, void *fpstp)
{
    float_status *fpst = fpstp;
    float16 f16 = float16_squash_input_denormal(input, fpst);
    uint32_t f16_val = float16_val(f16);
    uint32_t f16_sign = float16_is_neg(f16);
    int f16_exp = extract32(f16_val, 10, 5);
    uint32_t f16_frac = extract32(f16_val, 0, 10);
    uint64_t f64_frac;

    if (float16_is_any_nan(f16)) {
        float16 nan = f16;
        if (float16_is_signaling_nan(f16, fpst)) {
            float_raise(float_flag_invalid, fpst);
            nan = float16_silence_nan(f16, fpst);
        }
        if (fpst->default_nan_mode) {
            nan =  float16_default_nan(fpst);
        }
        return nan;
    } else if (float16_is_infinity(f16)) {
        return float16_set_sign(float16_zero, float16_is_neg(f16));
    } else if (float16_is_zero(f16)) {
        float_raise(float_flag_divbyzero, fpst);
        return float16_set_sign(float16_infinity, float16_is_neg(f16));
    } else if (float16_abs(f16) < (1 << 8)) {
        /* Abs(value) < 2.0^-16 */
        float_raise(float_flag_overflow | float_flag_inexact, fpst);
        if (round_to_inf(fpst, f16_sign)) {
            return float16_set_sign(float16_infinity, f16_sign);
        } else {
            return float16_set_sign(float16_maxnorm, f16_sign);
        }
    } else if (f16_exp >= 29 && fpst->flush_to_zero) {
        float_raise(float_flag_underflow, fpst);
        return float16_set_sign(float16_zero, float16_is_neg(f16));
    }

    f64_frac = call_recip_estimate(&f16_exp, 29,
                                   ((uint64_t) f16_frac) << (52 - 10));

    /* result = sign : result_exp<4:0> : fraction<51:42> */
    f16_val = deposit32(0, 15, 1, f16_sign);
    f16_val = deposit32(f16_val, 10, 5, f16_exp);
    f16_val = deposit32(f16_val, 0, 10, extract64(f64_frac, 52 - 10, 10));
    return make_float16(f16_val);
}

float32 HELPER(recpe_f32)(float32 input, void *fpstp)
{
    float_status *fpst = fpstp;
    float32 f32 = float32_squash_input_denormal(input, fpst);
    uint32_t f32_val = float32_val(f32);
    bool f32_sign = float32_is_neg(f32);
    int f32_exp = extract32(f32_val, 23, 8);
    uint32_t f32_frac = extract32(f32_val, 0, 23);
    uint64_t f64_frac;

    if (float32_is_any_nan(f32)) {
        float32 nan = f32;
        if (float32_is_signaling_nan(f32, fpst)) {
            float_raise(float_flag_invalid, fpst);
            nan = float32_silence_nan(f32, fpst);
        }
        if (fpst->default_nan_mode) {
            nan =  float32_default_nan(fpst);
        }
        return nan;
    } else if (float32_is_infinity(f32)) {
        return float32_set_sign(float32_zero, float32_is_neg(f32));
    } else if (float32_is_zero(f32)) {
        float_raise(float_flag_divbyzero, fpst);
        return float32_set_sign(float32_infinity, float32_is_neg(f32));
    } else if (float32_abs(f32) < (1ULL << 21)) {
        /* Abs(value) < 2.0^-128 */
        float_raise(float_flag_overflow | float_flag_inexact, fpst);
        if (round_to_inf(fpst, f32_sign)) {
            return float32_set_sign(float32_infinity, f32_sign);
        } else {
            return float32_set_sign(float32_maxnorm, f32_sign);
        }
    } else if (f32_exp >= 253 && fpst->flush_to_zero) {
        float_raise(float_flag_underflow, fpst);
        return float32_set_sign(float32_zero, float32_is_neg(f32));
    }

    f64_frac = call_recip_estimate(&f32_exp, 253,
                                   ((uint64_t) f32_frac) << (52 - 23));

    /* result = sign : result_exp<7:0> : fraction<51:29> */
    f32_val = deposit32(0, 31, 1, f32_sign);
    f32_val = deposit32(f32_val, 23, 8, f32_exp);
    f32_val = deposit32(f32_val, 0, 23, extract64(f64_frac, 52 - 23, 23));
    return make_float32(f32_val);
}

float64 HELPER(recpe_f64)(float64 input, void *fpstp)
{
    float_status *fpst = fpstp;
    float64 f64 = float64_squash_input_denormal(input, fpst);
    uint64_t f64_val = float64_val(f64);
    bool f64_sign = float64_is_neg(f64);
    int f64_exp = extract64(f64_val, 52, 11);
    uint64_t f64_frac = extract64(f64_val, 0, 52);

    /* Deal with any special cases */
    if (float64_is_any_nan(f64)) {
        float64 nan = f64;
        if (float64_is_signaling_nan(f64, fpst)) {
            float_raise(float_flag_invalid, fpst);
            nan = float64_silence_nan(f64, fpst);
        }
        if (fpst->default_nan_mode) {
            nan =  float64_default_nan(fpst);
        }
        return nan;
    } else if (float64_is_infinity(f64)) {
        return float64_set_sign(float64_zero, float64_is_neg(f64));
    } else if (float64_is_zero(f64)) {
        float_raise(float_flag_divbyzero, fpst);
        return float64_set_sign(float64_infinity, float64_is_neg(f64));
    } else if ((f64_val & ~(1ULL << 63)) < (1ULL << 50)) {
        /* Abs(value) < 2.0^-1024 */
        float_raise(float_flag_overflow | float_flag_inexact, fpst);
        if (round_to_inf(fpst, f64_sign)) {
            return float64_set_sign(float64_infinity, f64_sign);
        } else {
            return float64_set_sign(float64_maxnorm, f64_sign);
        }
    } else if (f64_exp >= 2045 && fpst->flush_to_zero) {
        float_raise(float_flag_underflow, fpst);
        return float64_set_sign(float64_zero, float64_is_neg(f64));
    }

    f64_frac = call_recip_estimate(&f64_exp, 2045, f64_frac);

    /* result = sign : result_exp<10:0> : fraction<51:0>; */
    f64_val = deposit64(0, 63, 1, f64_sign);
    f64_val = deposit64(f64_val, 52, 11, f64_exp);
    f64_val = deposit64(f64_val, 0, 52, f64_frac);
    return make_float64(f64_val);
}

/* The algorithm that must be used to calculate the estimate
 * is specified by the ARM ARM.
 */

static int do_recip_sqrt_estimate(int a)
{
    int b, estimate;

    assert(128 <= a && a < 512);
    if (a < 256) {
        a = a * 2 + 1;
    } else {
        a = (a >> 1) << 1;
        a = (a + 1) * 2;
    }
    b = 512;
    while (a * (b + 1) * (b + 1) < (1 << 28)) {
        b += 1;
    }
    estimate = (b + 1) / 2;
    assert(256 <= estimate && estimate < 512);

    return estimate;
}


static uint64_t recip_sqrt_estimate(int *exp , int exp_off, uint64_t frac)
{
    int estimate;
    uint32_t scaled;

    if (*exp == 0) {
        while (extract64(frac, 51, 1) == 0) {
            frac = frac << 1;
            *exp -= 1;
        }
        frac = extract64(frac, 0, 51) << 1;
    }

    if (*exp & 1) {
        /* scaled = UInt('01':fraction<51:45>) */
        scaled = deposit32(1 << 7, 0, 7, extract64(frac, 45, 7));
    } else {
        /* scaled = UInt('1':fraction<51:44>) */
        scaled = deposit32(1 << 8, 0, 8, extract64(frac, 44, 8));
    }
    estimate = do_recip_sqrt_estimate(scaled);

    *exp = (exp_off - *exp) / 2;
    return extract64(estimate, 0, 8) << 44;
}

uint32_t HELPER(rsqrte_f16)(uint32_t input, void *fpstp)
{
    float_status *s = fpstp;
    float16 f16 = float16_squash_input_denormal(input, s);
    uint16_t val = float16_val(f16);
    bool f16_sign = float16_is_neg(f16);
    int f16_exp = extract32(val, 10, 5);
    uint16_t f16_frac = extract32(val, 0, 10);
    uint64_t f64_frac;

    if (float16_is_any_nan(f16)) {
        float16 nan = f16;
        if (float16_is_signaling_nan(f16, s)) {
            float_raise(float_flag_invalid, s);
            nan = float16_silence_nan(f16, s);
        }
        if (s->default_nan_mode) {
            nan =  float16_default_nan(s);
        }
        return nan;
    } else if (float16_is_zero(f16)) {
        float_raise(float_flag_divbyzero, s);
        return float16_set_sign(float16_infinity, f16_sign);
    } else if (f16_sign) {
        float_raise(float_flag_invalid, s);
        return float16_default_nan(s);
    } else if (float16_is_infinity(f16)) {
        return float16_zero;
    }

    /* Scale and normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */

    f64_frac = ((uint64_t) f16_frac) << (52 - 10);

    f64_frac = recip_sqrt_estimate(&f16_exp, 44, f64_frac);

    /* result = sign : result_exp<4:0> : estimate<7:0> : Zeros(2) */
    val = deposit32(0, 15, 1, f16_sign);
    val = deposit32(val, 10, 5, f16_exp);
    val = deposit32(val, 2, 8, extract64(f64_frac, 52 - 8, 8));
    return make_float16(val);
}

float32 HELPER(rsqrte_f32)(float32 input, void *fpstp)
{
    float_status *s = fpstp;
    float32 f32 = float32_squash_input_denormal(input, s);
    uint32_t val = float32_val(f32);
    uint32_t f32_sign = float32_is_neg(f32);
    int f32_exp = extract32(val, 23, 8);
    uint32_t f32_frac = extract32(val, 0, 23);
    uint64_t f64_frac;

    if (float32_is_any_nan(f32)) {
        float32 nan = f32;
        if (float32_is_signaling_nan(f32, s)) {
            float_raise(float_flag_invalid, s);
            nan = float32_silence_nan(f32, s);
        }
        if (s->default_nan_mode) {
            nan =  float32_default_nan(s);
        }
        return nan;
    } else if (float32_is_zero(f32)) {
        float_raise(float_flag_divbyzero, s);
        return float32_set_sign(float32_infinity, float32_is_neg(f32));
    } else if (float32_is_neg(f32)) {
        float_raise(float_flag_invalid, s);
        return float32_default_nan(s);
    } else if (float32_is_infinity(f32)) {
        return float32_zero;
    }

    /* Scale and normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */

    f64_frac = ((uint64_t) f32_frac) << 29;

    f64_frac = recip_sqrt_estimate(&f32_exp, 380, f64_frac);

    /* result = sign : result_exp<4:0> : estimate<7:0> : Zeros(15) */
    val = deposit32(0, 31, 1, f32_sign);
    val = deposit32(val, 23, 8, f32_exp);
    val = deposit32(val, 15, 8, extract64(f64_frac, 52 - 8, 8));
    return make_float32(val);
}

float64 HELPER(rsqrte_f64)(float64 input, void *fpstp)
{
    float_status *s = fpstp;
    float64 f64 = float64_squash_input_denormal(input, s);
    uint64_t val = float64_val(f64);
    bool f64_sign = float64_is_neg(f64);
    int f64_exp = extract64(val, 52, 11);
    uint64_t f64_frac = extract64(val, 0, 52);

    if (float64_is_any_nan(f64)) {
        float64 nan = f64;
        if (float64_is_signaling_nan(f64, s)) {
            float_raise(float_flag_invalid, s);
            nan = float64_silence_nan(f64, s);
        }
        if (s->default_nan_mode) {
            nan =  float64_default_nan(s);
        }
        return nan;
    } else if (float64_is_zero(f64)) {
        float_raise(float_flag_divbyzero, s);
        return float64_set_sign(float64_infinity, float64_is_neg(f64));
    } else if (float64_is_neg(f64)) {
        float_raise(float_flag_invalid, s);
        return float64_default_nan(s);
    } else if (float64_is_infinity(f64)) {
        return float64_zero;
    }

    f64_frac = recip_sqrt_estimate(&f64_exp, 3068, f64_frac);

    /* result = sign : result_exp<4:0> : estimate<7:0> : Zeros(44) */
    val = deposit64(0, 61, 1, f64_sign);
    val = deposit64(val, 52, 11, f64_exp);
    val = deposit64(val, 44, 8, extract64(f64_frac, 52 - 8, 8));
    return make_float64(val);
}

uint32_t HELPER(recpe_u32)(uint32_t a, void *fpstp)
{
    /* float_status *s = fpstp; */
    int input, estimate;

    if ((a & 0x80000000) == 0) {
        return 0xffffffff;
    }

    input = extract32(a, 23, 9);
    estimate = recip_estimate(input);

    return deposit32(0, (32 - 9), 9, estimate);
}

uint32_t HELPER(rsqrte_u32)(uint32_t a, void *fpstp)
{
    int estimate;

    if ((a & 0xc0000000) == 0) {
        return 0xffffffff;
    }

    estimate = do_recip_sqrt_estimate(extract32(a, 23, 9));

    return deposit32(0, 23, 9, estimate);
}

/* VFPv4 fused multiply-accumulate */
float32 VFP_HELPER(muladd, s)(float32 a, float32 b, float32 c, void *fpstp)
{
    float_status *fpst = fpstp;
    return float32_muladd(a, b, c, 0, fpst);
}

float64 VFP_HELPER(muladd, d)(float64 a, float64 b, float64 c, void *fpstp)
{
    float_status *fpst = fpstp;
    return float64_muladd(a, b, c, 0, fpst);
}

/* ARMv8 round to integral */
float32 HELPER(rints_exact)(float32 x, void *fp_status)
{
    return float32_round_to_int(x, fp_status);
}

float64 HELPER(rintd_exact)(float64 x, void *fp_status)
{
    return float64_round_to_int(x, fp_status);
}

float32 HELPER(rints)(float32 x, void *fp_status)
{
    int old_flags = get_float_exception_flags(fp_status), new_flags;
    float32 ret;

    ret = float32_round_to_int(x, fp_status);

    /* Suppress any inexact exceptions the conversion produced */
    if (!(old_flags & float_flag_inexact)) {
        new_flags = get_float_exception_flags(fp_status);
        set_float_exception_flags(new_flags & ~float_flag_inexact, fp_status);
    }

    return ret;
}

float64 HELPER(rintd)(float64 x, void *fp_status)
{
    int old_flags = get_float_exception_flags(fp_status), new_flags;
    float64 ret;

    ret = float64_round_to_int(x, fp_status);

    new_flags = get_float_exception_flags(fp_status);

    /* Suppress any inexact exceptions the conversion produced */
    if (!(old_flags & float_flag_inexact)) {
        new_flags = get_float_exception_flags(fp_status);
        set_float_exception_flags(new_flags & ~float_flag_inexact, fp_status);
    }

    return ret;
}

/* Convert ARM rounding mode to softfloat */
int arm_rmode_to_sf(int rmode)
{
    switch (rmode) {
    case FPROUNDING_TIEAWAY:
        rmode = float_round_ties_away;
        break;
    case FPROUNDING_ODD:
        /* FIXME: add support for TIEAWAY and ODD */
        qemu_log_mask(LOG_UNIMP, "arm: unimplemented rounding mode: %d\n",
                      rmode);
        /* fall through for now */
    case FPROUNDING_TIEEVEN:
    default:
        rmode = float_round_nearest_even;
        break;
    case FPROUNDING_POSINF:
        rmode = float_round_up;
        break;
    case FPROUNDING_NEGINF:
        rmode = float_round_down;
        break;
    case FPROUNDING_ZERO:
        rmode = float_round_to_zero;
        break;
    }
    return rmode;
}

/*
 * Implement float64 to int32_t conversion without saturation;
 * the result is supplied modulo 2^32.
 */
uint64_t HELPER(fjcvtzs)(float64 value, void *vstatus)
{
    float_status *status = vstatus;
    uint32_t exp, sign;
    uint64_t frac;
    uint32_t inexact = 1; /* !Z */

    sign = extract64(value, 63, 1);
    exp = extract64(value, 52, 11);
    frac = extract64(value, 0, 52);

    if (exp == 0) {
        /* While not inexact for IEEE FP, -0.0 is inexact for JavaScript.  */
        inexact = sign;
        if (frac != 0) {
            if (status->flush_inputs_to_zero) {
                float_raise(float_flag_input_denormal, status);
            } else {
                float_raise(float_flag_inexact, status);
                inexact = 1;
            }
        }
        frac = 0;
    } else if (exp == 0x7ff) {
        /* This operation raises Invalid for both NaN and overflow (Inf).  */
        float_raise(float_flag_invalid, status);
        frac = 0;
    } else {
        int true_exp = exp - 1023;
        int shift = true_exp - 52;

        /* Restore implicit bit.  */
        frac |= 1ull << 52;

        /* Shift the fraction into place.  */
        if (shift >= 0) {
            /* The number is so large we must shift the fraction left.  */
            if (shift >= 64) {
                /* The fraction is shifted out entirely.  */
                frac = 0;
            } else {
                frac <<= shift;
            }
        } else if (shift > -64) {
            /* Normal case -- shift right and notice if bits shift out.  */
            inexact = (frac << (64 + shift)) != 0;
            frac >>= -shift;
        } else {
            /* The fraction is shifted out entirely.  */
            frac = 0;
        }

        /* Notice overflow or inexact exceptions.  */
        if (true_exp > 31 || frac > (sign ? 0x80000000ull : 0x7fffffff)) {
            /* Overflow, for which this operation raises invalid.  */
            float_raise(float_flag_invalid, status);
            inexact = 1;
        } else if (inexact) {
            float_raise(float_flag_inexact, status);
        }

        /* Honor the sign.  */
        if (sign) {
#ifdef _MSC_VER
            frac = 0 - frac;
#else
            frac = -frac;
#endif
        }
    }

    /* Pack the result and the env->ZF representation of Z together.  */
    return deposit64(frac, 32, 32, inexact);
}

uint32_t HELPER(vjcvt)(float64 value, CPUARMState *env)
{
    uint64_t pair = HELPER(fjcvtzs)(value, &env->vfp.fp_status);
    uint32_t result = pair;
    uint32_t z = (pair >> 32) == 0;

    /* Store Z, clear NCV, in FPSCR.NZCV.  */
    env->vfp.xregs[ARM_VFP_FPSCR]
        = (env->vfp.xregs[ARM_VFP_FPSCR] & ~CPSR_NZCV) | (z * CPSR_Z);

    return result;
}

/* Round a float32 to an integer that fits in int32_t or int64_t.  */
static float32 frint_s(float32 f, float_status *fpst, int intsize)
{
    int old_flags = get_float_exception_flags(fpst);
    uint32_t exp = extract32(f, 23, 8);

    if (unlikely(exp == 0xff)) {
        /* NaN or Inf.  */
        goto overflow;
    }

    /* Round and re-extract the exponent.  */
    f = float32_round_to_int(f, fpst);
    exp = extract32(f, 23, 8);

    /* Validate the range of the result.  */
    if (exp < 126 + intsize) {
        /* abs(F) <= INT{N}_MAX */
        return f;
    }
    if (exp == 126 + intsize) {
        uint32_t sign = extract32(f, 31, 1);
        uint32_t frac = extract32(f, 0, 23);
        if (sign && frac == 0) {
            /* F == INT{N}_MIN */
            return f;
        }
    }

 overflow:
    /*
     * Raise Invalid and return INT{N}_MIN as a float.  Revert any
     * inexact exception float32_round_to_int may have raised.
     */
    set_float_exception_flags(old_flags | float_flag_invalid, fpst);
    return (0x100u + 126u + intsize) << 23;
}

float32 HELPER(frint32_s)(float32 f, void *fpst)
{
    return frint_s(f, fpst, 32);
}

float32 HELPER(frint64_s)(float32 f, void *fpst)
{
    return frint_s(f, fpst, 64);
}

/* Round a float64 to an integer that fits in int32_t or int64_t.  */
static float64 frint_d(float64 f, float_status *fpst, int intsize)
{
    int old_flags = get_float_exception_flags(fpst);
    uint32_t exp = extract64(f, 52, 11);

    if (unlikely(exp == 0x7ff)) {
        /* NaN or Inf.  */
        goto overflow;
    }

    /* Round and re-extract the exponent.  */
    f = float64_round_to_int(f, fpst);
    exp = extract64(f, 52, 11);

    /* Validate the range of the result.  */
    if (exp < 1022 + intsize) {
        /* abs(F) <= INT{N}_MAX */
        return f;
    }
    if (exp == 1022 + intsize) {
        uint64_t sign = extract64(f, 63, 1);
        uint64_t frac = extract64(f, 0, 52);
        if (sign && frac == 0) {
            /* F == INT{N}_MIN */
            return f;
        }
    }

 overflow:
    /*
     * Raise Invalid and return INT{N}_MIN as a float.  Revert any
     * inexact exception float64_round_to_int may have raised.
     */
    set_float_exception_flags(old_flags | float_flag_invalid, fpst);
    return (uint64_t)(0x800 + 1022 + intsize) << 52;
}

float64 HELPER(frint32_d)(float64 f, void *fpst)
{
    return frint_d(f, fpst, 32);
}

float64 HELPER(frint64_d)(float64 f, void *fpst)
{
    return frint_d(f, fpst, 64);
}

void HELPER(check_hcr_el2_trap)(CPUARMState *env, uint32_t rt, uint32_t reg)
{
    uint32_t syndrome;

    switch (reg) {
    case ARM_VFP_MVFR0:
    case ARM_VFP_MVFR1:
    case ARM_VFP_MVFR2:
        if (!(arm_hcr_el2_eff(env) & HCR_TID3)) {
            return;
        }
        break;
    case ARM_VFP_FPSID:
        if (!(arm_hcr_el2_eff(env) & HCR_TID0)) {
            return;
        }
        break;
    default:
        g_assert_not_reached();
        break;
    }

    syndrome = ((EC_FPIDTRAP << ARM_EL_EC_SHIFT)
                | ARM_EL_IL
                | (1 << 24) | (0xe << 20) | (7 << 14)
                | (reg << 10) | (rt << 5) | 1);

    raise_exception(env, EXCP_HYP_TRAP, syndrome, 2);
}
