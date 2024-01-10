/*
 * RH850 FPU Emulation Helpers for QEMU.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include <stdlib.h>
#include "cpu.h"
#include "qemu/host-utils.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"

target_ulong cpu_rh850_get_fflags(CPURH850State *env)
{
    int soft = get_float_exception_flags(&env->fp_status);
    target_ulong hard = 0;

    hard |= (soft & float_flag_inexact) ? FPEXC_NX : 0;
    hard |= (soft & float_flag_underflow) ? FPEXC_UF : 0;
    hard |= (soft & float_flag_overflow) ? FPEXC_OF : 0;
    hard |= (soft & float_flag_divbyzero) ? FPEXC_DZ : 0;
    hard |= (soft & float_flag_invalid) ? FPEXC_NV : 0;

    return hard;
}

void cpu_rh850_set_fflags(CPURH850State *env, target_ulong hard)
{
    int soft = 0;

    soft |= (hard & FPEXC_NX) ? float_flag_inexact : 0;
    soft |= (hard & FPEXC_UF) ? float_flag_underflow : 0;
    soft |= (hard & FPEXC_OF) ? float_flag_overflow : 0;
    soft |= (hard & FPEXC_DZ) ? float_flag_divbyzero : 0;
    soft |= (hard & FPEXC_NV) ? float_flag_invalid : 0;

    set_float_exception_flags(soft, &env->fp_status);
}

void helper_set_rounding_mode(CPURH850State *env, uint32_t rm)
{
    int softrm;

    if (rm == 7) {
        rm = 0; //env->frm;
    }
    switch (rm) {
    case 0:
        softrm = float_round_nearest_even;
        break;
    case 1:
        softrm = float_round_to_zero;
        break;
    case 2:
        softrm = float_round_down;
        break;
    case 3:
        softrm = float_round_up;
        break;
    case 4:
        softrm = float_round_ties_away;
        break;
    default:
        qemu_log_mask(CPU_LOG_INT, "%s\n", __func__);
        do_raise_exception_err(env, RH850_EXCP_ILLEGAL_INST, GETPC());
    }

    set_float_rounding_mode(softrm, &env->fp_status);
}

/* Propagate softfloat flags into FPSR. */
void helper_f_sync_fflags(CPURH850State *env)
{
    target_ulong flags;

    /* Retrieve softfloat flags. */
    flags = cpu_rh850_get_fflags(env);

    /* Handle inexact flag. */
    if (flags & FPEXC_NX)
    {
        if (env->fpsr & (1 << 5))
        {
            /* Inexact exception allowed, set cause bit. */
            env->fpsr |= (1 << 10);
        }
        else
        {
            /* Set preservation bit. */
            flags |= 1 << 0;
        }
    }

    /* Handle underflow flag. */
    if (flags & FPEXC_UF)
    {
        if (env->fpsr & (1 << 6))
        {
            /* Underflow exception allowed, set cause bit. */
            env->fpsr |= (1 << 11);
        }
        else
        {
            /* Set preservation bit. */
            env->fpsr |= 1 << 1;
        }
    }

    /* Handle overflow flag. */
    if (flags & FPEXC_OF)
    {
        if (env->fpsr & (1 << 7))
        {
            /* Overflow exception allowed, set cause bit. */
            env->fpsr |= (1 << 12);
        }
        else
        {
            /* Set preservation bit. */
            env->fpsr |= 1 << 2;
        }
    }

    /* Handle div-by-zero flag. */
    if (flags & FPEXC_DZ)
    {
        if (env->fpsr & (1 << 8))
        {
            /* Div-by-zero exception allowed, set cause bit. */
            env->fpsr |= (1 << 13);
        }
        else
        {
            /* Set preservation bit. */
            env->fpsr |= 1 << 3;
        }
    }

    /* Handle invalid flag. */
    if (flags & FPEXC_NV)
    {
        if (env->fpsr & (1 << 9))
        {
            /* Div-by-zero exception allowed, set cause bit. */
            env->fpsr |= (1 << 14);
        }
        else
        {
            /* Set preservation bit. */
            env->fpsr |= 1 << 4;
        }
    }
}

/**
 * FPU flags checks
 **/

uint32_t HELPER(f32_is_normal)(CPURH850State *env, uint32_t frs1)
{
    return (uint32_t)float32_is_normal(frs1);
}

uint32_t HELPER(f32_is_zero_or_normal)(CPURH850State *env, uint32_t frs1)
{
    return (uint32_t)float32_is_zero_or_normal(frs1);
}

uint32_t HELPER(f32_is_infinity)(CPURH850State *env, uint32_t frs1)
{
    return (uint32_t)float32_is_infinity(frs1);
}



uint64_t helper_fmadd_s(CPURH850State *env, uint64_t frs1, uint64_t frs2,
                        uint64_t frs3)
{
    return float32_muladd(frs1, frs2, frs3, 0, &env->fp_status);
}

uint64_t helper_fmadd_d(CPURH850State *env, uint64_t frs1, uint64_t frs2,
                        uint64_t frs3)
{
    return float64_muladd(frs1, frs2, frs3, 0, &env->fp_status);
}

uint64_t helper_fmsub_s(CPURH850State *env, uint64_t frs1, uint64_t frs2,
                        uint64_t frs3)
{
    return float32_muladd(frs1, frs2, frs3, float_muladd_negate_c,
                          &env->fp_status);
}

uint64_t helper_fmsub_d(CPURH850State *env, uint64_t frs1, uint64_t frs2,
                        uint64_t frs3)
{
    return float64_muladd(frs1, frs2, frs3, float_muladd_negate_c,
                          &env->fp_status);
}

uint64_t helper_fnmsub_s(CPURH850State *env, uint64_t frs1, uint64_t frs2,
                         uint64_t frs3)
{
    return float32_muladd(frs1, frs2, frs3, float_muladd_negate_product,
                          &env->fp_status);
}

uint64_t helper_fnmsub_d(CPURH850State *env, uint64_t frs1, uint64_t frs2,
                         uint64_t frs3)
{
    return float64_muladd(frs1, frs2, frs3, float_muladd_negate_product,
                          &env->fp_status);
}

uint64_t helper_fnmadd_s(CPURH850State *env, uint64_t frs1, uint64_t frs2,
                         uint64_t frs3)
{
    return float32_muladd(frs1, frs2, frs3, float_muladd_negate_c |
                          float_muladd_negate_product, &env->fp_status);
}

uint64_t helper_fnmadd_d(CPURH850State *env, uint64_t frs1, uint64_t frs2,
                         uint64_t frs3)
{
    return float64_muladd(frs1, frs2, frs3, float_muladd_negate_c |
                          float_muladd_negate_product, &env->fp_status);
}


/**
 * Floating-point simple precision helpers.
 **/

uint32_t HELPER(fadd_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_add(frs1, frs2, &env->fp_status);
}

uint32_t HELPER(fsub_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_sub(frs1, frs2, &env->fp_status);
}

uint32_t HELPER(fmul_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_mul(frs1, frs2, &env->fp_status);
}

uint32_t HELPER(fmax_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_maxnum(frs1, frs2, &env->fp_status);
}

uint32_t HELPER(fmin_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_minnum(frs1, frs2, &env->fp_status);
}

uint32_t HELPER(fdiv_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_div(frs1, frs2, &env->fp_status);
}

uint32_t HELPER(fabs_s)(CPURH850State *env, uint32_t frs1)
{
    return float32_abs(frs1);
}

uint32_t HELPER(fneg_s)(CPURH850State *env, uint32_t frs1)
{
    return (frs1^0x80000000);
}

uint32_t HELPER(ftrnc_sw)(CPURH850State *env, uint32_t frs1)
{
    return float32_to_int32_round_to_zero(frs1, &env->fp_status);
}

uint32_t HELPER(fceil_sw)(CPURH850State *env, uint32_t frs1)
{
    /* Convert to int32 and round to positive. */
    return float32_to_int32_scalbn(frs1, float_round_up, 0, &env->fp_status);
}

uint32_t HELPER(ffloor_sw)(CPURH850State *env, uint32_t frs1)
{
    /* Convert to int32 and round to positive. */
    return float32_to_int32_scalbn(frs1, float_round_down, 0, &env->fp_status);
}

uint32_t HELPER(fcvt_sw)(CPURH850State *env, uint32_t frs1)
{
    /* Convert to int32 and round based on fp_status. */
    return float32_to_int32(frs1, &env->fp_status);
}

uint32_t HELPER(fcvt_ls)(CPURH850State *env, uint64_t frs1)
{
    /* Convert int64 to float32 and round based on fp_status. */
    return int64_to_float32(frs1, &env->fp_status);
}

uint32_t HELPER(fcvt_hs)(CPURH850State *env, uint32_t frs1)
{
    /* Convert lower half of frs1 into float32. */
    return int16_to_float32((int16_t)(frs1&0xffff), &env->fp_status);
}

uint32_t HELPER(fcvt_sh)(CPURH850State *env, uint32_t frs1)
{
    /* Convert float32 to int16_t, zero-extended. */
    return float32_to_int16(frs1, &env->fp_status) & 0xffff;
}

uint32_t HELPER(fcvt_ws)(CPURH850State *env, uint32_t frs1)
{
    /* Convert to float32 and round based on fp_status. */
    return int32_to_float32(frs1, &env->fp_status);
}

uint32_t HELPER(ftrnc_suw)(CPURH850State *env, uint32_t frs1)
{
    return float32_to_uint32_round_to_zero(frs1, &env->fp_status);
}

uint32_t HELPER(fceil_suw)(CPURH850State *env, uint32_t frs1)
{
    /* Convert to int32 and round to positive. */
    return float32_to_uint32_scalbn(frs1, float_round_up, 0, &env->fp_status);
}

uint32_t HELPER(ffloor_suw)(CPURH850State *env, uint32_t frs1)
{
    /* Convert to int32 and round to positive. */
    return float32_to_uint32_scalbn(frs1, float_round_down, 0, &env->fp_status);
}

uint32_t HELPER(fcvt_suw)(CPURH850State *env, uint32_t frs1)
{
    /* Convert to int32 and round based on fp_status. */
    return float32_to_uint32(frs1, &env->fp_status);
}

uint32_t HELPER(fcvt_uws)(CPURH850State *env, uint32_t frs1)
{
    /* Convert from uint32 to float32 and round based on fp_status. */
    return uint32_to_float32(frs1, &env->fp_status);
}

uint32_t HELPER(fcvt_uls)(CPURH850State *env, uint64_t frs1)
{
    /* Convert uint64 to float32 and round based on fp_status. */
    return uint64_to_float32(frs1, &env->fp_status);
}

uint64_t HELPER(ftrnc_sl)(CPURH850State *env, uint32_t frs1)
{
    return float32_to_int64_round_to_zero(frs1, &env->fp_status);
}

uint64_t HELPER(fceil_sl)(CPURH850State *env, uint32_t frs1)
{
    /* Convert float32 to int64 and round to upper value. */
    return float32_to_int64_scalbn(frs1, float_round_up, 0, &env->fp_status);
}

uint64_t HELPER(ffloor_sl)(CPURH850State *env, uint32_t frs1)
{
    /* Convert float32 to int64 and round to lower value. */
    return float32_to_int64_scalbn(frs1, float_round_down, 0, &env->fp_status);
}

uint64_t HELPER(fcvt_sl)(CPURH850State *env, uint32_t frs1)
{
    /* Convert float32 to int64. */
    return float32_to_int64(frs1, &env->fp_status);
}

uint64_t HELPER(ftrnc_sul)(CPURH850State *env, uint32_t frs1)
{
    return float32_to_uint64_round_to_zero(frs1, &env->fp_status);
}

uint64_t HELPER(fceil_sul)(CPURH850State *env, uint32_t frs1)
{
    /* Convert float32 to uint64 and round to upper value. */
    return float32_to_uint64_scalbn(frs1, float_round_up, 0, &env->fp_status);
}

uint64_t HELPER(ffloor_sul)(CPURH850State *env, uint32_t frs1)
{
    /* Convert float32 to uint64 and round to lower value. */
    return float32_to_uint64_scalbn(frs1, float_round_down, 0, &env->fp_status);
}

uint64_t HELPER(fcvt_sul)(CPURH850State *env, uint32_t frs1)
{
    /* Convert float32 to uint64. */
    return float32_to_uint64(frs1, &env->fp_status);
}

uint32_t HELPER(fsqrt_s)(CPURH850State *env, uint32_t frs1)
{
    return float32_sqrt(frs1, &env->fp_status);
}

uint32_t HELPER(frecip_s)(CPURH850State *env, uint32_t frs1)
{
    /* Compute 1/x (0x3f800000 = float32(1.1)). */
    return float32_div(0x3f800000, frs1, &env->fp_status);
}

uint32_t HELPER(frsqrt_s)(CPURH850State *env, uint32_t frs1)
{
    /* Compute 1/sqrt(x). */
    return HELPER(frecip_s)(env, float32_sqrt(frs1, &env->fp_status));
}

uint32_t HELPER(f_is_nan_s)(CPURH850State *env, uint32_t frs1)
{
    /* Check if float32 is NaN. */
    return float32_is_any_nan(frs1);
}

uint32_t helper_fle_s(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_le(frs1, frs2, &env->fp_status);
}

uint32_t helper_flt_s(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_lt(frs1, frs2, &env->fp_status);
}

uint32_t helper_feq_s(CPURH850State *env, uint32_t frs1, uint32_t frs2)
{
    return float32_eq_quiet(frs1, frs2, &env->fp_status);
}


uint32_t HELPER(fmaf_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2, uint32_t frs3)
{
    /* Compute (frs1 * frs2) + frs3 */
    return float32_muladd(frs1, frs2, frs3, 0, &env->fp_status);
}

uint32_t HELPER(fmsf_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2, uint32_t frs3)
{
    /* Compute (frs1 * frs2) - frs3 */
    return float32_muladd(frs1, frs2, frs3, float_muladd_negate_c, &env->fp_status);
}

uint32_t HELPER(fnmaf_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2, uint32_t frs3)
{
    /* Compute (frs1 * frs2) + frs3 */
    return float32_muladd(frs1, frs2, frs3, float_muladd_negate_result, &env->fp_status);
}

uint32_t HELPER(fnmsf_s)(CPURH850State *env, uint32_t frs1, uint32_t frs2, uint32_t frs3)
{
    /* Compute (frs1 * frs2) - frs3 */
    return float32_muladd(frs1, frs2, frs3, float_muladd_negate_c | float_muladd_negate_result, &env->fp_status);
}



target_ulong helper_fcvt_w_s(CPURH850State *env, uint64_t frs1)
{
    return float32_to_int32(frs1, &env->fp_status);
}

target_ulong helper_fcvt_wu_s(CPURH850State *env, uint64_t frs1)
{
    return (int32_t)float32_to_uint32(frs1, &env->fp_status);
}

#if defined(TARGET_RH85064)
uint64_t helper_fcvt_l_s(CPURH850State *env, uint64_t frs1)
{
    return float32_to_int64(frs1, &env->fp_status);
}

uint64_t helper_fcvt_lu_s(CPURH850State *env, uint64_t frs1)
{
    return float32_to_uint64(frs1, &env->fp_status);
}
#endif

uint64_t helper_fcvt_s_w(CPURH850State *env, target_ulong rs1)
{
    return int32_to_float32((int32_t)rs1, &env->fp_status);
}

uint64_t helper_fcvt_s_wu(CPURH850State *env, target_ulong rs1)
{
    return uint32_to_float32((uint32_t)rs1, &env->fp_status);
}

#if defined(TARGET_RH85064)
uint64_t helper_fcvt_s_l(CPURH850State *env, uint64_t rs1)
{
    return int64_to_float32(rs1, &env->fp_status);
}

uint64_t helper_fcvt_s_lu(CPURH850State *env, uint64_t rs1)
{
    return uint64_to_float32(rs1, &env->fp_status);
}
#endif

target_ulong helper_fclass_s(uint64_t frs1)
{
    float32 f = frs1;
    bool sign = float32_is_neg(f);

    if (float32_is_infinity(f)) {
        return sign ? 1 << 0 : 1 << 7;
    } else if (float32_is_zero(f)) {
        return sign ? 1 << 3 : 1 << 4;
    } else if (float32_is_zero_or_denormal(f)) {
        return sign ? 1 << 2 : 1 << 5;
    } else if (float32_is_any_nan(f)) {
        float_status s = { 0 }; /* for snan_bit_is_one */
        return float32_is_quiet_nan(f, &s) ? 1 << 9 : 1 << 8;
    } else {
        return sign ? 1 << 1 : 1 << 6;
    }
}

/**
 * Floating-point double precision helpers.
 **/

uint64_t HELPER(fadd_d)(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_add(frs1, frs2, &env->fp_status);
}

uint64_t HELPER(fsub_d)(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_sub(frs1, frs2, &env->fp_status);
}

uint64_t HELPER(fmul_d)(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_mul(frs1, frs2, &env->fp_status);
}

uint64_t HELPER(fmax_d)(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_maxnum(frs1, frs2, &env->fp_status);
}

uint64_t HELPER(fmin_d)(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_minnum(frs1, frs2, &env->fp_status);
}

uint64_t HELPER(fdiv_d)(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_div(frs1, frs2, &env->fp_status);
}

uint64_t HELPER(fabs_d)(CPURH850State *env, uint64_t frs1)
{
    return float64_abs(frs1);
}

uint64_t HELPER(fneg_d)(CPURH850State *env, uint64_t frs1)
{
    return (frs1 ^ 0x8000000000000000);
}

uint32_t HELPER(ftrnc_dw)(CPURH850State *env, uint64_t frs1)
{
    return float64_to_int32_round_to_zero(frs1, &env->fp_status);
}

uint32_t HELPER(fceil_dw)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to int32 and round to upper value. */
    return float64_to_int32_scalbn(frs1, float_round_up, 0, &env->fp_status);
}

uint32_t HELPER(ffloor_dw)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to int32 and round to lower value. */
    return float64_to_int32_scalbn(frs1, float_round_down, 0, &env->fp_status);
}

uint32_t HELPER(fcvt_dw)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to int32. */
    return float64_to_int32(frs1, &env->fp_status);
}

uint32_t HELPER(ftrnc_duw)(CPURH850State *env, uint64_t frs1)
{
    return float64_to_uint32_round_to_zero(frs1, &env->fp_status);
}

uint32_t HELPER(fceil_duw)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to uint32 and round to upper value. */
    return float64_to_uint32_scalbn(frs1, float_round_up, 0, &env->fp_status);
}

uint32_t HELPER(ffloor_duw)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to uint32 and round to lower value. */
    return float64_to_uint32_scalbn(frs1, float_round_down, 0, &env->fp_status);
}

uint32_t HELPER(fcvt_duw)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to uint32. */
    return float64_to_uint32(frs1, &env->fp_status);
}

uint64_t HELPER(fcvt_wd)(CPURH850State *env, uint32_t frs1)
{
    /* Convert int32 to float64. */
    return int32_to_float64(frs1, &env->fp_status);
}

uint64_t HELPER(fcvt_ld)(CPURH850State *env, uint64_t frs1)
{
    /* Convert int32 to float64. */
    return int64_to_float64(frs1, &env->fp_status);
}

uint64_t HELPER(fcvt_sd)(CPURH850State *env, uint32_t frs1)
{
    /* Convert float32 to float64. */
    return float32_to_float64(frs1, &env->fp_status);
}

uint64_t HELPER(fcvt_uwd)(CPURH850State *env, uint32_t frs1)
{
    /* Convert int32 to float64. */
    return uint32_to_float64(frs1, &env->fp_status);
}

uint64_t HELPER(fcvt_uld)(CPURH850State *env, uint64_t frs1)
{
    /* Convert int32 to float64. */
    return uint64_to_float64(frs1, &env->fp_status);
}



uint64_t HELPER(ftrnc_dl)(CPURH850State *env, uint64_t frs1)
{
    return float64_to_int64_round_to_zero(frs1, &env->fp_status);
}

uint64_t HELPER(fceil_dl)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to int64 and round to upper value. */
    return float64_to_int64_scalbn(frs1, float_round_up, 0, &env->fp_status);
}

uint64_t HELPER(ffloor_dl)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to int64 and round to lower value. */
    return float64_to_int64_scalbn(frs1, float_round_down, 0, &env->fp_status);
}

uint64_t HELPER(fcvt_dl)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to int64. */
    return float64_to_int64(frs1, &env->fp_status);
}

uint64_t HELPER(ftrnc_dul)(CPURH850State *env, uint64_t frs1)
{
    return float64_to_uint64_round_to_zero(frs1, &env->fp_status);
}

uint64_t HELPER(fceil_dul)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to uint64 and round to upper value. */
    return float64_to_uint64_scalbn(frs1, float_round_up, 0, &env->fp_status);
}

uint64_t HELPER(ffloor_dul)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to uint64 and round to lower value. */
    return float64_to_uint64_scalbn(frs1, float_round_down, 0, &env->fp_status);
}

uint64_t HELPER(fcvt_dul)(CPURH850State *env, uint64_t frs1)
{
    /* Convert float64 to uint64. */
    return float64_to_uint64(frs1, &env->fp_status);
}

uint64_t HELPER(fsqrt_d)(CPURH850State *env, uint64_t frs1)
{
    return float64_sqrt(frs1, &env->fp_status);
}

uint64_t HELPER(frecip_d)(CPURH850State *env, uint64_t frs1)
{
    /* Compute 1/x (0x3ff0000000000000 = float64(1.1)). */
    return float64_div(0x3ff0000000000000, frs1, &env->fp_status);
}

uint64_t HELPER(frsqrt_d)(CPURH850State *env, uint64_t frs1)
{
    /* Compute 1/sqrt(x). */
    return HELPER(frecip_d)(env, float64_sqrt(frs1, &env->fp_status));
}

uint32_t HELPER(f_is_nan_d)(CPURH850State *env, uint64_t frs1)
{
    /* Check if float64 is NaN. */
    return float64_is_any_nan(frs1);
}



uint64_t helper_fcvt_s_d(CPURH850State *env, uint64_t rs1)
{
    return float64_to_float32(rs1, &env->fp_status);
}

uint64_t helper_fcvt_d_s(CPURH850State *env, uint64_t rs1)
{
    return float32_to_float64(rs1, &env->fp_status);
}

uint32_t helper_fle_d(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_le(frs1, frs2, &env->fp_status);
}

uint32_t helper_flt_d(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_lt(frs1, frs2, &env->fp_status);
}

uint32_t helper_feq_d(CPURH850State *env, uint64_t frs1, uint64_t frs2)
{
    return float64_eq_quiet(frs1, frs2, &env->fp_status);
}

target_ulong helper_fcvt_w_d(CPURH850State *env, uint64_t frs1)
{
    return float64_to_int32(frs1, &env->fp_status);
}

target_ulong helper_fcvt_wu_d(CPURH850State *env, uint64_t frs1)
{
    return (int32_t)float64_to_uint32(frs1, &env->fp_status);
}

#if defined(TARGET_RH85064)
uint64_t helper_fcvt_l_d(CPURH850State *env, uint64_t frs1)
{
    return float64_to_int64(frs1, &env->fp_status);
}

uint64_t helper_fcvt_lu_d(CPURH850State *env, uint64_t frs1)
{
    return float64_to_uint64(frs1, &env->fp_status);
}
#endif

uint64_t helper_fcvt_d_w(CPURH850State *env, target_ulong rs1)
{
    return int32_to_float64((int32_t)rs1, &env->fp_status);
}

uint64_t helper_fcvt_d_wu(CPURH850State *env, target_ulong rs1)
{
    return uint32_to_float64((uint32_t)rs1, &env->fp_status);
}

#if defined(TARGET_RH85064)
uint64_t helper_fcvt_d_l(CPURH850State *env, uint64_t rs1)
{
    return int64_to_float64(rs1, &env->fp_status);
}

uint64_t helper_fcvt_d_lu(CPURH850State *env, uint64_t rs1)
{
    return uint64_to_float64(rs1, &env->fp_status);
}
#endif

target_ulong helper_fclass_d(uint64_t frs1)
{
    float64 f = frs1;
    bool sign = float64_is_neg(f);

    if (float64_is_infinity(f)) {
        return sign ? 1 << 0 : 1 << 7;
    } else if (float64_is_zero(f)) {
        return sign ? 1 << 3 : 1 << 4;
    } else if (float64_is_zero_or_denormal(f)) {
        return sign ? 1 << 2 : 1 << 5;
    } else if (float64_is_any_nan(f)) {
        float_status s = { 0 }; /* for snan_bit_is_one */
        return float64_is_quiet_nan(f, &s) ? 1 << 9 : 1 << 8;
    } else {
        return sign ? 1 << 1 : 1 << 6;
    }
}
