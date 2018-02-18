/*
 *  AArch64 specific helpers
 *
 *  Copyright (c) 2013 Alexander Graf <agraf@suse.de>
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
#include "qemu/host-utils.h"
#include "sysemu/sysemu.h"
#include "qemu/bitops.h"
#include "internals.h"
#include "qemu/crc32c.h"

/* C2.4.7 Multiply and divide */
/* special cases for 0 and LLONG_MIN are mandated by the standard */
uint64_t HELPER(udiv64)(uint64_t num, uint64_t den)
{
    if (den == 0) {
        return 0;
    }
    return num / den;
}

int64_t HELPER(sdiv64)(int64_t num, int64_t den)
{
    if (den == 0) {
        return 0;
    }
    if (num == LLONG_MIN && den == -1) {
        return LLONG_MIN;
    }
    return num / den;
}

uint64_t HELPER(clz64)(uint64_t x)
{
    return clz64(x);
}

uint64_t HELPER(cls64)(uint64_t x)
{
    return clrsb64(x);
}

uint32_t HELPER(cls32)(uint32_t x)
{
    return clrsb32(x);
}

uint32_t HELPER(clz32)(uint32_t x)
{
    return clz32(x);
}

uint64_t HELPER(rbit64)(uint64_t x)
{
    return revbit64(x);
}

/* Convert a softfloat float_relation_ (as returned by
 * the float*_compare functions) to the correct ARM
 * NZCV flag state.
 */
static inline uint32_t float_rel_to_flags(int res)
{
    uint64_t flags;
    switch (res) {
    case float_relation_equal:
        flags = PSTATE_Z | PSTATE_C;
        break;
    case float_relation_less:
        flags = PSTATE_N;
        break;
    case float_relation_greater:
        flags = PSTATE_C;
        break;
    case float_relation_unordered:
    default:
        flags = PSTATE_C | PSTATE_V;
        break;
    }
    return flags;
}

uint64_t HELPER(vfp_cmps_a64)(float32 x, float32 y, void *fp_status)
{
    return float_rel_to_flags(float32_compare_quiet(x, y, fp_status));
}

uint64_t HELPER(vfp_cmpes_a64)(float32 x, float32 y, void *fp_status)
{
    return float_rel_to_flags(float32_compare(x, y, fp_status));
}

uint64_t HELPER(vfp_cmpd_a64)(float64 x, float64 y, void *fp_status)
{
    return float_rel_to_flags(float64_compare_quiet(x, y, fp_status));
}

uint64_t HELPER(vfp_cmped_a64)(float64 x, float64 y, void *fp_status)
{
    return float_rel_to_flags(float64_compare(x, y, fp_status));
}

float32 HELPER(vfp_mulxs)(float32 a, float32 b, void *fpstp)
{
    float_status *fpst = fpstp;

    if ((float32_is_zero(a) && float32_is_infinity(b)) ||
        (float32_is_infinity(a) && float32_is_zero(b))) {
        /* 2.0 with the sign bit set to sign(A) XOR sign(B) */
        return make_float32((1U << 30) |
                            ((float32_val(a) ^ float32_val(b)) & (1U << 31)));
    }
    return float32_mul(a, b, fpst);
}

float64 HELPER(vfp_mulxd)(float64 a, float64 b, void *fpstp)
{
    float_status *fpst = fpstp;

    if ((float64_is_zero(a) && float64_is_infinity(b)) ||
        (float64_is_infinity(a) && float64_is_zero(b))) {
        /* 2.0 with the sign bit set to sign(A) XOR sign(B) */
        return make_float64((1ULL << 62) |
                            ((float64_val(a) ^ float64_val(b)) & (1ULL << 63)));
    }
    return float64_mul(a, b, fpst);
}

uint64_t HELPER(simd_tbl)(CPUARMState *env, uint64_t result, uint64_t indices,
                          uint32_t rn, uint32_t numregs)
{
    /* Helper function for SIMD TBL and TBX. We have to do the table
     * lookup part for the 64 bits worth of indices we're passed in.
     * result is the initial results vector (either zeroes for TBL
     * or some guest values for TBX), rn the register number where
     * the table starts, and numregs the number of registers in the table.
     * We return the results of the lookups.
     */
    int shift;

    for (shift = 0; shift < 64; shift += 8) {
        int index = extract64(indices, shift, 8);
        if (index < 16 * numregs) {
            /* Convert index (a byte offset into the virtual table
             * which is a series of 128-bit vectors concatenated)
             * into the correct register element plus a bit offset
             * into that element, bearing in mind that the table
             * can wrap around from V31 to V0.
             */
            int elt = (rn * 2 + (index >> 3)) % 64;
            int bitidx = (index & 7) * 8;
            uint64_t *q = aa64_vfp_qreg(env, elt >> 1);
            uint64_t val = extract64(q[elt & 1], bitidx, 8);

            result = deposit64(result, shift, 8, val);
        }
    }
    return result;
}

/* 64bit/double versions of the neon float compare functions */
uint64_t HELPER(neon_ceq_f64)(float64 a, float64 b, void *fpstp)
{
    float_status *fpst = fpstp;
    return -float64_eq_quiet(a, b, fpst);
}

uint64_t HELPER(neon_cge_f64)(float64 a, float64 b, void *fpstp)
{
    float_status *fpst = fpstp;
    return -float64_le(b, a, fpst);
}

uint64_t HELPER(neon_cgt_f64)(float64 a, float64 b, void *fpstp)
{
    float_status *fpst = fpstp;
    return -float64_lt(b, a, fpst);
}

/* Reciprocal step and sqrt step. Note that unlike the A32/T32
 * versions, these do a fully fused multiply-add or
 * multiply-add-and-halve.
 */
#define float32_two make_float32(0x40000000)
#define float32_three make_float32(0x40400000)
#define float32_one_point_five make_float32(0x3fc00000)

#define float64_two make_float64(0x4000000000000000ULL)
#define float64_three make_float64(0x4008000000000000ULL)
#define float64_one_point_five make_float64(0x3FF8000000000000ULL)

float32 HELPER(recpsf_f32)(float32 a, float32 b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float32_squash_input_denormal(a, fpst);
    b = float32_squash_input_denormal(b, fpst);

    a = float32_chs(a);
    if ((float32_is_infinity(a) && float32_is_zero(b)) ||
        (float32_is_infinity(b) && float32_is_zero(a))) {
        return float32_two;
    }
    return float32_muladd(a, b, float32_two, 0, fpst);
}

float64 HELPER(recpsf_f64)(float64 a, float64 b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float64_squash_input_denormal(a, fpst);
    b = float64_squash_input_denormal(b, fpst);

    a = float64_chs(a);
    if ((float64_is_infinity(a) && float64_is_zero(b)) ||
        (float64_is_infinity(b) && float64_is_zero(a))) {
        return float64_two;
    }
    return float64_muladd(a, b, float64_two, 0, fpst);
}

float32 HELPER(rsqrtsf_f32)(float32 a, float32 b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float32_squash_input_denormal(a, fpst);
    b = float32_squash_input_denormal(b, fpst);

    a = float32_chs(a);
    if ((float32_is_infinity(a) && float32_is_zero(b)) ||
        (float32_is_infinity(b) && float32_is_zero(a))) {
        return float32_one_point_five;
    }
    return float32_muladd(a, b, float32_three, float_muladd_halve_result, fpst);
}

float64 HELPER(rsqrtsf_f64)(float64 a, float64 b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float64_squash_input_denormal(a, fpst);
    b = float64_squash_input_denormal(b, fpst);

    a = float64_chs(a);
    if ((float64_is_infinity(a) && float64_is_zero(b)) ||
        (float64_is_infinity(b) && float64_is_zero(a))) {
        return float64_one_point_five;
    }
    return float64_muladd(a, b, float64_three, float_muladd_halve_result, fpst);
}

/* Pairwise long add: add pairs of adjacent elements into
 * double-width elements in the result (eg _s8 is an 8x8->16 op)
 */
uint64_t HELPER(neon_addlp_s8)(uint64_t a)
{
    uint64_t nsignmask = 0x0080008000800080ULL;
    uint64_t wsignmask = 0x8000800080008000ULL;
    uint64_t elementmask = 0x00ff00ff00ff00ffULL;
    uint64_t tmp1, tmp2;
    uint64_t res, signres;

    /* Extract odd elements, sign extend each to a 16 bit field */
    tmp1 = a & elementmask;
    tmp1 ^= nsignmask;
    tmp1 |= wsignmask;
    tmp1 = (tmp1 - nsignmask) ^ wsignmask;
    /* Ditto for the even elements */
    tmp2 = (a >> 8) & elementmask;
    tmp2 ^= nsignmask;
    tmp2 |= wsignmask;
    tmp2 = (tmp2 - nsignmask) ^ wsignmask;

    /* calculate the result by summing bits 0..14, 16..22, etc,
     * and then adjusting the sign bits 15, 23, etc manually.
     * This ensures the addition can't overflow the 16 bit field.
     */
    signres = (tmp1 ^ tmp2) & wsignmask;
    res = (tmp1 & ~wsignmask) + (tmp2 & ~wsignmask);
    res ^= signres;

    return res;
}

uint64_t HELPER(neon_addlp_u8)(uint64_t a)
{
    uint64_t tmp;

    tmp = a & 0x00ff00ff00ff00ffULL;
    tmp += (a >> 8) & 0x00ff00ff00ff00ffULL;
    return tmp;
}

uint64_t HELPER(neon_addlp_s16)(uint64_t a)
{
    int32_t reslo, reshi;

    reslo = (int32_t)(int16_t)a + (int32_t)(int16_t)(a >> 16);
    reshi = (int32_t)(int16_t)(a >> 32) + (int32_t)(int16_t)(a >> 48);

    return (uint32_t)reslo | (((uint64_t)reshi) << 32);
}

uint64_t HELPER(neon_addlp_u16)(uint64_t a)
{
    uint64_t tmp;

    tmp = a & 0x0000ffff0000ffffULL;
    tmp += (a >> 16) & 0x0000ffff0000ffffULL;
    return tmp;
}

/* Floating-point reciprocal exponent - see FPRecpX in ARM ARM */
float32 HELPER(frecpx_f32)(float32 a, void *fpstp)
{
    float_status *fpst = fpstp;
    uint32_t val32, sbit;
    int32_t exp;

    if (float32_is_any_nan(a)) {
        float32 nan = a;
        if (float32_is_signaling_nan(a)) {
            float_raise(float_flag_invalid, fpst);
            nan = float32_maybe_silence_nan(a);
        }
        if (fpst->default_nan_mode) {
            nan = float32_default_nan;
        }
        return nan;
    }

    val32 = float32_val(a);
    sbit = 0x80000000ULL & val32;
    exp = extract32(val32, 23, 8);

    if (exp == 0) {
        return make_float32(sbit | (0xfe << 23));
    } else {
        return make_float32(sbit | (~exp & 0xff) << 23);
    }
}

float64 HELPER(frecpx_f64)(float64 a, void *fpstp)
{
    float_status *fpst = fpstp;
    uint64_t val64, sbit;
    int64_t exp;

    if (float64_is_any_nan(a)) {
        float64 nan = a;
        if (float64_is_signaling_nan(a)) {
            float_raise(float_flag_invalid, fpst);
            nan = float64_maybe_silence_nan(a);
        }
        if (fpst->default_nan_mode) {
            nan = float64_default_nan;
        }
        return nan;
    }

    val64 = float64_val(a);
    sbit = 0x8000000000000000ULL & val64;
    exp = extract64(float64_val(a), 52, 11);

    if (exp == 0) {
        return make_float64(sbit | (0x7feULL << 52));
    } else {
        return make_float64(sbit | (~exp & 0x7ffULL) << 52);
    }
}

float32 HELPER(fcvtx_f64_to_f32)(float64 a, CPUARMState *env)
{
    /* Von Neumann rounding is implemented by using round-to-zero
     * and then setting the LSB of the result if Inexact was raised.
     */
    float32 r;
    float_status *fpst = &env->vfp.fp_status;
    float_status tstat = *fpst;
    int exflags;

    set_float_rounding_mode(float_round_to_zero, &tstat);
    set_float_exception_flags(0, &tstat);
    r = float64_to_float32(a, &tstat);
    r = float32_maybe_silence_nan(r);
    exflags = get_float_exception_flags(&tstat);
    if (exflags & float_flag_inexact) {
        r = make_float32(float32_val(r) | 1);
    }
    exflags |= get_float_exception_flags(fpst);
    set_float_exception_flags(exflags, fpst);
    return r;
}

/* 64-bit versions of the CRC helpers. Note that although the operation
 * (and the prototypes of crc32c() and crc32() mean that only the bottom
 * 32 bits of the accumulator and result are used, we pass and return
 * uint64_t for convenience of the generated code. Unlike the 32-bit
 * instruction set versions, val may genuinely have 64 bits of data in it.
 * The upper bytes of val (above the number specified by 'bytes') must have
 * been zeroed out by the caller.
 */
uint64_t HELPER(crc32_64)(uint64_t acc, uint64_t val, uint32_t bytes)
{
    uint8_t buf[8];

    stq_le_p(buf, val);

    static const uint32_t iso_table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
        0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
        0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
        0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
        0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
        0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
        0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
        0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
        0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
        0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
        0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
        0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
        0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
        0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
        0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
        0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
        0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
        0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
        0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
        0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
        0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
        0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
        0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
        0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
        0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
        0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
        0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
        0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
        0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
        0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
        0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
        0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
        0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
        0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
        0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
        0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
        0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
        0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
        0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };

    const uint8_t* data = buf;
    uint32_t crc = (uint32_t)acc;

    while (bytes-- > 0) {
        crc = (crc >> 8) ^ iso_table[(crc ^ (*data++)) & 0xFF];
    }

    return crc;

    /* zlib crc32 converts the accumulator and output to one's complement.  */
    // return crc32(acc ^ 0xffffffff, buf, bytes) ^ 0xffffffff;
}

uint64_t HELPER(crc32c_64)(uint64_t acc, uint64_t val, uint32_t bytes)
{
    uint8_t buf[8];

    stq_le_p(buf, val);

    /* Linux crc32c converts the output to one's complement.  */
    return crc32c(acc, buf, bytes) ^ 0xffffffff;
}

#if !defined(CONFIG_USER_ONLY)

/* Handle a CPU exception.  */
void aarch64_cpu_do_interrupt(CPUState *cs)
{
    CPUARMState *env = cs->env_ptr;
    ARMCPU *cpu = ARM_CPU(env->uc, cs);
    unsigned int new_el = env->exception.target_el;
    target_ulong addr = env->cp15.vbar_el[new_el];
    unsigned int new_mode = aarch64_pstate_mode(new_el, true);

    if (arm_current_el(env) < new_el) {
        if (env->aarch64) {
            addr += 0x400;
        } else {
            addr += 0x600;
        }
    } else if (pstate_read(env) & PSTATE_SP) {
        addr += 0x200;
    }

    arm_log_exception(cs->exception_index);
    qemu_log_mask(CPU_LOG_INT, "...from EL%d to EL%d\n", arm_current_el(env),
                  new_el);
    if (qemu_loglevel_mask(CPU_LOG_INT)
        && !excp_is_internal(cs->exception_index)) {
        qemu_log_mask(CPU_LOG_INT, "...with ESR 0x%" PRIx32 "\n",
                      env->exception.syndrome);
    }

    if (arm_is_psci_call(cpu, cs->exception_index)) {
        arm_handle_psci_call(cpu);
        qemu_log_mask(CPU_LOG_INT, "...handled as PSCI call\n");
        return;
    }

    switch (cs->exception_index) {
    case EXCP_PREFETCH_ABORT:
    case EXCP_DATA_ABORT:
        env->cp15.far_el[new_el] = env->exception.vaddress;
        qemu_log_mask(CPU_LOG_INT, "...with FAR 0x%" PRIx64 "\n",
                      env->cp15.far_el[new_el]);
        /* fall through */
    case EXCP_BKPT:
    case EXCP_UDEF:
    case EXCP_SWI:
    case EXCP_HVC:
    case EXCP_HYP_TRAP:
    case EXCP_SMC:
        env->cp15.esr_el[new_el] = env->exception.syndrome;
        break;
    case EXCP_IRQ:
    case EXCP_VIRQ:
        addr += 0x80;
        break;
    case EXCP_FIQ:
    case EXCP_VFIQ:
        addr += 0x100;
        break;
    case EXCP_SEMIHOST:
        /* UNICORN: Commented out
        qemu_log_mask(CPU_LOG_INT,
                      "...handling as semihosting call 0x%" PRIx64 "\n",
                      env->xregs[0]);
        env->xregs[0] = do_arm_semihosting(env);*/
        return;
    default:
        cpu_abort(cs, "Unhandled exception 0x%x\n", cs->exception_index);
    }

    if (is_a64(env)) {
        env->banked_spsr[aarch64_banked_spsr_index(new_el)] = pstate_read(env);
        aarch64_save_sp(env, arm_current_el(env));
        env->elr_el[new_el] = env->pc;
    } else {
        env->banked_spsr[aarch64_banked_spsr_index(new_el)] = cpsr_read(env);
        if (!env->thumb) {
            env->cp15.esr_el[new_el] |= 1 << 25;
        }
        env->elr_el[new_el] = env->regs[15];

        aarch64_sync_32_to_64(env);

        env->condexec_bits = 0;
    }
    qemu_log_mask(CPU_LOG_INT, "...with ELR 0x%" PRIx64 "\n",
                  env->elr_el[new_el]);

    pstate_write(env, PSTATE_DAIF | new_mode);
    env->aarch64 = 1;
    aarch64_restore_sp(env, new_el);

    env->pc = addr;
    cs->interrupt_request |= CPU_INTERRUPT_EXITTB;
}
#endif
