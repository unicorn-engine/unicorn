/*
 *  AArch64 translation, common definitions.
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

#ifndef TARGET_ARM_TRANSLATE_A64_H
#define TARGET_ARM_TRANSLATE_A64_H

void unallocated_encoding(DisasContext *s);
typedef struct TCGContext TCGContext;

#define unsupported_encoding(s, insn)                                    \
    do {                                                                 \
        qemu_log_mask(LOG_UNIMP,                                         \
                      "%s:%d: unsupported instruction encoding 0x%08x "  \
                      "at pc=%016" PRIx64 "\n",                          \
                      __FILE__, __LINE__, insn, s->pc_curr);             \
        unallocated_encoding(s);                                         \
    } while (0)

TCGv_i64 new_tmp_a64(DisasContext *s);
TCGv_i64 new_tmp_a64_zero(DisasContext *s);
TCGv_i64 cpu_reg(DisasContext *s, int reg);
TCGv_i64 cpu_reg_sp(DisasContext *s, int reg);
TCGv_i64 read_cpu_reg(DisasContext *s, int reg, int sf);
TCGv_i64 read_cpu_reg_sp(DisasContext *s, int reg, int sf);
void write_fp_dreg(DisasContext *s, int reg, TCGv_i64 v);
TCGv_ptr get_fpstatus_ptr(TCGContext *tcg_ctx, bool);
bool logic_imm_decode_wmask(uint64_t *result, unsigned int immn,
                            unsigned int imms, unsigned int immr);
bool sve_access_check(DisasContext *s);

/* We should have at some point before trying to access an FP register
 * done the necessary access check, so assert that
 * (a) we did the check and
 * (b) we didn't then just plough ahead anyway if it failed.
 * Print the instruction pattern in the abort message so we can figure
 * out what we need to fix if a user encounters this problem in the wild.
 */
static inline void assert_fp_access_checked(DisasContext *s)
{
#ifdef CONFIG_DEBUG_TCG
    if (unlikely(!s->fp_access_checked || s->fp_excp_el)) {
        fprintf(stderr, "target-arm: FP access check missing for "
                "instruction 0x%08x\n", s->insn);
        abort();
    }
#endif
}

/* Return the offset into CPUARMState of an element of specified
 * size, 'element' places in from the least significant end of
 * the FP/vector register Qn.
 */
static inline int vec_reg_offset(DisasContext *s, int regno,
                                 int element, MemOp size)
{
    int element_size = 1 << size;
    int offs = element * element_size;
#ifdef HOST_WORDS_BIGENDIAN
    /* This is complicated slightly because vfp.zregs[n].d[0] is
     * still the lowest and vfp.zregs[n].d[15] the highest of the
     * 256 byte vector, even on big endian systems.
     *
     * Calculate the offset assuming fully little-endian,
     * then XOR to account for the order of the 8-byte units.
     *
     * For 16 byte elements, the two 8 byte halves will not form a
     * host int128 if the host is bigendian, since they're in the
     * wrong order.  However the only 16 byte operation we have is
     * a move, so we can ignore this for the moment.  More complicated
     * operations will have to special case loading and storing from
     * the zregs array.
     */
    if (element_size < 8) {
        offs ^= 8 - element_size;
    }
#endif
    offs += offsetof(CPUARMState, vfp.zregs[regno]);
    assert_fp_access_checked(s);
    return offs;
}

/* Return the offset info CPUARMState of the "whole" vector register Qn.  */
static inline int vec_full_reg_offset(DisasContext *s, int regno)
{
    assert_fp_access_checked(s);
    return offsetof(CPUARMState, vfp.zregs[regno]);
}

/* Return a newly allocated pointer to the vector register.  */
static inline TCGv_ptr vec_full_reg_ptr(DisasContext *s, int regno)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr ret = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, ret, tcg_ctx->cpu_env, vec_full_reg_offset(s, regno));
    return ret;
}

/* Return the byte size of the "whole" vector register, VL / 8.  */
static inline int vec_full_reg_size(DisasContext *s)
{
    return s->sve_len;
}

bool disas_sve(DisasContext *, uint32_t);

/* Note that the gvec expanders operate on offsets + sizes.  */
typedef void GVecGen2Fn(TCGContext *, unsigned, uint32_t, uint32_t, uint32_t, uint32_t);
typedef void GVecGen2iFn(TCGContext *, unsigned, uint32_t, uint32_t, int64_t,
                         uint32_t, uint32_t);
typedef void GVecGen3Fn(TCGContext *, unsigned, uint32_t, uint32_t,
                        uint32_t, uint32_t, uint32_t);
typedef void GVecGen4Fn(TCGContext *, unsigned, uint32_t, uint32_t, uint32_t,
                        uint32_t, uint32_t, uint32_t);

#endif /* TARGET_ARM_TRANSLATE_A64_H */
