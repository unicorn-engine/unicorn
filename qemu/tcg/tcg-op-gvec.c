/*
 * Generic vector operation expansion
 *
 * Copyright (c) 2018 Linaro
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
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-op-gvec.h"
#include "tcg/tcg-gvec-desc.h"

#define MAX_UNROLL  4

#ifdef CONFIG_DEBUG_TCG
// static const TCGOpcode vecop_list_empty[1] = { 0 };
#else
#define vecop_list_empty NULL
#endif


/* Verify vector size and alignment rules.  OFS should be the OR of all
   of the operand offsets so that we can check them all at once.  */
static void check_size_align(uint32_t oprsz, uint32_t maxsz, uint32_t ofs)
{
    uint32_t opr_align = oprsz >= 16 ? 15 : 7;
    uint32_t max_align = maxsz >= 16 || oprsz >= 16 ? 15 : 7;
    tcg_debug_assert(oprsz > 0);
    tcg_debug_assert(oprsz <= maxsz);
    tcg_debug_assert((oprsz & opr_align) == 0);
    tcg_debug_assert((maxsz & max_align) == 0);
    tcg_debug_assert((ofs & max_align) == 0);
}

/* Verify vector overlap rules for two operands.  */
static void check_overlap_2(uint32_t d, uint32_t a, uint32_t s)
{
    tcg_debug_assert(d == a || d + s <= a || a + s <= d);
}

/* Verify vector overlap rules for three operands.  */
static void check_overlap_3(uint32_t d, uint32_t a, uint32_t b, uint32_t s)
{
    check_overlap_2(d, a, s);
    check_overlap_2(d, b, s);
    check_overlap_2(a, b, s);
}

/* Verify vector overlap rules for four operands.  */
static void check_overlap_4(uint32_t d, uint32_t a, uint32_t b,
                            uint32_t c, uint32_t s)
{
    check_overlap_2(d, a, s);
    check_overlap_2(d, b, s);
    check_overlap_2(d, c, s);
    check_overlap_2(a, b, s);
    check_overlap_2(a, c, s);
    check_overlap_2(b, c, s);
}

/* Create a descriptor from components.  */
uint32_t simd_desc(uint32_t oprsz, uint32_t maxsz, int32_t data)
{
    uint32_t desc = 0;

    assert(oprsz % 8 == 0 && oprsz <= (8 << SIMD_OPRSZ_BITS));
    assert(maxsz % 8 == 0 && maxsz <= (8 << SIMD_MAXSZ_BITS));
    assert(data == sextract32(data, 0, SIMD_DATA_BITS));

    oprsz = (oprsz / 8) - 1;
    maxsz = (maxsz / 8) - 1;
    desc = deposit32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS, oprsz);
    desc = deposit32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS, maxsz);
    desc = deposit32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS, data);

    return desc;
}

/* Generate a call to a gvec-style helper with two vector operands.  */
void tcg_gen_gvec_2_ool(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs,
                        uint32_t oprsz, uint32_t maxsz, int32_t data,
                        gen_helper_gvec_2 *fn)
{
    TCGv_ptr a0, a1;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);

    fn(tcg_ctx, a0, a1, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Generate a call to a gvec-style helper with two vector operands
   and one scalar operand.  */
void tcg_gen_gvec_2i_ool(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, TCGv_i64 c,
                         uint32_t oprsz, uint32_t maxsz, int32_t data,
                         gen_helper_gvec_2i *fn)
{
    TCGv_ptr a0, a1;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);

    fn(tcg_ctx, a0, a1, c, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Generate a call to a gvec-style helper with three vector operands.  */
void tcg_gen_gvec_3_ool(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                        uint32_t oprsz, uint32_t maxsz, int32_t data,
                        gen_helper_gvec_3 *fn)
{
    TCGv_ptr a0, a1, a2;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);
    a2 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);
    tcg_gen_addi_ptr(tcg_ctx, a2, tcg_ctx->cpu_env, bofs);

    fn(tcg_ctx, a0, a1, a2, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_ptr(tcg_ctx, a2);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Generate a call to a gvec-style helper with four vector operands.  */
void tcg_gen_gvec_4_ool(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                        uint32_t cofs, uint32_t oprsz, uint32_t maxsz,
                        int32_t data, gen_helper_gvec_4 *fn)
{
    TCGv_ptr a0, a1, a2, a3;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);
    a2 = tcg_temp_new_ptr(tcg_ctx);
    a3 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);
    tcg_gen_addi_ptr(tcg_ctx, a2, tcg_ctx->cpu_env, bofs);
    tcg_gen_addi_ptr(tcg_ctx, a3, tcg_ctx->cpu_env, cofs);

    fn(tcg_ctx, a0, a1, a2, a3, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_ptr(tcg_ctx, a2);
    tcg_temp_free_ptr(tcg_ctx, a3);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Generate a call to a gvec-style helper with five vector operands.  */
void tcg_gen_gvec_5_ool(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                        uint32_t cofs, uint32_t xofs, uint32_t oprsz,
                        uint32_t maxsz, int32_t data, gen_helper_gvec_5 *fn)
{
    TCGv_ptr a0, a1, a2, a3, a4;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);
    a2 = tcg_temp_new_ptr(tcg_ctx);
    a3 = tcg_temp_new_ptr(tcg_ctx);
    a4 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);
    tcg_gen_addi_ptr(tcg_ctx, a2, tcg_ctx->cpu_env, bofs);
    tcg_gen_addi_ptr(tcg_ctx, a3, tcg_ctx->cpu_env, cofs);
    tcg_gen_addi_ptr(tcg_ctx, a4, tcg_ctx->cpu_env, xofs);

    fn(tcg_ctx, a0, a1, a2, a3, a4, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_ptr(tcg_ctx, a2);
    tcg_temp_free_ptr(tcg_ctx, a3);
    tcg_temp_free_ptr(tcg_ctx, a4);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Generate a call to a gvec-style helper with three vector operands
   and an extra pointer operand.  */
void tcg_gen_gvec_2_ptr(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs,
                        TCGv_ptr ptr, uint32_t oprsz, uint32_t maxsz,
                        int32_t data, gen_helper_gvec_2_ptr *fn)
{
    TCGv_ptr a0, a1;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);

    fn(tcg_ctx, a0, a1, ptr, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Generate a call to a gvec-style helper with three vector operands
   and an extra pointer operand.  */
void tcg_gen_gvec_3_ptr(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                        TCGv_ptr ptr, uint32_t oprsz, uint32_t maxsz,
                        int32_t data, gen_helper_gvec_3_ptr *fn)
{
    TCGv_ptr a0, a1, a2;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);
    a2 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);
    tcg_gen_addi_ptr(tcg_ctx, a2, tcg_ctx->cpu_env, bofs);

    fn(tcg_ctx, a0, a1, a2, ptr, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_ptr(tcg_ctx, a2);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Generate a call to a gvec-style helper with four vector operands
   and an extra pointer operand.  */
void tcg_gen_gvec_4_ptr(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                        uint32_t cofs, TCGv_ptr ptr, uint32_t oprsz,
                        uint32_t maxsz, int32_t data,
                        gen_helper_gvec_4_ptr *fn)
{
    TCGv_ptr a0, a1, a2, a3;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);
    a2 = tcg_temp_new_ptr(tcg_ctx);
    a3 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);
    tcg_gen_addi_ptr(tcg_ctx, a2, tcg_ctx->cpu_env, bofs);
    tcg_gen_addi_ptr(tcg_ctx, a3, tcg_ctx->cpu_env, cofs);

    fn(tcg_ctx, a0, a1, a2, a3, ptr, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_ptr(tcg_ctx, a2);
    tcg_temp_free_ptr(tcg_ctx, a3);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Generate a call to a gvec-style helper with five vector operands
   and an extra pointer operand.  */
void tcg_gen_gvec_5_ptr(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                        uint32_t cofs, uint32_t eofs, TCGv_ptr ptr,
                        uint32_t oprsz, uint32_t maxsz, int32_t data,
                        gen_helper_gvec_5_ptr *fn)
{
    TCGv_ptr a0, a1, a2, a3, a4;
    TCGv_i32 desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, data));

    a0 = tcg_temp_new_ptr(tcg_ctx);
    a1 = tcg_temp_new_ptr(tcg_ctx);
    a2 = tcg_temp_new_ptr(tcg_ctx);
    a3 = tcg_temp_new_ptr(tcg_ctx);
    a4 = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
    tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);
    tcg_gen_addi_ptr(tcg_ctx, a2, tcg_ctx->cpu_env, bofs);
    tcg_gen_addi_ptr(tcg_ctx, a3, tcg_ctx->cpu_env, cofs);
    tcg_gen_addi_ptr(tcg_ctx, a4, tcg_ctx->cpu_env, eofs);

    fn(tcg_ctx, a0, a1, a2, a3, a4, ptr, desc);

    tcg_temp_free_ptr(tcg_ctx, a0);
    tcg_temp_free_ptr(tcg_ctx, a1);
    tcg_temp_free_ptr(tcg_ctx, a2);
    tcg_temp_free_ptr(tcg_ctx, a3);
    tcg_temp_free_ptr(tcg_ctx, a4);
    tcg_temp_free_i32(tcg_ctx, desc);
}

/* Return true if we want to implement something of OPRSZ bytes
   in units of LNSZ.  This limits the expansion of inline code.  */
static inline bool check_size_impl(uint32_t oprsz, uint32_t lnsz)
{
    if (oprsz % lnsz == 0) {
        uint32_t lnct = oprsz / lnsz;
        return lnct >= 1 && lnct <= MAX_UNROLL;
    }
    return false;
}

static void expand_clr(TCGContext *tcg_ctx, uint32_t dofs, uint32_t maxsz);

/* Duplicate C as per VECE.  */
uint64_t dup_const_func(unsigned vece, uint64_t c)
{
    switch (vece) {
    case MO_8:
        return 0x0101010101010101ull * (uint8_t)c;
    case MO_16:
        return 0x0001000100010001ull * (uint16_t)c;
    case MO_32:
        return 0x0000000100000001ull * (uint32_t)c;
    case MO_64:
        return c;
    default:
        // g_assert_not_reached();
        return 0;
    }
}

/* Duplicate IN into OUT as per VECE.  */
static void gen_dup_i32(TCGContext *tcg_ctx, unsigned vece, TCGv_i32 out, TCGv_i32 in)
{
    switch (vece) {
    case MO_8:
        tcg_gen_ext8u_i32(tcg_ctx, out, in);
        tcg_gen_muli_i32(tcg_ctx, out, out, 0x01010101);
        break;
    case MO_16:
        tcg_gen_deposit_i32(tcg_ctx, out, in, in, 16, 16);
        break;
    case MO_32:
        tcg_gen_mov_i32(tcg_ctx, out, in);
        break;
    default:
        // g_assert_not_reached();
        break;
    }
}

static void gen_dup_i64(TCGContext *tcg_ctx, unsigned vece, TCGv_i64 out, TCGv_i64 in)
{
    switch (vece) {
    case MO_8:
        tcg_gen_ext8u_i64(tcg_ctx, out, in);
        tcg_gen_muli_i64(tcg_ctx, out, out, 0x0101010101010101ull);
        break;
    case MO_16:
        tcg_gen_ext16u_i64(tcg_ctx, out, in);
        tcg_gen_muli_i64(tcg_ctx, out, out, 0x0001000100010001ull);
        break;
    case MO_32:
        tcg_gen_deposit_i64(tcg_ctx, out, in, in, 32, 32);
        break;
    case MO_64:
        tcg_gen_mov_i64(tcg_ctx, out, in);
        break;
    default:
        // g_assert_not_reached();
        break;
    }
}

/* Select a supported vector type for implementing an operation on SIZE
 * bytes.  If OP is 0, assume that the real operation to be performed is
 * required by all backends.  Otherwise, make sure than OP can be performed
 * on elements of size VECE in the selected type.  Do not select V64 if
 * PREFER_I64 is true.  Return 0 if no vector type is selected.
 */
static TCGType choose_vector_type(TCGContext *tcg_ctx, const TCGOpcode *list, unsigned vece,
                                  uint32_t size, bool prefer_i64)
{
    if (TCG_TARGET_HAS_v256 && check_size_impl(size, 32)) {
        /*
         * Recall that ARM SVE allows vector sizes that are not a
         * power of 2, but always a multiple of 16.  The intent is
         * that e.g. size == 80 would be expanded with 2x32 + 1x16.
         * It is hard to imagine a case in which v256 is supported
         * but v128 is not, but check anyway.
         */
        if (tcg_can_emit_vecop_list(tcg_ctx, list, TCG_TYPE_V256, vece)
            && (size % 32 == 0
                || tcg_can_emit_vecop_list(tcg_ctx, list, TCG_TYPE_V128, vece))) {
            return TCG_TYPE_V256;
        }
    }
    if (TCG_TARGET_HAS_v128 && check_size_impl(size, 16)
        && tcg_can_emit_vecop_list(tcg_ctx, list, TCG_TYPE_V128, vece)) {
        return TCG_TYPE_V128;
    }
    if (TCG_TARGET_HAS_v64 && !prefer_i64 && check_size_impl(size, 8)
        && tcg_can_emit_vecop_list(tcg_ctx, list, TCG_TYPE_V64, vece)) {
        return TCG_TYPE_V64;
    }
    return 0;
}

static void do_dup_store(TCGContext *tcg_ctx, TCGType type, uint32_t dofs, uint32_t oprsz,
                         uint32_t maxsz, TCGv_vec t_vec)
{
    uint32_t i = 0;

    switch (type) {
    case TCG_TYPE_V256:
        /*
         * Recall that ARM SVE allows vector sizes that are not a
         * power of 2, but always a multiple of 16.  The intent is
         * that e.g. size == 80 would be expanded with 2x32 + 1x16.
         */
        for (; i + 32 <= oprsz; i += 32) {
            tcg_gen_stl_vec(tcg_ctx, t_vec, tcg_ctx->cpu_env, dofs + i, TCG_TYPE_V256);
        }
        /* fallthru */
    case TCG_TYPE_V128:
        for (; i + 16 <= oprsz; i += 16) {
            tcg_gen_stl_vec(tcg_ctx, t_vec, tcg_ctx->cpu_env, dofs + i, TCG_TYPE_V128);
        }
        break;
    case TCG_TYPE_V64:
        for (; i < oprsz; i += 8) {
            tcg_gen_stl_vec(tcg_ctx, t_vec, tcg_ctx->cpu_env, dofs + i, TCG_TYPE_V64);
        }
        break;
    default:
        g_assert_not_reached();
    }

    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

/* Set OPRSZ bytes at DOFS to replications of IN_32, IN_64 or IN_C.
 * Only one of IN_32 or IN_64 may be set;
 * IN_C is used if IN_32 and IN_64 are unset.
 */
static void do_dup(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t oprsz,
                   uint32_t maxsz, TCGv_i32 in_32, TCGv_i64 in_64,
                   uint64_t in_c)
{
    TCGType type;
    TCGv_i64 t_64;
    TCGv_i32 t_32, t_desc;
    TCGv_ptr t_ptr;
    uint32_t i;

    assert(vece <= (in_32 ? MO_32 : MO_64));
    assert(in_32 == NULL || in_64 == NULL);

    /* If we're storing 0, expand oprsz to maxsz.  */
    if (in_32 == NULL && in_64 == NULL) {
        in_c = dup_const(vece, in_c);
        if (in_c == 0) {
            oprsz = maxsz;
        }
    }

    /* Implement inline with a vector type, if possible.
     * Prefer integer when 64-bit host and no variable dup.
     */
    type = choose_vector_type(tcg_ctx, NULL, vece, oprsz,
                              (TCG_TARGET_REG_BITS == 64 && in_32 == NULL
                               && (in_64 == NULL || vece == MO_64)));
    if (type != 0) {
        TCGv_vec t_vec = tcg_temp_new_vec(tcg_ctx, type);

        if (in_32) {
            tcg_gen_dup_i32_vec(tcg_ctx, vece, t_vec, in_32);
        } else if (in_64) {
            tcg_gen_dup_i64_vec(tcg_ctx, vece, t_vec, in_64);
        } else {
            tcg_gen_dupi_vec(tcg_ctx, vece, t_vec, in_c);
        }
        do_dup_store(tcg_ctx, type, dofs, oprsz, maxsz, t_vec);
        tcg_temp_free_vec(tcg_ctx, t_vec);
        return;
    }

    /* Otherwise, inline with an integer type, unless "large".  */
    if (check_size_impl(oprsz, TCG_TARGET_REG_BITS / 8)) {
        t_64 = NULL;
        t_32 = NULL;

        if (in_32) {
            /* We are given a 32-bit variable input.  For a 64-bit host,
               use a 64-bit operation unless the 32-bit operation would
               be simple enough.  */
            if (TCG_TARGET_REG_BITS == 64
                && (vece != MO_32 || !check_size_impl(oprsz, 4))) {
                t_64 = tcg_temp_new_i64(tcg_ctx);
                tcg_gen_extu_i32_i64(tcg_ctx, t_64, in_32);
                gen_dup_i64(tcg_ctx, vece, t_64, t_64);
            } else {
                t_32 = tcg_temp_new_i32(tcg_ctx);
                gen_dup_i32(tcg_ctx, vece, t_32, in_32);
            }
        } else if (in_64) {
            /* We are given a 64-bit variable input.  */
            t_64 = tcg_temp_new_i64(tcg_ctx);
            gen_dup_i64(tcg_ctx, vece, t_64, in_64);
        } else {
            /* We are given a constant input.  */
            /* For 64-bit hosts, use 64-bit constants for "simple" constants
               or when we'd need too many 32-bit stores, or when a 64-bit
               constant is really required.  */
            if (vece == MO_64
                || (TCG_TARGET_REG_BITS == 64
                    && (in_c == 0 || in_c == -1
                        || !check_size_impl(oprsz, 4)))) {
                t_64 = tcg_const_i64(tcg_ctx, in_c);
            } else {
                t_32 = tcg_const_i32(tcg_ctx, in_c);
            }
        }

        /* Implement inline if we picked an implementation size above.  */
        if (t_32) {
            for (i = 0; i < oprsz; i += 4) {
                tcg_gen_st_i32(tcg_ctx, t_32, tcg_ctx->cpu_env, dofs + i);
            }
            tcg_temp_free_i32(tcg_ctx, t_32);
            goto done;
        }
        if (t_64) {
            for (i = 0; i < oprsz; i += 8) {
                tcg_gen_st_i64(tcg_ctx, t_64, tcg_ctx->cpu_env, dofs + i);
            }
            tcg_temp_free_i64(tcg_ctx, t_64);
            goto done;
        }
    }

    /* Otherwise implement out of line.  */
    t_ptr = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, t_ptr, tcg_ctx->cpu_env, dofs);
    t_desc = tcg_const_i32(tcg_ctx, simd_desc(oprsz, maxsz, 0));

    if (vece == MO_64) {
        if (in_64) {
            gen_helper_gvec_dup64(tcg_ctx, t_ptr, t_desc, in_64);
        } else {
            t_64 = tcg_const_i64(tcg_ctx, in_c);
            gen_helper_gvec_dup64(tcg_ctx, t_ptr, t_desc, t_64);
            tcg_temp_free_i64(tcg_ctx, t_64);
        }
    } else {
        typedef void dup_fn(TCGContext *, TCGv_ptr, TCGv_i32, TCGv_i32);
        static dup_fn * const fns[3] = {
            gen_helper_gvec_dup8,
            gen_helper_gvec_dup16,
            gen_helper_gvec_dup32
        };

        if (in_32) {
            fns[vece](tcg_ctx, t_ptr, t_desc, in_32);
        } else {
            t_32 = tcg_temp_new_i32(tcg_ctx);
            if (in_64) {
                tcg_gen_extrl_i64_i32(tcg_ctx, t_32, in_64);
            } else if (vece == MO_8) {
                tcg_gen_movi_i32(tcg_ctx, t_32, in_c & 0xff);
            } else if (vece == MO_16) {
                tcg_gen_movi_i32(tcg_ctx, t_32, in_c & 0xffff);
            } else {
                tcg_gen_movi_i32(tcg_ctx, t_32, in_c);
            }
            fns[vece](tcg_ctx, t_ptr, t_desc, t_32);
            tcg_temp_free_i32(tcg_ctx, t_32);
        }
    }

    tcg_temp_free_ptr(tcg_ctx, t_ptr);
    tcg_temp_free_i32(tcg_ctx, t_desc);
    return;

 done:
    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

/* Likewise, but with zero.  */
static void expand_clr(TCGContext *tcg_ctx, uint32_t dofs, uint32_t maxsz)
{
    do_dup(tcg_ctx, MO_8, dofs, maxsz, maxsz, NULL, NULL, 0);
}

/* Expand OPSZ bytes worth of two-operand operations using i32 elements.  */
static void expand_2_i32(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t oprsz,
                         void (*fni)(TCGContext *, TCGv_i32, TCGv_i32))
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 4) {
        tcg_gen_ld_i32(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        fni(tcg_ctx, t0, t0);
        tcg_gen_st_i32(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void expand_2i_i32(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t oprsz,
                          int32_t c, bool load_dest,
                          void (*fni)(TCGContext *, TCGv_i32, TCGv_i32, int32_t))
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 4) {
        tcg_gen_ld_i32(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        if (load_dest) {
            tcg_gen_ld_i32(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, t1, t0, c);
        tcg_gen_st_i32(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i32(tcg_ctx, t0);
    tcg_temp_free_i32(tcg_ctx, t1);
}

static void expand_2s_i32(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t oprsz,
                          TCGv_i32 c, bool scalar_first,
                          void (*fni)(TCGContext *, TCGv_i32, TCGv_i32, TCGv_i32))
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 4) {
        tcg_gen_ld_i32(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        if (scalar_first) {
            fni(tcg_ctx, t1, c, t0);
        } else {
            fni(tcg_ctx, t1, t0, c);
        }
        tcg_gen_st_i32(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i32(tcg_ctx, t0);
    tcg_temp_free_i32(tcg_ctx, t1);
}

/* Expand OPSZ bytes worth of three-operand operations using i32 elements.  */
static void expand_3_i32(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs,
                         uint32_t bofs, uint32_t oprsz, bool load_dest,
                         void (*fni)(TCGContext *, TCGv_i32, TCGv_i32, TCGv_i32))
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t2 = tcg_temp_new_i32(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 4) {
        tcg_gen_ld_i32(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_i32(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        if (load_dest) {
            tcg_gen_ld_i32(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, t2, t0, t1);
        tcg_gen_st_i32(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i32(tcg_ctx, t2);
    tcg_temp_free_i32(tcg_ctx, t1);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void expand_3i_i32(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                          uint32_t oprsz, int32_t c, bool load_dest,
                          void (*fni)(TCGContext *, TCGv_i32, TCGv_i32, TCGv_i32, int32_t))
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t2 = tcg_temp_new_i32(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 4) {
        tcg_gen_ld_i32(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_i32(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        if (load_dest) {
            tcg_gen_ld_i32(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, t2, t0, t1, c);
        tcg_gen_st_i32(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i32(tcg_ctx, t0);
    tcg_temp_free_i32(tcg_ctx, t1);
    tcg_temp_free_i32(tcg_ctx, t2);
}

/* Expand OPSZ bytes worth of three-operand operations using i32 elements.  */
static void expand_4_i32(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                         uint32_t cofs, uint32_t oprsz, bool write_aofs,
                         void (*fni)(TCGContext *, TCGv_i32, TCGv_i32, TCGv_i32, TCGv_i32))
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t2 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t3 = tcg_temp_new_i32(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 4) {
        tcg_gen_ld_i32(tcg_ctx, t1, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_i32(tcg_ctx, t2, tcg_ctx->cpu_env, bofs + i);
        tcg_gen_ld_i32(tcg_ctx, t3, tcg_ctx->cpu_env, cofs + i);
        fni(tcg_ctx, t0, t1, t2, t3);
        tcg_gen_st_i32(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
        if (write_aofs) {
            tcg_gen_st_i32(tcg_ctx, t1, tcg_ctx->cpu_env, aofs + i);
        }
    }
    tcg_temp_free_i32(tcg_ctx, t3);
    tcg_temp_free_i32(tcg_ctx, t2);
    tcg_temp_free_i32(tcg_ctx, t1);
    tcg_temp_free_i32(tcg_ctx, t0);
}

/* Expand OPSZ bytes worth of two-operand operations using i64 elements.  */
static void expand_2_i64(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t oprsz,
                         void (*fni)(TCGContext *, TCGv_i64, TCGv_i64))
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 8) {
        tcg_gen_ld_i64(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        fni(tcg_ctx, t0, t0);
        tcg_gen_st_i64(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void expand_2i_i64(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t oprsz,
                          int64_t c, bool load_dest,
                          void (*fni)(TCGContext *, TCGv_i64, TCGv_i64, int64_t))
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 8) {
        tcg_gen_ld_i64(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        if (load_dest) {
            tcg_gen_ld_i64(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, t1, t0, c);
        tcg_gen_st_i64(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

static void expand_2s_i64(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t oprsz,
                          TCGv_i64 c, bool scalar_first,
                          void (*fni)(TCGContext *, TCGv_i64, TCGv_i64, TCGv_i64))
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 8) {
        tcg_gen_ld_i64(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        if (scalar_first) {
            fni(tcg_ctx, t1, c, t0);
        } else {
            fni(tcg_ctx, t1, t0, c);
        }
        tcg_gen_st_i64(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

/* Expand OPSZ bytes worth of three-operand operations using i64 elements.  */
static void expand_3_i64(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs,
                         uint32_t bofs, uint32_t oprsz, bool load_dest,
                         void (*fni)(TCGContext *, TCGv_i64, TCGv_i64, TCGv_i64))
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 8) {
        tcg_gen_ld_i64(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_i64(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        if (load_dest) {
            tcg_gen_ld_i64(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, t2, t0, t1);
        tcg_gen_st_i64(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i64(tcg_ctx, t2);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void expand_3i_i64(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                          uint32_t oprsz, int64_t c, bool load_dest,
                          void (*fni)(TCGContext *, TCGv_i64, TCGv_i64, TCGv_i64, int64_t))
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 8) {
        tcg_gen_ld_i64(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_i64(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        if (load_dest) {
            tcg_gen_ld_i64(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, t2, t0, t1, c);
        tcg_gen_st_i64(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
}

/* Expand OPSZ bytes worth of three-operand operations using i64 elements.  */
static void expand_4_i64(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                         uint32_t cofs, uint32_t oprsz, bool write_aofs,
                         void (*fni)(TCGContext *, TCGv_i64, TCGv_i64, TCGv_i64, TCGv_i64))
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t3 = tcg_temp_new_i64(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 8) {
        tcg_gen_ld_i64(tcg_ctx, t1, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_i64(tcg_ctx, t2, tcg_ctx->cpu_env, bofs + i);
        tcg_gen_ld_i64(tcg_ctx, t3, tcg_ctx->cpu_env, cofs + i);
        fni(tcg_ctx, t0, t1, t2, t3);
        tcg_gen_st_i64(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
        if (write_aofs) {
            tcg_gen_st_i64(tcg_ctx, t1, tcg_ctx->cpu_env, aofs + i);
        }
    }
    tcg_temp_free_i64(tcg_ctx, t3);
    tcg_temp_free_i64(tcg_ctx, t2);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t0);
}

/* Expand OPSZ bytes worth of two-operand operations using host vectors.  */
static void expand_2_vec(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                         uint32_t oprsz, uint32_t tysz, TCGType type,
                         void (*fni)(TCGContext *, unsigned, TCGv_vec, TCGv_vec))
{
    TCGv_vec t0 = tcg_temp_new_vec(tcg_ctx, type);
    uint32_t i;

    for (i = 0; i < oprsz; i += tysz) {
        tcg_gen_ld_vec(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        fni(tcg_ctx, vece, t0, t0);
        tcg_gen_st_vec(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_vec(tcg_ctx, t0);
}

/* Expand OPSZ bytes worth of two-vector operands and an immediate operand
   using host vectors.  */
static void expand_2i_vec(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                          uint32_t oprsz, uint32_t tysz, TCGType type,
                          int64_t c, bool load_dest,
                          void (*fni)(TCGContext *, unsigned, TCGv_vec, TCGv_vec, int64_t))
{
    TCGv_vec t0 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t1 = tcg_temp_new_vec(tcg_ctx, type);
    uint32_t i;

    for (i = 0; i < oprsz; i += tysz) {
        tcg_gen_ld_vec(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        if (load_dest) {
            tcg_gen_ld_vec(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, vece, t1, t0, c);
        tcg_gen_st_vec(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_vec(tcg_ctx, t0);
    tcg_temp_free_vec(tcg_ctx, t1);
}

static void expand_2s_vec(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                          uint32_t oprsz, uint32_t tysz, TCGType type,
                          TCGv_vec c, bool scalar_first,
                          void (*fni)(TCGContext *, unsigned, TCGv_vec, TCGv_vec, TCGv_vec))
{
    TCGv_vec t0 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t1 = tcg_temp_new_vec(tcg_ctx, type);
    uint32_t i;

    for (i = 0; i < oprsz; i += tysz) {
        tcg_gen_ld_vec(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        if (scalar_first) {
            fni(tcg_ctx, vece, t1, c, t0);
        } else {
            fni(tcg_ctx, vece, t1, t0, c);
        }
        tcg_gen_st_vec(tcg_ctx, t1, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_vec(tcg_ctx, t0);
    tcg_temp_free_vec(tcg_ctx, t1);
}

/* Expand OPSZ bytes worth of three-operand operations using host vectors.  */
static void expand_3_vec(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                         uint32_t bofs, uint32_t oprsz,
                         uint32_t tysz, TCGType type, bool load_dest,
                         void (*fni)(TCGContext *, unsigned, TCGv_vec, TCGv_vec, TCGv_vec))
{
    TCGv_vec t0 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t1 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t2 = tcg_temp_new_vec(tcg_ctx, type);
    uint32_t i;

    for (i = 0; i < oprsz; i += tysz) {
        tcg_gen_ld_vec(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_vec(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        if (load_dest) {
            tcg_gen_ld_vec(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, vece, t2, t0, t1);
        tcg_gen_st_vec(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_vec(tcg_ctx, t2);
    tcg_temp_free_vec(tcg_ctx, t1);
    tcg_temp_free_vec(tcg_ctx, t0);
}

/*
 * Expand OPSZ bytes worth of three-vector operands and an immediate operand
 * using host vectors.
 */
static void expand_3i_vec(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                          uint32_t bofs, uint32_t oprsz, uint32_t tysz,
                          TCGType type, int64_t c, bool load_dest,
                          void (*fni)(TCGContext *, unsigned, TCGv_vec, TCGv_vec, TCGv_vec,
                                      int64_t))
{
    TCGv_vec t0 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t1 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t2 = tcg_temp_new_vec(tcg_ctx, type);
    uint32_t i;

    for (i = 0; i < oprsz; i += tysz) {
        tcg_gen_ld_vec(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_vec(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        if (load_dest) {
            tcg_gen_ld_vec(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
        }
        fni(tcg_ctx, vece, t2, t0, t1, c);
        tcg_gen_st_vec(tcg_ctx, t2, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_vec(tcg_ctx, t0);
    tcg_temp_free_vec(tcg_ctx, t1);
    tcg_temp_free_vec(tcg_ctx, t2);
}

/* Expand OPSZ bytes worth of four-operand operations using host vectors.  */
static void expand_4_vec(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                         uint32_t bofs, uint32_t cofs, uint32_t oprsz,
                         uint32_t tysz, TCGType type, bool write_aofs,
                         void (*fni)(TCGContext *, unsigned, TCGv_vec, TCGv_vec,
                                     TCGv_vec, TCGv_vec))
{
    TCGv_vec t0 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t1 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t2 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t3 = tcg_temp_new_vec(tcg_ctx, type);
    uint32_t i;

    for (i = 0; i < oprsz; i += tysz) {
        tcg_gen_ld_vec(tcg_ctx, t1, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_vec(tcg_ctx, t2, tcg_ctx->cpu_env, bofs + i);
        tcg_gen_ld_vec(tcg_ctx, t3, tcg_ctx->cpu_env, cofs + i);
        fni(tcg_ctx, vece, t0, t1, t2, t3);
        tcg_gen_st_vec(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
        if (write_aofs) {
            tcg_gen_st_vec(tcg_ctx, t1, tcg_ctx->cpu_env, aofs + i);
        }
    }
    tcg_temp_free_vec(tcg_ctx, t3);
    tcg_temp_free_vec(tcg_ctx, t2);
    tcg_temp_free_vec(tcg_ctx, t1);
    tcg_temp_free_vec(tcg_ctx, t0);
}

/* Expand a vector two-operand operation.  */
void tcg_gen_gvec_2(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs,
                    uint32_t oprsz, uint32_t maxsz, const GVecGen2 *g)
{
    const TCGOpcode *this_list = g->opt_opc ? g->opt_opc : vecop_list_empty;
    const TCGOpcode *hold_list = tcg_swap_vecop_list(this_list);
    TCGType type;
    uint32_t some;

    check_size_align(oprsz, maxsz, dofs | aofs);
    check_overlap_2(dofs, aofs, maxsz);

    type = 0;
    if (g->fniv) {
        type = choose_vector_type(tcg_ctx, g->opt_opc, g->vece, oprsz, g->prefer_i64);
    }
    switch (type) {
    case TCG_TYPE_V256:
        /* Recall that ARM SVE allows vector sizes that are not a
         * power of 2, but always a multiple of 16.  The intent is
         * that e.g. size == 80 would be expanded with 2x32 + 1x16.
         */
        some = QEMU_ALIGN_DOWN(oprsz, 32);
        expand_2_vec(tcg_ctx, g->vece, dofs, aofs, some, 32, TCG_TYPE_V256, g->fniv);
        if (some == oprsz) {
            break;
        }
        dofs += some;
        aofs += some;
        oprsz -= some;
        maxsz -= some;
        /* fallthru */
    case TCG_TYPE_V128:
        expand_2_vec(tcg_ctx, g->vece, dofs, aofs, oprsz, 16, TCG_TYPE_V128, g->fniv);
        break;
    case TCG_TYPE_V64:
        expand_2_vec(tcg_ctx, g->vece, dofs, aofs, oprsz, 8, TCG_TYPE_V64, g->fniv);
        break;

    case 0:
        if (g->fni8 && check_size_impl(oprsz, 8)) {
            expand_2_i64(tcg_ctx, dofs, aofs, oprsz, g->fni8);
        } else if (g->fni4 && check_size_impl(oprsz, 4)) {
            expand_2_i32(tcg_ctx, dofs, aofs, oprsz, g->fni4);
        } else {
            assert(g->fno != NULL);
            tcg_gen_gvec_2_ool(tcg_ctx, dofs, aofs, oprsz, maxsz, g->data, g->fno);
            oprsz = maxsz;
        }
        break;

    default:
        g_assert_not_reached();
    }
    tcg_swap_vecop_list(hold_list);

    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

/* Expand a vector operation with two vectors and an immediate.  */
void tcg_gen_gvec_2i(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t oprsz,
                     uint32_t maxsz, int64_t c, const GVecGen2i *g)
{
    const TCGOpcode *this_list = g->opt_opc ? g->opt_opc : vecop_list_empty;
    const TCGOpcode *hold_list = tcg_swap_vecop_list(this_list);
    TCGType type;
    uint32_t some;

    check_size_align(oprsz, maxsz, dofs | aofs);
    check_overlap_2(dofs, aofs, maxsz);

    type = 0;
    if (g->fniv) {
        type = choose_vector_type(tcg_ctx, g->opt_opc, g->vece, oprsz, g->prefer_i64);
    }
    switch (type) {
    case TCG_TYPE_V256:
        /* Recall that ARM SVE allows vector sizes that are not a
         * power of 2, but always a multiple of 16.  The intent is
         * that e.g. size == 80 would be expanded with 2x32 + 1x16.
         */
        some = QEMU_ALIGN_DOWN(oprsz, 32);
        expand_2i_vec(tcg_ctx, g->vece, dofs, aofs, some, 32, TCG_TYPE_V256,
                      c, g->load_dest, g->fniv);
        if (some == oprsz) {
            break;
        }
        dofs += some;
        aofs += some;
        oprsz -= some;
        maxsz -= some;
        /* fallthru */
    case TCG_TYPE_V128:
        expand_2i_vec(tcg_ctx, g->vece, dofs, aofs, oprsz, 16, TCG_TYPE_V128,
                      c, g->load_dest, g->fniv);
        break;
    case TCG_TYPE_V64:
        expand_2i_vec(tcg_ctx, g->vece, dofs, aofs, oprsz, 8, TCG_TYPE_V64,
                      c, g->load_dest, g->fniv);
        break;

    case 0:
        if (g->fni8 && check_size_impl(oprsz, 8)) {
            expand_2i_i64(tcg_ctx, dofs, aofs, oprsz, c, g->load_dest, g->fni8);
        } else if (g->fni4 && check_size_impl(oprsz, 4)) {
            expand_2i_i32(tcg_ctx, dofs, aofs, oprsz, c, g->load_dest, g->fni4);
        } else {
            if (g->fno) {
                tcg_gen_gvec_2_ool(tcg_ctx, dofs, aofs, oprsz, maxsz, c, g->fno);
            } else {
                TCGv_i64 tcg_c = tcg_const_i64(tcg_ctx, c);
                tcg_gen_gvec_2i_ool(tcg_ctx, dofs, aofs, tcg_c, oprsz,
                                    maxsz, c, g->fnoi);
                tcg_temp_free_i64(tcg_ctx, tcg_c);
            }
            oprsz = maxsz;
        }
        break;

    default:
        g_assert_not_reached();
    }
    tcg_swap_vecop_list(hold_list);

    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

/* Expand a vector operation with two vectors and a scalar.  */
void tcg_gen_gvec_2s(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t oprsz,
                     uint32_t maxsz, TCGv_i64 c, const GVecGen2s *g)
{
    TCGType type;

    check_size_align(oprsz, maxsz, dofs | aofs);
    check_overlap_2(dofs, aofs, maxsz);

    type = 0;
    if (g->fniv) {
        type = choose_vector_type(tcg_ctx, g->opt_opc, g->vece, oprsz, g->prefer_i64);
    }
    if (type != 0) {
        const TCGOpcode *this_list = g->opt_opc ? g->opt_opc : vecop_list_empty;
        const TCGOpcode *hold_list = tcg_swap_vecop_list(this_list);
        TCGv_vec t_vec = tcg_temp_new_vec(tcg_ctx, type);
        uint32_t some;

        tcg_gen_dup_i64_vec(tcg_ctx, g->vece, t_vec, c);

        switch (type) {
        case TCG_TYPE_V256:
            /* Recall that ARM SVE allows vector sizes that are not a
             * power of 2, but always a multiple of 16.  The intent is
             * that e.g. size == 80 would be expanded with 2x32 + 1x16.
             */
            some = QEMU_ALIGN_DOWN(oprsz, 32);
            expand_2s_vec(tcg_ctx, g->vece, dofs, aofs, some, 32, TCG_TYPE_V256,
                          t_vec, g->scalar_first, g->fniv);
            if (some == oprsz) {
                break;
            }
            dofs += some;
            aofs += some;
            oprsz -= some;
            maxsz -= some;
            /* fallthru */

        case TCG_TYPE_V128:
            expand_2s_vec(tcg_ctx, g->vece, dofs, aofs, oprsz, 16, TCG_TYPE_V128,
                          t_vec, g->scalar_first, g->fniv);
            break;

        case TCG_TYPE_V64:
            expand_2s_vec(tcg_ctx, g->vece, dofs, aofs, oprsz, 8, TCG_TYPE_V64,
                          t_vec, g->scalar_first, g->fniv);
            break;

        default:
            g_assert_not_reached();
        }
        tcg_temp_free_vec(tcg_ctx, t_vec);
        tcg_swap_vecop_list(hold_list);
    } else if (g->fni8 && check_size_impl(oprsz, 8)) {
        TCGv_i64 t64 = tcg_temp_new_i64(tcg_ctx);

        gen_dup_i64(tcg_ctx, g->vece, t64, c);
        expand_2s_i64(tcg_ctx, dofs, aofs, oprsz, t64, g->scalar_first, g->fni8);
        tcg_temp_free_i64(tcg_ctx, t64);
    } else if (g->fni4 && check_size_impl(oprsz, 4)) {
        TCGv_i32 t32 = tcg_temp_new_i32(tcg_ctx);

        tcg_gen_extrl_i64_i32(tcg_ctx, t32, c);
        gen_dup_i32(tcg_ctx, g->vece, t32, t32);
        expand_2s_i32(tcg_ctx, dofs, aofs, oprsz, t32, g->scalar_first, g->fni4);
        tcg_temp_free_i32(tcg_ctx, t32);
    } else {
        tcg_gen_gvec_2i_ool(tcg_ctx, dofs, aofs, c, oprsz, maxsz, 0, g->fno);
        return;
    }

    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

/* Expand a vector three-operand operation.  */
void tcg_gen_gvec_3(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                    uint32_t oprsz, uint32_t maxsz, const GVecGen3 *g)
{
    const TCGOpcode *this_list = g->opt_opc ? g->opt_opc : vecop_list_empty;
    const TCGOpcode *hold_list = tcg_swap_vecop_list(this_list);
    TCGType type;
    uint32_t some;

    check_size_align(oprsz, maxsz, dofs | aofs | bofs);
    check_overlap_3(dofs, aofs, bofs, maxsz);

    type = 0;
    if (g->fniv) {
        type = choose_vector_type(tcg_ctx, g->opt_opc, g->vece, oprsz, g->prefer_i64);
    }
    switch (type) {
    case TCG_TYPE_V256:
        /* Recall that ARM SVE allows vector sizes that are not a
         * power of 2, but always a multiple of 16.  The intent is
         * that e.g. size == 80 would be expanded with 2x32 + 1x16.
         */
        some = QEMU_ALIGN_DOWN(oprsz, 32);
        expand_3_vec(tcg_ctx, g->vece, dofs, aofs, bofs, some, 32, TCG_TYPE_V256,
                     g->load_dest, g->fniv);
        if (some == oprsz) {
            break;
        }
        dofs += some;
        aofs += some;
        bofs += some;
        oprsz -= some;
        maxsz -= some;
        /* fallthru */
    case TCG_TYPE_V128:
        expand_3_vec(tcg_ctx, g->vece, dofs, aofs, bofs, oprsz, 16, TCG_TYPE_V128,
                     g->load_dest, g->fniv);
        break;
    case TCG_TYPE_V64:
        expand_3_vec(tcg_ctx, g->vece, dofs, aofs, bofs, oprsz, 8, TCG_TYPE_V64,
                     g->load_dest, g->fniv);
        break;

    case 0:
        if (g->fni8 && check_size_impl(oprsz, 8)) {
            expand_3_i64(tcg_ctx, dofs, aofs, bofs, oprsz, g->load_dest, g->fni8);
        } else if (g->fni4 && check_size_impl(oprsz, 4)) {
            expand_3_i32(tcg_ctx, dofs, aofs, bofs, oprsz, g->load_dest, g->fni4);
        } else {
            assert(g->fno != NULL);
            tcg_gen_gvec_3_ool(tcg_ctx, dofs, aofs, bofs, oprsz,
                               maxsz, g->data, g->fno);
            oprsz = maxsz;
        }
        break;

    default:
        g_assert_not_reached();
    }
    tcg_swap_vecop_list(hold_list);

    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

/* Expand a vector operation with three vectors and an immediate.  */
void tcg_gen_gvec_3i(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                     uint32_t oprsz, uint32_t maxsz, int64_t c,
                     const GVecGen3i *g)
{
    const TCGOpcode *this_list = g->opt_opc ? g->opt_opc : vecop_list_empty;
    const TCGOpcode *hold_list = tcg_swap_vecop_list(this_list);
    TCGType type;
    uint32_t some;

    check_size_align(oprsz, maxsz, dofs | aofs | bofs);
    check_overlap_3(dofs, aofs, bofs, maxsz);

    type = 0;
    if (g->fniv) {
        type = choose_vector_type(tcg_ctx, g->opt_opc, g->vece, oprsz, g->prefer_i64);
    }
    switch (type) {
    case TCG_TYPE_V256:
        /*
         * Recall that ARM SVE allows vector sizes that are not a
         * power of 2, but always a multiple of 16.  The intent is
         * that e.g. size == 80 would be expanded with 2x32 + 1x16.
         */
        some = QEMU_ALIGN_DOWN(oprsz, 32);
        expand_3i_vec(tcg_ctx, g->vece, dofs, aofs, bofs, some, 32, TCG_TYPE_V256,
                      c, g->load_dest, g->fniv);
        if (some == oprsz) {
            break;
        }
        dofs += some;
        aofs += some;
        bofs += some;
        oprsz -= some;
        maxsz -= some;
        /* fallthru */
    case TCG_TYPE_V128:
        expand_3i_vec(tcg_ctx, g->vece, dofs, aofs, bofs, oprsz, 16, TCG_TYPE_V128,
                      c, g->load_dest, g->fniv);
        break;
    case TCG_TYPE_V64:
        expand_3i_vec(tcg_ctx, g->vece, dofs, aofs, bofs, oprsz, 8, TCG_TYPE_V64,
                      c, g->load_dest, g->fniv);
        break;

    case 0:
        if (g->fni8 && check_size_impl(oprsz, 8)) {
            expand_3i_i64(tcg_ctx, dofs, aofs, bofs, oprsz, c, g->load_dest, g->fni8);
        } else if (g->fni4 && check_size_impl(oprsz, 4)) {
            expand_3i_i32(tcg_ctx, dofs, aofs, bofs, oprsz, c, g->load_dest, g->fni4);
        } else {
            assert(g->fno != NULL);
            tcg_gen_gvec_3_ool(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, c, g->fno);
            oprsz = maxsz;
        }
        break;

    default:
        g_assert_not_reached();
    }
    tcg_swap_vecop_list(hold_list);

    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

/* Expand a vector four-operand operation.  */
void tcg_gen_gvec_4(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs, uint32_t cofs,
                    uint32_t oprsz, uint32_t maxsz, const GVecGen4 *g)
{
    const TCGOpcode *this_list = g->opt_opc ? g->opt_opc : vecop_list_empty;
    const TCGOpcode *hold_list = tcg_swap_vecop_list(this_list);
    TCGType type;
    uint32_t some;

    check_size_align(oprsz, maxsz, dofs | aofs | bofs | cofs);
    check_overlap_4(dofs, aofs, bofs, cofs, maxsz);

    type = 0;
    if (g->fniv) {
        type = choose_vector_type(tcg_ctx, g->opt_opc, g->vece, oprsz, g->prefer_i64);
    }
    switch (type) {
    case TCG_TYPE_V256:
        /* Recall that ARM SVE allows vector sizes that are not a
         * power of 2, but always a multiple of 16.  The intent is
         * that e.g. size == 80 would be expanded with 2x32 + 1x16.
         */
        some = QEMU_ALIGN_DOWN(oprsz, 32);
        expand_4_vec(tcg_ctx, g->vece, dofs, aofs, bofs, cofs, some,
                     32, TCG_TYPE_V256, g->write_aofs, g->fniv);
        if (some == oprsz) {
            break;
        }
        dofs += some;
        aofs += some;
        bofs += some;
        cofs += some;
        oprsz -= some;
        maxsz -= some;
        /* fallthru */
    case TCG_TYPE_V128:
        expand_4_vec(tcg_ctx, g->vece, dofs, aofs, bofs, cofs, oprsz,
                     16, TCG_TYPE_V128, g->write_aofs, g->fniv);
        break;
    case TCG_TYPE_V64:
        expand_4_vec(tcg_ctx, g->vece, dofs, aofs, bofs, cofs, oprsz,
                     8, TCG_TYPE_V64, g->write_aofs, g->fniv);
        break;

    case 0:
        if (g->fni8 && check_size_impl(oprsz, 8)) {
            expand_4_i64(tcg_ctx, dofs, aofs, bofs, cofs, oprsz,
                         g->write_aofs, g->fni8);
        } else if (g->fni4 && check_size_impl(oprsz, 4)) {
            expand_4_i32(tcg_ctx, dofs, aofs, bofs, cofs, oprsz,
                         g->write_aofs, g->fni4);
        } else {
            assert(g->fno != NULL);
            tcg_gen_gvec_4_ool(tcg_ctx, dofs, aofs, bofs, cofs,
                               oprsz, maxsz, g->data, g->fno);
            oprsz = maxsz;
        }
        break;

    default:
        g_assert_not_reached();
    }
    tcg_swap_vecop_list(hold_list);

    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

/*
 * Expand specific vector operations.
 */

static void vec_mov2(TCGContext *tcg_ctx, unsigned vece, TCGv_vec a, TCGv_vec b)
{
    tcg_gen_mov_vec(tcg_ctx, a, b);
}

void tcg_gen_gvec_mov(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen2 g = {
        .fni8 = tcg_gen_mov_i64,
        .fniv = vec_mov2,
        .fno = gen_helper_gvec_mov,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };
    if (dofs != aofs) {
        tcg_gen_gvec_2(tcg_ctx, dofs, aofs, oprsz, maxsz, &g);
    } else {
        check_size_align(oprsz, maxsz, dofs);
        if (oprsz < maxsz) {
            expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
        }
    }
}

void tcg_gen_gvec_dup_i32(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t oprsz,
                          uint32_t maxsz, TCGv_i32 in)
{
    check_size_align(oprsz, maxsz, dofs);
    tcg_debug_assert(vece <= MO_32);
    do_dup(tcg_ctx, vece, dofs, oprsz, maxsz, in, NULL, 0);
}

void tcg_gen_gvec_dup_i64(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t oprsz,
                          uint32_t maxsz, TCGv_i64 in)
{
    check_size_align(oprsz, maxsz, dofs);
    tcg_debug_assert(vece <= MO_64);
    do_dup(tcg_ctx, vece, dofs, oprsz, maxsz, NULL, in, 0);
}

void tcg_gen_gvec_dup_mem(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                          uint32_t oprsz, uint32_t maxsz)
{
    check_size_align(oprsz, maxsz, dofs);
    if (vece <= MO_64) {
        TCGType type = choose_vector_type(tcg_ctx, NULL, vece, oprsz, 0);
        if (type != 0) {
            TCGv_vec t_vec = tcg_temp_new_vec(tcg_ctx, type);
            tcg_gen_dup_mem_vec(tcg_ctx, vece, t_vec, tcg_ctx->cpu_env, aofs);
            do_dup_store(tcg_ctx, type, dofs, oprsz, maxsz, t_vec);
            tcg_temp_free_vec(tcg_ctx, t_vec);
        } else if (vece <= MO_32) {
            TCGv_i32 in = tcg_temp_new_i32(tcg_ctx);
            switch (vece) {
            case MO_8:
                tcg_gen_ld8u_i32(tcg_ctx, in, tcg_ctx->cpu_env, aofs);
                break;
            case MO_16:
                tcg_gen_ld16u_i32(tcg_ctx, in, tcg_ctx->cpu_env, aofs);
                break;
            default:
                tcg_gen_ld_i32(tcg_ctx, in, tcg_ctx->cpu_env, aofs);
                break;
            }
            do_dup(tcg_ctx, vece, dofs, oprsz, maxsz, in, NULL, 0);
            tcg_temp_free_i32(tcg_ctx, in);
        } else {
            TCGv_i64 in = tcg_temp_new_i64(tcg_ctx);
            tcg_gen_ld_i64(tcg_ctx, in, tcg_ctx->cpu_env, aofs);
            do_dup(tcg_ctx, vece, dofs, oprsz, maxsz, NULL, in, 0);
            tcg_temp_free_i64(tcg_ctx, in);
        }
    } else {
        /* 128-bit duplicate.  */
        /* ??? Dup to 256-bit vector.  */
        int i;

        tcg_debug_assert(vece == 4);
        tcg_debug_assert(oprsz >= 16);
        if (TCG_TARGET_HAS_v128) {
            TCGv_vec in = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);

            tcg_gen_ld_vec(tcg_ctx, in, tcg_ctx->cpu_env, aofs);
            for (i = 0; i < oprsz; i += 16) {
                tcg_gen_st_vec(tcg_ctx, in, tcg_ctx->cpu_env, dofs + i);
            }
            tcg_temp_free_vec(tcg_ctx, in);
        } else {
            TCGv_i64 in0 = tcg_temp_new_i64(tcg_ctx);
            TCGv_i64 in1 = tcg_temp_new_i64(tcg_ctx);

            tcg_gen_ld_i64(tcg_ctx, in0, tcg_ctx->cpu_env, aofs);
            tcg_gen_ld_i64(tcg_ctx, in1, tcg_ctx->cpu_env, aofs + 8);
            for (i = 0; i < oprsz; i += 16) {
                tcg_gen_st_i64(tcg_ctx, in0, tcg_ctx->cpu_env, dofs + i);
                tcg_gen_st_i64(tcg_ctx, in1, tcg_ctx->cpu_env, dofs + i + 8);
            }
            tcg_temp_free_i64(tcg_ctx, in0);
            tcg_temp_free_i64(tcg_ctx, in1);
        }
        if (oprsz < maxsz) {
            expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
        }
    }
}

void tcg_gen_gvec_dup64i(TCGContext *tcg_ctx, uint32_t dofs, uint32_t oprsz,
                         uint32_t maxsz, uint64_t x)
{
    check_size_align(oprsz, maxsz, dofs);
    do_dup(tcg_ctx, MO_64, dofs, oprsz, maxsz, NULL, NULL, x);
}

void tcg_gen_gvec_dup32i(TCGContext *tcg_ctx, uint32_t dofs, uint32_t oprsz,
                         uint32_t maxsz, uint32_t x)
{
    check_size_align(oprsz, maxsz, dofs);
    do_dup(tcg_ctx, MO_32, dofs, oprsz, maxsz, NULL, NULL, x);
}

void tcg_gen_gvec_dup16i(TCGContext *tcg_ctx, uint32_t dofs, uint32_t oprsz,
                         uint32_t maxsz, uint16_t x)
{
    check_size_align(oprsz, maxsz, dofs);
    do_dup(tcg_ctx, MO_16, dofs, oprsz, maxsz, NULL, NULL, x);
}

void tcg_gen_gvec_dup8i(TCGContext *tcg_ctx, uint32_t dofs, uint32_t oprsz,
                         uint32_t maxsz, uint8_t x)
{
    check_size_align(oprsz, maxsz, dofs);
    do_dup(tcg_ctx, MO_8, dofs, oprsz, maxsz, NULL, NULL, x);
}

void tcg_gen_gvec_not(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen2 g = {
        .fni8 = tcg_gen_not_i64,
        .fniv = tcg_gen_not_vec,
        .fno = gen_helper_gvec_not,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };
    tcg_gen_gvec_2(tcg_ctx, dofs, aofs, oprsz, maxsz, &g);
}

/* Perform a vector addition using normal addition and a mask.  The mask
   should be the sign bit of each lane.  This 6-operation form is more
   efficient than separate additions when there are 4 or more lanes in
   the 64-bit operation.  */
static void gen_addv_mask(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b, TCGv_i64 m)
{
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t3 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andc_i64(tcg_ctx, t1, a, m);
    tcg_gen_andc_i64(tcg_ctx, t2, b, m);
    tcg_gen_xor_i64(tcg_ctx, t3, a, b);
    tcg_gen_add_i64(tcg_ctx, d, t1, t2);
    tcg_gen_and_i64(tcg_ctx, t3, t3, m);
    tcg_gen_xor_i64(tcg_ctx, d, d, t3);

    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
    tcg_temp_free_i64(tcg_ctx, t3);
}

void tcg_gen_vec_add8_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 m = tcg_const_i64(tcg_ctx, dup_const(MO_8, 0x80));
    gen_addv_mask(tcg_ctx, d, a, b, m);
    tcg_temp_free_i64(tcg_ctx, m);
}

void tcg_gen_vec_add16_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 m = tcg_const_i64(tcg_ctx, dup_const(MO_16, 0x8000));
    gen_addv_mask(tcg_ctx, d, a, b, m);
    tcg_temp_free_i64(tcg_ctx, m);
}

void tcg_gen_vec_add32_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, t1, a, ~0xffffffffull);
    tcg_gen_add_i64(tcg_ctx, t2, a, b);
    tcg_gen_add_i64(tcg_ctx, t1, t1, b);
    tcg_gen_deposit_i64(tcg_ctx, d, t1, t2, 0, 32);

    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
}

static const TCGOpcode vecop_list_add[] = { INDEX_op_add_vec, 0 };

void tcg_gen_gvec_add(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g[4] = {
        { .fni8 = tcg_gen_vec_add8_i64,
          .fniv = tcg_gen_add_vec,
          .fno = gen_helper_gvec_add8,
          .opt_opc = vecop_list_add,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_add16_i64,
          .fniv = tcg_gen_add_vec,
          .fno = gen_helper_gvec_add16,
          .opt_opc = vecop_list_add,
          .vece = MO_16 },
        { .fni4 = tcg_gen_add_i32,
          .fniv = tcg_gen_add_vec,
          .fno = gen_helper_gvec_add32,
          .opt_opc = vecop_list_add,
          .vece = MO_32 },
        { .fni8 = tcg_gen_add_i64,
          .fniv = tcg_gen_add_vec,
          .fno = gen_helper_gvec_add64,
          .opt_opc = vecop_list_add,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

void tcg_gen_gvec_adds(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       TCGv_i64 c, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen2s g[4] = {
        { .fni8 = tcg_gen_vec_add8_i64,
          .fniv = tcg_gen_add_vec,
          .fno = gen_helper_gvec_adds8,
          .opt_opc = vecop_list_add,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_add16_i64,
          .fniv = tcg_gen_add_vec,
          .fno = gen_helper_gvec_adds16,
          .opt_opc = vecop_list_add,
          .vece = MO_16 },
        { .fni4 = tcg_gen_add_i32,
          .fniv = tcg_gen_add_vec,
          .fno = gen_helper_gvec_adds32,
          .opt_opc = vecop_list_add,
          .vece = MO_32 },
        { .fni8 = tcg_gen_add_i64,
          .fniv = tcg_gen_add_vec,
          .fno = gen_helper_gvec_adds64,
          .opt_opc = vecop_list_add,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, c, &g[vece]);
}

void tcg_gen_gvec_addi(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       int64_t c, uint32_t oprsz, uint32_t maxsz)
{
    TCGv_i64 tmp = tcg_const_i64(tcg_ctx, c);
    tcg_gen_gvec_adds(tcg_ctx, vece, dofs, aofs, tmp, oprsz, maxsz);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

static const TCGOpcode vecop_list_sub[] = { INDEX_op_sub_vec, 0 };

void tcg_gen_gvec_subs(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       TCGv_i64 c, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen2s g[4] = {
        { .fni8 = tcg_gen_vec_sub8_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_gvec_subs8,
          .opt_opc = vecop_list_sub,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_sub16_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_gvec_subs16,
          .opt_opc = vecop_list_sub,
          .vece = MO_16 },
        { .fni4 = tcg_gen_sub_i32,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_gvec_subs32,
          .opt_opc = vecop_list_sub,
          .vece = MO_32 },
        { .fni8 = tcg_gen_sub_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_gvec_subs64,
          .opt_opc = vecop_list_sub,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, c, &g[vece]);
}

/* Perform a vector subtraction using normal subtraction and a mask.
   Compare gen_addv_mask above.  */
static void gen_subv_mask(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b, TCGv_i64 m)
{
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t3 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_or_i64(tcg_ctx, t1, a, m);
    tcg_gen_andc_i64(tcg_ctx, t2, b, m);
    tcg_gen_eqv_i64(tcg_ctx, t3, a, b);
    tcg_gen_sub_i64(tcg_ctx, d, t1, t2);
    tcg_gen_and_i64(tcg_ctx, t3, t3, m);
    tcg_gen_xor_i64(tcg_ctx, d, d, t3);

    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
    tcg_temp_free_i64(tcg_ctx, t3);
}

void tcg_gen_vec_sub8_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 m = tcg_const_i64(tcg_ctx, dup_const(MO_8, 0x80));
    gen_subv_mask(tcg_ctx, d, a, b, m);
    tcg_temp_free_i64(tcg_ctx, m);
}

void tcg_gen_vec_sub16_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 m = tcg_const_i64(tcg_ctx, dup_const(MO_16, 0x8000));
    gen_subv_mask(tcg_ctx, d, a, b, m);
    tcg_temp_free_i64(tcg_ctx, m);
}

void tcg_gen_vec_sub32_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, t1, b, ~0xffffffffull);
    tcg_gen_sub_i64(tcg_ctx, t2, a, b);
    tcg_gen_sub_i64(tcg_ctx, t1, a, t1);
    tcg_gen_deposit_i64(tcg_ctx, d, t1, t2, 0, 32);

    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
}

void tcg_gen_gvec_sub(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g[4] = {
        { .fni8 = tcg_gen_vec_sub8_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_gvec_sub8,
          .opt_opc = vecop_list_sub,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_sub16_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_gvec_sub16,
          .opt_opc = vecop_list_sub,
          .vece = MO_16 },
        { .fni4 = tcg_gen_sub_i32,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_gvec_sub32,
          .opt_opc = vecop_list_sub,
          .vece = MO_32 },
        { .fni8 = tcg_gen_sub_i64,
          .fniv = tcg_gen_sub_vec,
          .fno = gen_helper_gvec_sub64,
          .opt_opc = vecop_list_sub,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

static const TCGOpcode vecop_list_mul[] = { INDEX_op_mul_vec, 0 };

void tcg_gen_gvec_mul(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_mul_vec,
          .fno = gen_helper_gvec_mul8,
          .opt_opc = vecop_list_mul,
          .vece = MO_8 },
        { .fniv = tcg_gen_mul_vec,
          .fno = gen_helper_gvec_mul16,
          .opt_opc = vecop_list_mul,
          .vece = MO_16 },
        { .fni4 = tcg_gen_mul_i32,
          .fniv = tcg_gen_mul_vec,
          .fno = gen_helper_gvec_mul32,
          .opt_opc = vecop_list_mul,
          .vece = MO_32 },
        { .fni8 = tcg_gen_mul_i64,
          .fniv = tcg_gen_mul_vec,
          .fno = gen_helper_gvec_mul64,
          .opt_opc = vecop_list_mul,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

void tcg_gen_gvec_muls(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       TCGv_i64 c, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen2s g[4] = {
        { .fniv = tcg_gen_mul_vec,
          .fno = gen_helper_gvec_muls8,
          .opt_opc = vecop_list_mul,
          .vece = MO_8 },
        { .fniv = tcg_gen_mul_vec,
          .fno = gen_helper_gvec_muls16,
          .opt_opc = vecop_list_mul,
          .vece = MO_16 },
        { .fni4 = tcg_gen_mul_i32,
          .fniv = tcg_gen_mul_vec,
          .fno = gen_helper_gvec_muls32,
          .opt_opc = vecop_list_mul,
          .vece = MO_32 },
        { .fni8 = tcg_gen_mul_i64,
          .fniv = tcg_gen_mul_vec,
          .fno = gen_helper_gvec_muls64,
          .opt_opc = vecop_list_mul,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, c, &g[vece]);
}

void tcg_gen_gvec_muli(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       int64_t c, uint32_t oprsz, uint32_t maxsz)
{
    TCGv_i64 tmp = tcg_const_i64(tcg_ctx, c);
    tcg_gen_gvec_muls(tcg_ctx, vece, dofs, aofs, tmp, oprsz, maxsz);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

void tcg_gen_gvec_ssadd(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                        uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_ssadd_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_ssadd_vec,
          .fno = gen_helper_gvec_ssadd8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_ssadd_vec,
          .fno = gen_helper_gvec_ssadd16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fniv = tcg_gen_ssadd_vec,
          .fno = gen_helper_gvec_ssadd32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fniv = tcg_gen_ssadd_vec,
          .fno = gen_helper_gvec_ssadd64,
          .opt_opc = vecop_list,
          .vece = MO_64 },
    };
    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

void tcg_gen_gvec_sssub(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                        uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_sssub_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_sssub_vec,
          .fno = gen_helper_gvec_sssub8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_sssub_vec,
          .fno = gen_helper_gvec_sssub16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fniv = tcg_gen_sssub_vec,
          .fno = gen_helper_gvec_sssub32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fniv = tcg_gen_sssub_vec,
          .fno = gen_helper_gvec_sssub64,
          .opt_opc = vecop_list,
          .vece = MO_64 },
    };
    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

static void tcg_gen_usadd_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 max = tcg_const_i32(tcg_ctx, -1);
    tcg_gen_add_i32(tcg_ctx, d, a, b);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, d, d, a, max, d);
    tcg_temp_free_i32(tcg_ctx, max);
}

static void tcg_gen_usadd_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 max = tcg_const_i64(tcg_ctx, -1);
    tcg_gen_add_i64(tcg_ctx, d, a, b);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, d, d, a, max, d);
    tcg_temp_free_i64(tcg_ctx, max);
}

void tcg_gen_gvec_usadd(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                        uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_usadd_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_usadd_vec,
          .fno = gen_helper_gvec_usadd8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_usadd_vec,
          .fno = gen_helper_gvec_usadd16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_usadd_i32,
          .fniv = tcg_gen_usadd_vec,
          .fno = gen_helper_gvec_usadd32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_usadd_i64,
          .fniv = tcg_gen_usadd_vec,
          .fno = gen_helper_gvec_usadd64,
          .opt_opc = vecop_list,
          .vece = MO_64 }
    };
    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

static void tcg_gen_ussub_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 min = tcg_const_i32(tcg_ctx, 0);
    tcg_gen_sub_i32(tcg_ctx, d, a, b);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, d, a, b, min, d);
    tcg_temp_free_i32(tcg_ctx, min);
}

static void tcg_gen_ussub_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 min = tcg_const_i64(tcg_ctx, 0);
    tcg_gen_sub_i64(tcg_ctx, d, a, b);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, d, a, b, min, d);
    tcg_temp_free_i64(tcg_ctx, min);
}

void tcg_gen_gvec_ussub(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                        uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_ussub_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_ussub_vec,
          .fno = gen_helper_gvec_ussub8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_ussub_vec,
          .fno = gen_helper_gvec_ussub16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_ussub_i32,
          .fniv = tcg_gen_ussub_vec,
          .fno = gen_helper_gvec_ussub32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_ussub_i64,
          .fniv = tcg_gen_ussub_vec,
          .fno = gen_helper_gvec_ussub64,
          .opt_opc = vecop_list,
          .vece = MO_64 }
    };
    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

void tcg_gen_gvec_smin(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_smin_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_smin_vec,
          .fno = gen_helper_gvec_smin8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_smin_vec,
          .fno = gen_helper_gvec_smin16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_smin_i32,
          .fniv = tcg_gen_smin_vec,
          .fno = gen_helper_gvec_smin32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_smin_i64,
          .fniv = tcg_gen_smin_vec,
          .fno = gen_helper_gvec_smin64,
          .opt_opc = vecop_list,
          .vece = MO_64 }
    };
    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

void tcg_gen_gvec_umin(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_umin_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_umin_vec,
          .fno = gen_helper_gvec_umin8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_umin_vec,
          .fno = gen_helper_gvec_umin16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_umin_i32,
          .fniv = tcg_gen_umin_vec,
          .fno = gen_helper_gvec_umin32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_umin_i64,
          .fniv = tcg_gen_umin_vec,
          .fno = gen_helper_gvec_umin64,
          .opt_opc = vecop_list,
          .vece = MO_64 }
    };
    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

void tcg_gen_gvec_smax(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_smax_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_smax_vec,
          .fno = gen_helper_gvec_smax8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_smax_vec,
          .fno = gen_helper_gvec_smax16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_smax_i32,
          .fniv = tcg_gen_smax_vec,
          .fno = gen_helper_gvec_smax32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_smax_i64,
          .fniv = tcg_gen_smax_vec,
          .fno = gen_helper_gvec_smax64,
          .opt_opc = vecop_list,
          .vece = MO_64 }
    };
    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

void tcg_gen_gvec_umax(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_umax_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_umax_vec,
          .fno = gen_helper_gvec_umax8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_umax_vec,
          .fno = gen_helper_gvec_umax16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_umax_i32,
          .fniv = tcg_gen_umax_vec,
          .fno = gen_helper_gvec_umax32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_umax_i64,
          .fniv = tcg_gen_umax_vec,
          .fno = gen_helper_gvec_umax64,
          .opt_opc = vecop_list,
          .vece = MO_64 }
    };
    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

/* Perform a vector negation using normal negation and a mask.
   Compare gen_subv_mask above.  */
static void gen_negv_mask(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 b, TCGv_i64 m)
{
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t3 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andc_i64(tcg_ctx, t3, m, b);
    tcg_gen_andc_i64(tcg_ctx, t2, b, m);
    tcg_gen_sub_i64(tcg_ctx, d, m, t2);
    tcg_gen_xor_i64(tcg_ctx, d, d, t3);

    tcg_temp_free_i64(tcg_ctx, t2);
    tcg_temp_free_i64(tcg_ctx, t3);
}

void tcg_gen_vec_neg8_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 b)
{
    TCGv_i64 m = tcg_const_i64(tcg_ctx, dup_const(MO_8, 0x80));
    gen_negv_mask(tcg_ctx, d, b, m);
    tcg_temp_free_i64(tcg_ctx, m);
}

void tcg_gen_vec_neg16_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 b)
{
    TCGv_i64 m = tcg_const_i64(tcg_ctx, dup_const(MO_16, 0x8000));
    gen_negv_mask(tcg_ctx, d, b, m);
    tcg_temp_free_i64(tcg_ctx, m);
}

void tcg_gen_vec_neg32_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 b)
{
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, t1, b, ~0xffffffffull);
    tcg_gen_neg_i64(tcg_ctx,t2, b);
    tcg_gen_neg_i64(tcg_ctx,t1, t1);
    tcg_gen_deposit_i64(tcg_ctx, d, t1, t2, 0, 32);

    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
}

void tcg_gen_gvec_neg(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_neg_vec, 0 };
    static const GVecGen2 g[4] = {
        { .fni8 = tcg_gen_vec_neg8_i64,
          .fniv = tcg_gen_neg_vec,
          .fno = gen_helper_gvec_neg8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_neg16_i64,
          .fniv = tcg_gen_neg_vec,
          .fno = gen_helper_gvec_neg16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_neg_i32,
          .fniv = tcg_gen_neg_vec,
          .fno = gen_helper_gvec_neg32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_neg_i64,
          .fniv = tcg_gen_neg_vec,
          .fno = gen_helper_gvec_neg64,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_2(tcg_ctx, dofs, aofs, oprsz, maxsz, &g[vece]);
}

static void gen_absv_mask(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 b, unsigned vece)
{
    TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
    int nbit = 8 << vece;

    /* Create -1 for each negative element.  */
    tcg_gen_shri_i64(tcg_ctx, t, b, nbit - 1);
    tcg_gen_andi_i64(tcg_ctx, t, t, dup_const(vece, 1));
    tcg_gen_muli_i64(tcg_ctx, t, t, (1 << nbit) - 1);

    /*
     * Invert (via xor -1) and add one (via sub -1).
     * Because of the ordering the msb is cleared,
     * so we never have carry into the next element.
     */
    tcg_gen_xor_i64(tcg_ctx, d, b, t);
    tcg_gen_sub_i64(tcg_ctx, d, d, t);

    tcg_temp_free_i64(tcg_ctx, t);
}

static void tcg_gen_vec_abs8_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 b)
{
    gen_absv_mask(tcg_ctx, d, b, MO_8);
}

static void tcg_gen_vec_abs16_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 b)
{
    gen_absv_mask(tcg_ctx, d, b, MO_16);
}

void tcg_gen_gvec_abs(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_abs_vec, 0 };
    static const GVecGen2 g[4] = {
        { .fni8 = tcg_gen_vec_abs8_i64,
          .fniv = tcg_gen_abs_vec,
          .fno = gen_helper_gvec_abs8,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_abs16_i64,
          .fniv = tcg_gen_abs_vec,
          .fno = gen_helper_gvec_abs16,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_abs_i32,
          .fniv = tcg_gen_abs_vec,
          .fno = gen_helper_gvec_abs32,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_abs_i64,
          .fniv = tcg_gen_abs_vec,
          .fno = gen_helper_gvec_abs64,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_2(tcg_ctx, dofs, aofs, oprsz, maxsz, &g[vece]);
}

void tcg_gen_gvec_and(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g = {
        .fni8 = tcg_gen_and_i64,
        .fniv = tcg_gen_and_vec,
        .fno = gen_helper_gvec_and,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };

    if (aofs == bofs) {
        tcg_gen_gvec_mov(tcg_ctx, vece, dofs, aofs, oprsz, maxsz);
    } else {
        tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g);
    }
}

void tcg_gen_gvec_or(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                     uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g = {
        .fni8 = tcg_gen_or_i64,
        .fniv = tcg_gen_or_vec,
        .fno = gen_helper_gvec_or,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };

    if (aofs == bofs) {
        tcg_gen_gvec_mov(tcg_ctx, vece, dofs, aofs, oprsz, maxsz);
    } else {
        tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g);
    }
}

void tcg_gen_gvec_xor(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g = {
        .fni8 = tcg_gen_xor_i64,
        .fniv = tcg_gen_xor_vec,
        .fno = gen_helper_gvec_xor,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };

    if (aofs == bofs) {
        tcg_gen_gvec_dup8i(tcg_ctx, dofs, oprsz, maxsz, 0);
    } else {
        tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g);
    }
}

void tcg_gen_gvec_andc(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g = {
        .fni8 = tcg_gen_andc_i64,
        .fniv = tcg_gen_andc_vec,
        .fno = gen_helper_gvec_andc,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };

    if (aofs == bofs) {
        tcg_gen_gvec_dup8i(tcg_ctx, dofs, oprsz, maxsz, 0);
    } else {
        tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g);
    }
}

void tcg_gen_gvec_orc(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g = {
        .fni8 = tcg_gen_orc_i64,
        .fniv = tcg_gen_orc_vec,
        .fno = gen_helper_gvec_orc,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };

    if (aofs == bofs) {
        tcg_gen_gvec_dup8i(tcg_ctx, dofs, oprsz, maxsz, -1);
    } else {
        tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g);
    }
}

void tcg_gen_gvec_nand(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g = {
        .fni8 = tcg_gen_nand_i64,
        .fniv = tcg_gen_nand_vec,
        .fno = gen_helper_gvec_nand,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };

    if (aofs == bofs) {
        tcg_gen_gvec_not(tcg_ctx, vece, dofs, aofs, oprsz, maxsz);
    } else {
        tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g);
    }
}

void tcg_gen_gvec_nor(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g = {
        .fni8 = tcg_gen_nor_i64,
        .fniv = tcg_gen_nor_vec,
        .fno = gen_helper_gvec_nor,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };

    if (aofs == bofs) {
        tcg_gen_gvec_not(tcg_ctx, vece, dofs, aofs, oprsz, maxsz);
    } else {
        tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g);
    }
}

void tcg_gen_gvec_eqv(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen3 g = {
        .fni8 = tcg_gen_eqv_i64,
        .fniv = tcg_gen_eqv_vec,
        .fno = gen_helper_gvec_eqv,
        .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    };

    if (aofs == bofs) {
        tcg_gen_gvec_dup8i(tcg_ctx, dofs, oprsz, maxsz, -1);
    } else {
        tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g);
    }
}

static const GVecGen2s gop_ands = {
    .fni8 = tcg_gen_and_i64,
    .fniv = tcg_gen_and_vec,
    .fno = gen_helper_gvec_ands,
    .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    .vece = MO_64
};

void tcg_gen_gvec_ands(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       TCGv_i64 c, uint32_t oprsz, uint32_t maxsz)
{
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
    gen_dup_i64(tcg_ctx, vece, tmp, c);
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, tmp, &gop_ands);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

void tcg_gen_gvec_andi(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       int64_t c, uint32_t oprsz, uint32_t maxsz)
{
    TCGv_i64 tmp = tcg_const_i64(tcg_ctx, dup_const(vece, c));
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, tmp, &gop_ands);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

static const GVecGen2s gop_xors = {
    .fni8 = tcg_gen_xor_i64,
    .fniv = tcg_gen_xor_vec,
    .fno = gen_helper_gvec_xors,
    .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    .vece = MO_64
};

void tcg_gen_gvec_xors(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       TCGv_i64 c, uint32_t oprsz, uint32_t maxsz)
{
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
    gen_dup_i64(tcg_ctx, vece, tmp, c);
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, tmp, &gop_xors);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

void tcg_gen_gvec_xori(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       int64_t c, uint32_t oprsz, uint32_t maxsz)
{
    TCGv_i64 tmp = tcg_const_i64(tcg_ctx, dup_const(vece, c));
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, tmp, &gop_xors);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

static const GVecGen2s gop_ors = {
    .fni8 = tcg_gen_or_i64,
    .fniv = tcg_gen_or_vec,
    .fno = gen_helper_gvec_ors,
    .prefer_i64 = TCG_TARGET_REG_BITS == 64,
    .vece = MO_64
};

void tcg_gen_gvec_ors(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      TCGv_i64 c, uint32_t oprsz, uint32_t maxsz)
{
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
    gen_dup_i64(tcg_ctx, vece, tmp, c);
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, tmp, &gop_ors);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

void tcg_gen_gvec_ori(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                      int64_t c, uint32_t oprsz, uint32_t maxsz)
{
    TCGv_i64 tmp = tcg_const_i64(tcg_ctx, dup_const(vece, c));
    tcg_gen_gvec_2s(tcg_ctx, dofs, aofs, oprsz, maxsz, tmp, &gop_ors);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

void tcg_gen_vec_shl8i_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, int64_t c)
{
    uint64_t mask = dup_const(MO_8, 0xff << c);
    tcg_gen_shli_i64(tcg_ctx, d, a, c);
    tcg_gen_andi_i64(tcg_ctx, d, d, mask);
}

void tcg_gen_vec_shl16i_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, int64_t c)
{
    uint64_t mask = dup_const(MO_16, 0xffff << c);
    tcg_gen_shli_i64(tcg_ctx, d, a, c);
    tcg_gen_andi_i64(tcg_ctx, d, d, mask);
}

void tcg_gen_gvec_shli(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       int64_t shift, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_shli_vec, 0 };
    static const GVecGen2i g[4] = {
        { .fni8 = tcg_gen_vec_shl8i_i64,
          .fniv = tcg_gen_shli_vec,
          .fno = gen_helper_gvec_shl8i,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_shl16i_i64,
          .fniv = tcg_gen_shli_vec,
          .fno = gen_helper_gvec_shl16i,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_shli_i32,
          .fniv = tcg_gen_shli_vec,
          .fno = gen_helper_gvec_shl32i,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_shli_i64,
          .fniv = tcg_gen_shli_vec,
          .fno = gen_helper_gvec_shl64i,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_debug_assert(shift >= 0 && shift < (8 << vece));
    if (shift == 0) {
        tcg_gen_gvec_mov(tcg_ctx, vece, dofs, aofs, oprsz, maxsz);
    } else {
        tcg_gen_gvec_2i(tcg_ctx, dofs, aofs, oprsz, maxsz, shift, &g[vece]);
    }
}

void tcg_gen_vec_shr8i_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, int64_t c)
{
    uint64_t mask = dup_const(MO_8, 0xff >> c);
    tcg_gen_shri_i64(tcg_ctx, d, a, c);
    tcg_gen_andi_i64(tcg_ctx, d, d, mask);
}

void tcg_gen_vec_shr16i_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, int64_t c)
{
    uint64_t mask = dup_const(MO_16, 0xffff >> c);
    tcg_gen_shri_i64(tcg_ctx, d, a, c);
    tcg_gen_andi_i64(tcg_ctx, d, d, mask);
}

void tcg_gen_gvec_shri(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       int64_t shift, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_shri_vec, 0 };
    static const GVecGen2i g[4] = {
        { .fni8 = tcg_gen_vec_shr8i_i64,
          .fniv = tcg_gen_shri_vec,
          .fno = gen_helper_gvec_shr8i,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_shr16i_i64,
          .fniv = tcg_gen_shri_vec,
          .fno = gen_helper_gvec_shr16i,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_shri_i32,
          .fniv = tcg_gen_shri_vec,
          .fno = gen_helper_gvec_shr32i,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_shri_i64,
          .fniv = tcg_gen_shri_vec,
          .fno = gen_helper_gvec_shr64i,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_debug_assert(shift >= 0 && shift < (8 << vece));
    if (shift == 0) {
        tcg_gen_gvec_mov(tcg_ctx, vece, dofs, aofs, oprsz, maxsz);
    } else {
        tcg_gen_gvec_2i(tcg_ctx, dofs, aofs, oprsz, maxsz, shift, &g[vece]);
    }
}

void tcg_gen_vec_sar8i_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, int64_t c)
{
    uint64_t s_mask = dup_const(MO_8, 0x80 >> c);
    uint64_t c_mask = dup_const(MO_8, 0xff >> c);
    TCGv_i64 s = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_shri_i64(tcg_ctx, d, a, c);
    tcg_gen_andi_i64(tcg_ctx, s, d, s_mask);  /* isolate (shifted) sign bit */
    tcg_gen_muli_i64(tcg_ctx, s, s, (2 << c) - 2); /* replicate isolated signs */
    tcg_gen_andi_i64(tcg_ctx, d, d, c_mask);  /* clear out bits above sign  */
    tcg_gen_or_i64(tcg_ctx, d, d, s);         /* include sign extension */
    tcg_temp_free_i64(tcg_ctx, s);
}

void tcg_gen_vec_sar16i_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, int64_t c)
{
    uint64_t s_mask = dup_const(MO_16, 0x8000 >> c);
    uint64_t c_mask = dup_const(MO_16, 0xffff >> c);
    TCGv_i64 s = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_shri_i64(tcg_ctx, d, a, c);
    tcg_gen_andi_i64(tcg_ctx, s, d, s_mask);  /* isolate (shifted) sign bit */
    tcg_gen_andi_i64(tcg_ctx, d, d, c_mask);  /* clear out bits above sign  */
    tcg_gen_muli_i64(tcg_ctx, s, s, (2 << c) - 2); /* replicate isolated signs */
    tcg_gen_or_i64(tcg_ctx, d, d, s);         /* include sign extension */
    tcg_temp_free_i64(tcg_ctx, s);
}

void tcg_gen_gvec_sari(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       int64_t shift, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_sari_vec, 0 };
    static const GVecGen2i g[4] = {
        { .fni8 = tcg_gen_vec_sar8i_i64,
          .fniv = tcg_gen_sari_vec,
          .fno = gen_helper_gvec_sar8i,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fni8 = tcg_gen_vec_sar16i_i64,
          .fniv = tcg_gen_sari_vec,
          .fno = gen_helper_gvec_sar16i,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_sari_i32,
          .fniv = tcg_gen_sari_vec,
          .fno = gen_helper_gvec_sar32i,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_sari_i64,
          .fniv = tcg_gen_sari_vec,
          .fno = gen_helper_gvec_sar64i,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_debug_assert(shift >= 0 && shift < (8 << vece));
    if (shift == 0) {
        tcg_gen_gvec_mov(tcg_ctx, vece, dofs, aofs, oprsz, maxsz);
    } else {
        tcg_gen_gvec_2i(tcg_ctx, dofs, aofs, oprsz, maxsz, shift, &g[vece]);
    }
}

/*
 * Specialized generation vector shifts by a non-constant scalar.
 */

typedef struct {
    void (*fni4)(TCGContext *, TCGv_i32, TCGv_i32, TCGv_i32);
    void (*fni8)(TCGContext *, TCGv_i64, TCGv_i64, TCGv_i64);
    void (*fniv_s)(TCGContext *, unsigned, TCGv_vec, TCGv_vec, TCGv_i32);
    void (*fniv_v)(TCGContext *, unsigned, TCGv_vec, TCGv_vec, TCGv_vec);
    gen_helper_gvec_2 *fno[4];
    TCGOpcode s_list[2];
    TCGOpcode v_list[2];
} GVecGen2sh;

static void expand_2sh_vec(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                           uint32_t oprsz, uint32_t tysz, TCGType type,
                           TCGv_i32 shift,
                           void (*fni)(TCGContext *, unsigned, TCGv_vec, TCGv_vec, TCGv_i32))
{
    TCGv_vec t0 = tcg_temp_new_vec(tcg_ctx, type);
    uint32_t i;

    for (i = 0; i < oprsz; i += tysz) {
        tcg_gen_ld_vec(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        fni(tcg_ctx, vece, t0, t0, shift);
        tcg_gen_st_vec(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_vec(tcg_ctx, t0);
}

static void
do_gvec_shifts(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs, TCGv_i32 shift,
               uint32_t oprsz, uint32_t maxsz, const GVecGen2sh *g)
{
    TCGType type;
    uint32_t some;

    check_size_align(oprsz, maxsz, dofs | aofs);
    check_overlap_2(dofs, aofs, maxsz);

    /* If the backend has a scalar expansion, great.  */
    type = choose_vector_type(tcg_ctx, g->s_list, vece, oprsz, vece == MO_64);
    if (type) {
        const TCGOpcode *hold_list = tcg_swap_vecop_list(NULL);
        switch (type) {
        case TCG_TYPE_V256:
            some = QEMU_ALIGN_DOWN(oprsz, 32);
            expand_2sh_vec(tcg_ctx, vece, dofs, aofs, some, 32,
                           TCG_TYPE_V256, shift, g->fniv_s);
            if (some == oprsz) {
                break;
            }
            dofs += some;
            aofs += some;
            oprsz -= some;
            maxsz -= some;
            /* fallthru */
        case TCG_TYPE_V128:
            expand_2sh_vec(tcg_ctx, vece, dofs, aofs, oprsz, 16,
                           TCG_TYPE_V128, shift, g->fniv_s);
            break;
        case TCG_TYPE_V64:
            expand_2sh_vec(tcg_ctx, vece, dofs, aofs, oprsz, 8,
                           TCG_TYPE_V64, shift, g->fniv_s);
            break;
        default:
            g_assert_not_reached();
        }
        tcg_swap_vecop_list(hold_list);
        goto clear_tail;
    }

    /* If the backend supports variable vector shifts, also cool.  */
    type = choose_vector_type(tcg_ctx, g->v_list, vece, oprsz, vece == MO_64);
    if (type) {
        const TCGOpcode *hold_list = tcg_swap_vecop_list(NULL);
        TCGv_vec v_shift = tcg_temp_new_vec(tcg_ctx, type);

        if (vece == MO_64) {
            TCGv_i64 sh64 = tcg_temp_new_i64(tcg_ctx);
            tcg_gen_extu_i32_i64(tcg_ctx, sh64, shift);
            tcg_gen_dup_i64_vec(tcg_ctx, MO_64, v_shift, sh64);
            tcg_temp_free_i64(tcg_ctx, sh64);
        } else {
            tcg_gen_dup_i32_vec(tcg_ctx, vece, v_shift, shift);
        }

        switch (type) {
        case TCG_TYPE_V256:
            some = QEMU_ALIGN_DOWN(oprsz, 32);
            expand_2s_vec(tcg_ctx, vece, dofs, aofs, some, 32, TCG_TYPE_V256,
                          v_shift, false, g->fniv_v);
            if (some == oprsz) {
                break;
            }
            dofs += some;
            aofs += some;
            oprsz -= some;
            maxsz -= some;
            /* fallthru */
        case TCG_TYPE_V128:
            expand_2s_vec(tcg_ctx, vece, dofs, aofs, oprsz, 16, TCG_TYPE_V128,
                          v_shift, false, g->fniv_v);
            break;
        case TCG_TYPE_V64:
            expand_2s_vec(tcg_ctx, vece, dofs, aofs, oprsz, 8, TCG_TYPE_V64,
                          v_shift, false, g->fniv_v);
            break;
        default:
            g_assert_not_reached();
        }
        tcg_temp_free_vec(tcg_ctx, v_shift);
        tcg_swap_vecop_list(hold_list);
        goto clear_tail;
    }

    /* Otherwise fall back to integral... */
    if (vece == MO_32 && check_size_impl(oprsz, 4)) {
        expand_2s_i32(tcg_ctx, dofs, aofs, oprsz, shift, false, g->fni4);
    } else if (vece == MO_64 && check_size_impl(oprsz, 8)) {
        TCGv_i64 sh64 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_extu_i32_i64(tcg_ctx, sh64, shift);
        expand_2s_i64(tcg_ctx, dofs, aofs, oprsz, sh64, false, g->fni8);
        tcg_temp_free_i64(tcg_ctx, sh64);
    } else {
        TCGv_ptr a0 = tcg_temp_new_ptr(tcg_ctx);
        TCGv_ptr a1 = tcg_temp_new_ptr(tcg_ctx);
        TCGv_i32 desc = tcg_temp_new_i32(tcg_ctx);

        tcg_gen_shli_i32(tcg_ctx, desc, shift, SIMD_DATA_SHIFT);
        tcg_gen_ori_i32(tcg_ctx, desc, desc, simd_desc(oprsz, maxsz, 0));
        tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, dofs);
        tcg_gen_addi_ptr(tcg_ctx, a1, tcg_ctx->cpu_env, aofs);

        g->fno[vece](tcg_ctx, a0, a1, desc);

        tcg_temp_free_ptr(tcg_ctx, a0);
        tcg_temp_free_ptr(tcg_ctx, a1);
        tcg_temp_free_i32(tcg_ctx, desc);
        return;
    }

 clear_tail:
    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

void tcg_gen_gvec_shls(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       TCGv_i32 shift, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen2sh g = {
        .fni4 = tcg_gen_shl_i32,
        .fni8 = tcg_gen_shl_i64,
        .fniv_s = tcg_gen_shls_vec,
        .fniv_v = tcg_gen_shlv_vec,
        .fno = {
            gen_helper_gvec_shl8i,
            gen_helper_gvec_shl16i,
            gen_helper_gvec_shl32i,
            gen_helper_gvec_shl64i,
        },
        .s_list = { INDEX_op_shls_vec, 0 },
        .v_list = { INDEX_op_shlv_vec, 0 },
    };

    tcg_debug_assert(vece <= MO_64);
    do_gvec_shifts(tcg_ctx, vece, dofs, aofs, shift, oprsz, maxsz, &g);
}

void tcg_gen_gvec_shrs(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       TCGv_i32 shift, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen2sh g = {
        .fni4 = tcg_gen_shr_i32,
        .fni8 = tcg_gen_shr_i64,
        .fniv_s = tcg_gen_shrs_vec,
        .fniv_v = tcg_gen_shrv_vec,
        .fno = {
            gen_helper_gvec_shr8i,
            gen_helper_gvec_shr16i,
            gen_helper_gvec_shr32i,
            gen_helper_gvec_shr64i,
        },
        .s_list = { INDEX_op_shrs_vec, 0 },
        .v_list = { INDEX_op_shrv_vec, 0 },
    };

    tcg_debug_assert(vece <= MO_64);
    do_gvec_shifts(tcg_ctx, vece, dofs, aofs, shift, oprsz, maxsz, &g);
}

void tcg_gen_gvec_sars(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       TCGv_i32 shift, uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen2sh g = {
        .fni4 = tcg_gen_sar_i32,
        .fni8 = tcg_gen_sar_i64,
        .fniv_s = tcg_gen_sars_vec,
        .fniv_v = tcg_gen_sarv_vec,
        .fno = {
            gen_helper_gvec_sar8i,
            gen_helper_gvec_sar16i,
            gen_helper_gvec_sar32i,
            gen_helper_gvec_sar64i,
        },
        .s_list = { INDEX_op_sars_vec, 0 },
        .v_list = { INDEX_op_sarv_vec, 0 },
    };

    tcg_debug_assert(vece <= MO_64);
    do_gvec_shifts(tcg_ctx, vece, dofs, aofs, shift, oprsz, maxsz, &g);
}

/*
 * Expand D = A << (B % element bits)
 *
 * Unlike scalar shifts, where it is easy for the target front end
 * to include the modulo as part of the expansion.  If the target
 * naturally includes the modulo as part of the operation, great!
 * If the target has some other behaviour from out-of-range shifts,
 * then it could not use this function anyway, and would need to
 * do it's own expansion with custom functions.
 */
static void tcg_gen_shlv_mod_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec d,
                                 TCGv_vec a, TCGv_vec b)
{
    TCGv_vec t = tcg_temp_new_vec_matching(tcg_ctx, d);

    tcg_gen_dupi_vec(tcg_ctx, vece, t, (8 << vece) - 1);
    tcg_gen_and_vec(tcg_ctx, vece, t, t, b);
    tcg_gen_shlv_vec(tcg_ctx, vece, d, a, t);
    tcg_temp_free_vec(tcg_ctx, t);
}

static void tcg_gen_shl_mod_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_andi_i32(tcg_ctx, t, b, 31);
    tcg_gen_shl_i32(tcg_ctx, d, a, t);
    tcg_temp_free_i32(tcg_ctx, t);
}

static void tcg_gen_shl_mod_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, t, b, 63);
    tcg_gen_shl_i64(tcg_ctx, d, a, t);
    tcg_temp_free_i64(tcg_ctx, t);
}

void tcg_gen_gvec_shlv(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_shlv_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_shlv_mod_vec,
          .fno = gen_helper_gvec_shl8v,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_shlv_mod_vec,
          .fno = gen_helper_gvec_shl16v,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_shl_mod_i32,
          .fniv = tcg_gen_shlv_mod_vec,
          .fno = gen_helper_gvec_shl32v,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_shl_mod_i64,
          .fniv = tcg_gen_shlv_mod_vec,
          .fno = gen_helper_gvec_shl64v,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

/*
 * Similarly for logical right shifts.
 */

static void tcg_gen_shrv_mod_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec d,
                                 TCGv_vec a, TCGv_vec b)
{
    TCGv_vec t = tcg_temp_new_vec_matching(tcg_ctx, d);

    tcg_gen_dupi_vec(tcg_ctx, vece, t, (8 << vece) - 1);
    tcg_gen_and_vec(tcg_ctx, vece, t, t, b);
    tcg_gen_shrv_vec(tcg_ctx, vece, d, a, t);
    tcg_temp_free_vec(tcg_ctx, t);
}

static void tcg_gen_shr_mod_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_andi_i32(tcg_ctx, t, b, 31);
    tcg_gen_shr_i32(tcg_ctx, d, a, t);
    tcg_temp_free_i32(tcg_ctx, t);
}

static void tcg_gen_shr_mod_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, t, b, 63);
    tcg_gen_shr_i64(tcg_ctx, d, a, t);
    tcg_temp_free_i64(tcg_ctx, t);
}

void tcg_gen_gvec_shrv(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_shrv_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_shrv_mod_vec,
          .fno = gen_helper_gvec_shr8v,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_shrv_mod_vec,
          .fno = gen_helper_gvec_shr16v,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_shr_mod_i32,
          .fniv = tcg_gen_shrv_mod_vec,
          .fno = gen_helper_gvec_shr32v,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_shr_mod_i64,
          .fniv = tcg_gen_shrv_mod_vec,
          .fno = gen_helper_gvec_shr64v,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

/*
 * Similarly for arithmetic right shifts.
 */

static void tcg_gen_sarv_mod_vec(TCGContext *tcg_ctx, unsigned vece, TCGv_vec d,
                                 TCGv_vec a, TCGv_vec b)
{
    TCGv_vec t = tcg_temp_new_vec_matching(tcg_ctx, d);

    tcg_gen_dupi_vec(tcg_ctx, vece, t, (8 << vece) - 1);
    tcg_gen_and_vec(tcg_ctx, vece, t, t, b);
    tcg_gen_sarv_vec(tcg_ctx, vece, d, a, t);
    tcg_temp_free_vec(tcg_ctx, t);
}

static void tcg_gen_sar_mod_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_andi_i32(tcg_ctx, t, b, 31);
    tcg_gen_sar_i32(tcg_ctx, d, a, t);
    tcg_temp_free_i32(tcg_ctx, t);
}

static void tcg_gen_sar_mod_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, t, b, 63);
    tcg_gen_sar_i64(tcg_ctx, d, a, t);
    tcg_temp_free_i64(tcg_ctx, t);
}

void tcg_gen_gvec_sarv(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                       uint32_t bofs, uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode vecop_list[] = { INDEX_op_sarv_vec, 0 };
    static const GVecGen3 g[4] = {
        { .fniv = tcg_gen_sarv_mod_vec,
          .fno = gen_helper_gvec_sar8v,
          .opt_opc = vecop_list,
          .vece = MO_8 },
        { .fniv = tcg_gen_sarv_mod_vec,
          .fno = gen_helper_gvec_sar16v,
          .opt_opc = vecop_list,
          .vece = MO_16 },
        { .fni4 = tcg_gen_sar_mod_i32,
          .fniv = tcg_gen_sarv_mod_vec,
          .fno = gen_helper_gvec_sar32v,
          .opt_opc = vecop_list,
          .vece = MO_32 },
        { .fni8 = tcg_gen_sar_mod_i64,
          .fniv = tcg_gen_sarv_mod_vec,
          .fno = gen_helper_gvec_sar64v,
          .opt_opc = vecop_list,
          .prefer_i64 = TCG_TARGET_REG_BITS == 64,
          .vece = MO_64 },
    };

    tcg_debug_assert(vece <= MO_64);
    tcg_gen_gvec_3(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, &g[vece]);
}

/* Expand OPSZ bytes worth of three-operand operations using i32 elements.  */
static void expand_cmp_i32(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                           uint32_t oprsz, TCGCond cond)
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 4) {
        tcg_gen_ld_i32(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_i32(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        tcg_gen_setcond_i32(tcg_ctx, cond, t0, t0, t1);
        tcg_gen_neg_i32(tcg_ctx, t0, t0);
        tcg_gen_st_i32(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i32(tcg_ctx, t1);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void expand_cmp_i64(TCGContext *tcg_ctx, uint32_t dofs, uint32_t aofs, uint32_t bofs,
                           uint32_t oprsz, TCGCond cond)
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    uint32_t i;

    for (i = 0; i < oprsz; i += 8) {
        tcg_gen_ld_i64(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_i64(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        tcg_gen_setcond_i64(tcg_ctx,cond, t0, t0, t1);
        tcg_gen_neg_i64(tcg_ctx,t0, t0);
        tcg_gen_st_i64(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void expand_cmp_vec(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                           uint32_t bofs, uint32_t oprsz, uint32_t tysz,
                           TCGType type, TCGCond cond)
{
    TCGv_vec t0 = tcg_temp_new_vec(tcg_ctx, type);
    TCGv_vec t1 = tcg_temp_new_vec(tcg_ctx, type);
    uint32_t i;

    for (i = 0; i < oprsz; i += tysz) {
        tcg_gen_ld_vec(tcg_ctx, t0, tcg_ctx->cpu_env, aofs + i);
        tcg_gen_ld_vec(tcg_ctx, t1, tcg_ctx->cpu_env, bofs + i);
        tcg_gen_cmp_vec(tcg_ctx, cond, vece, t0, t0, t1);
        tcg_gen_st_vec(tcg_ctx, t0, tcg_ctx->cpu_env, dofs + i);
    }
    tcg_temp_free_vec(tcg_ctx, t1);
    tcg_temp_free_vec(tcg_ctx, t0);
}

void tcg_gen_gvec_cmp(TCGContext *tcg_ctx, TCGCond cond, unsigned vece, uint32_t dofs,
                      uint32_t aofs, uint32_t bofs,
                      uint32_t oprsz, uint32_t maxsz)
{
    static const TCGOpcode cmp_list[] = { INDEX_op_cmp_vec, 0 };
    static gen_helper_gvec_3 * const eq_fn[4] = {
        gen_helper_gvec_eq8, gen_helper_gvec_eq16,
        gen_helper_gvec_eq32, gen_helper_gvec_eq64
    };
    static gen_helper_gvec_3 * const ne_fn[4] = {
        gen_helper_gvec_ne8, gen_helper_gvec_ne16,
        gen_helper_gvec_ne32, gen_helper_gvec_ne64
    };
    static gen_helper_gvec_3 * const lt_fn[4] = {
        gen_helper_gvec_lt8, gen_helper_gvec_lt16,
        gen_helper_gvec_lt32, gen_helper_gvec_lt64
    };
    static gen_helper_gvec_3 * const le_fn[4] = {
        gen_helper_gvec_le8, gen_helper_gvec_le16,
        gen_helper_gvec_le32, gen_helper_gvec_le64
    };
    static gen_helper_gvec_3 * const ltu_fn[4] = {
        gen_helper_gvec_ltu8, gen_helper_gvec_ltu16,
        gen_helper_gvec_ltu32, gen_helper_gvec_ltu64
    };
    static gen_helper_gvec_3 * const leu_fn[4] = {
        gen_helper_gvec_leu8, gen_helper_gvec_leu16,
        gen_helper_gvec_leu32, gen_helper_gvec_leu64
    };
    static gen_helper_gvec_3 * const * const fns[16] = {
        [TCG_COND_EQ] = eq_fn,
        [TCG_COND_NE] = ne_fn,
        [TCG_COND_LT] = lt_fn,
        [TCG_COND_LE] = le_fn,
        [TCG_COND_LTU] = ltu_fn,
        [TCG_COND_LEU] = leu_fn,
    };

    const TCGOpcode *hold_list;
    TCGType type;
    uint32_t some;

    check_size_align(oprsz, maxsz, dofs | aofs | bofs);
    check_overlap_3(dofs, aofs, bofs, maxsz);

    if (cond == TCG_COND_NEVER || cond == TCG_COND_ALWAYS) {
        do_dup(tcg_ctx, MO_8, dofs, oprsz, maxsz,
               NULL, NULL, -(cond == TCG_COND_ALWAYS));
        return;
    }

    /*
     * Implement inline with a vector type, if possible.
     * Prefer integer when 64-bit host and 64-bit comparison.
     */
    hold_list = tcg_swap_vecop_list(cmp_list);
    type = choose_vector_type(tcg_ctx, cmp_list, vece, oprsz,
                              TCG_TARGET_REG_BITS == 64 && vece == MO_64);
    switch (type) {
    case TCG_TYPE_V256:
        /* Recall that ARM SVE allows vector sizes that are not a
         * power of 2, but always a multiple of 16.  The intent is
         * that e.g. size == 80 would be expanded with 2x32 + 1x16.
         */
        some = QEMU_ALIGN_DOWN(oprsz, 32);
        expand_cmp_vec(tcg_ctx, vece, dofs, aofs, bofs, some, 32, TCG_TYPE_V256, cond);
        if (some == oprsz) {
            break;
        }
        dofs += some;
        aofs += some;
        bofs += some;
        oprsz -= some;
        maxsz -= some;
        /* fallthru */
    case TCG_TYPE_V128:
        expand_cmp_vec(tcg_ctx, vece, dofs, aofs, bofs, oprsz, 16, TCG_TYPE_V128, cond);
        break;
    case TCG_TYPE_V64:
        expand_cmp_vec(tcg_ctx, vece, dofs, aofs, bofs, oprsz, 8, TCG_TYPE_V64, cond);
        break;

    case 0:
        if (vece == MO_64 && check_size_impl(oprsz, 8)) {
            expand_cmp_i64(tcg_ctx, dofs, aofs, bofs, oprsz, cond);
        } else if (vece == MO_32 && check_size_impl(oprsz, 4)) {
            expand_cmp_i32(tcg_ctx, dofs, aofs, bofs, oprsz, cond);
        } else {
            gen_helper_gvec_3 * const *fn = fns[cond];

            if (fn == NULL) {
                uint32_t tmp;
                tmp = aofs, aofs = bofs, bofs = tmp;
                cond = tcg_swap_cond(cond);
                fn = fns[cond];
                assert(fn != NULL);
            }
            tcg_gen_gvec_3_ool(tcg_ctx, dofs, aofs, bofs, oprsz, maxsz, 0, fn[vece]);
            oprsz = maxsz;
        }
        break;

    default:
        g_assert_not_reached();
    }
    tcg_swap_vecop_list(hold_list);

    if (oprsz < maxsz) {
        expand_clr(tcg_ctx, dofs + oprsz, maxsz - oprsz);
    }
}

static void tcg_gen_bitsel_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c)
{
    TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_and_i64(tcg_ctx, t, b, a);
    tcg_gen_andc_i64(tcg_ctx, d, c, a);
    tcg_gen_or_i64(tcg_ctx, d, d, t);
    tcg_temp_free_i64(tcg_ctx, t);
}

void tcg_gen_gvec_bitsel(TCGContext *tcg_ctx, unsigned vece, uint32_t dofs, uint32_t aofs,
                         uint32_t bofs, uint32_t cofs,
                         uint32_t oprsz, uint32_t maxsz)
{
    static const GVecGen4 g = {
        .fni8 = tcg_gen_bitsel_i64,
        .fniv = tcg_gen_bitsel_vec,
        .fno = gen_helper_gvec_bitsel,
    };

    tcg_gen_gvec_4(tcg_ctx, dofs, aofs, bofs, cofs, oprsz, maxsz, &g);
}
