/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "tcg.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

/* Basic output routines.  Not for general consumption.  */
void tcg_gen_op1(TCGContext *, TCGOpcode, TCGArg);
void tcg_gen_op2(TCGContext *, TCGOpcode, TCGArg, TCGArg);
void tcg_gen_op3(TCGContext *, TCGOpcode, TCGArg, TCGArg, TCGArg);
void tcg_gen_op4(TCGContext *, TCGOpcode, TCGArg, TCGArg, TCGArg, TCGArg);
void tcg_gen_op5(TCGContext *, TCGOpcode, TCGArg, TCGArg, TCGArg,
                 TCGArg, TCGArg);
void tcg_gen_op6(TCGContext *, TCGOpcode, TCGArg, TCGArg, TCGArg,
                 TCGArg, TCGArg, TCGArg);

static inline void gen_uc_tracecode(TCGContext *tcg_ctx, int32_t size, int32_t type, void *uc, uint64_t pc)
{
    TCGv_i32 tsize = tcg_const_i32(tcg_ctx, size);
    TCGv_i32 ttype = tcg_const_i32(tcg_ctx, type);
    TCGv_ptr tuc = tcg_const_ptr(tcg_ctx, uc);
    TCGv_i64 tpc = tcg_const_i64(tcg_ctx, pc);
    gen_helper_uc_tracecode(tcg_ctx, tsize, ttype, tuc, tpc);
}

static inline void tcg_gen_op1_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1)
{
    tcg_gen_op1(s, opc, GET_TCGV_I32(a1));
}

static inline void tcg_gen_op1_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1)
{
    tcg_gen_op1(s, opc, GET_TCGV_I64(a1));
}

static inline void tcg_gen_op1i(TCGContext *s, TCGOpcode opc, TCGArg a1)
{
    tcg_gen_op1(s, opc, a1);
}

static inline void tcg_gen_op2_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2)
{
    tcg_gen_op2(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2));
}

static inline void tcg_gen_op2_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2)
{
    tcg_gen_op2(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2));
}

static inline void tcg_gen_op2i_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGArg a2)
{
    tcg_gen_op2(s, opc, GET_TCGV_I32(a1), a2);
}

static inline void tcg_gen_op2i_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGArg a2)
{
    tcg_gen_op2(s, opc, GET_TCGV_I64(a1), a2);
}

static inline void tcg_gen_op2ii(TCGContext *s, TCGOpcode opc, TCGArg a1, TCGArg a2)
{
    tcg_gen_op2(s, opc, a1, a2);
}

static inline void tcg_gen_op3_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                   TCGv_i32 a3)
{
    tcg_gen_op3(s, opc, GET_TCGV_I32(a1),
                GET_TCGV_I32(a2), GET_TCGV_I32(a3));
}

static inline void tcg_gen_op3_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                   TCGv_i64 a3)
{
    tcg_gen_op3(s, opc, GET_TCGV_I64(a1),
                GET_TCGV_I64(a2), GET_TCGV_I64(a3));
}

static inline void tcg_gen_op3i_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1,
                                    TCGv_i32 a2, TCGArg a3)
{
    tcg_gen_op3(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2), a3);
}

static inline void tcg_gen_op3i_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1,
                                    TCGv_i64 a2, TCGArg a3)
{
    tcg_gen_op3(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2), a3);
}

static inline void tcg_gen_ldst_op_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 val,
                                       TCGv_ptr base, TCGArg offset)
{
    tcg_gen_op3(s, opc, GET_TCGV_I32(val), GET_TCGV_PTR(base), offset);
}

static inline void tcg_gen_ldst_op_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 val,
                                       TCGv_ptr base, TCGArg offset)
{
    tcg_gen_op3(s, opc, GET_TCGV_I64(val), GET_TCGV_PTR(base), offset);
}

static inline void tcg_gen_op4_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                   TCGv_i32 a3, TCGv_i32 a4)
{
    tcg_gen_op4(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2),
                GET_TCGV_I32(a3), GET_TCGV_I32(a4));
}

static inline void tcg_gen_op4_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                   TCGv_i64 a3, TCGv_i64 a4)
{
    tcg_gen_op4(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2),
                GET_TCGV_I64(a3), GET_TCGV_I64(a4));
}

static inline void tcg_gen_op4i_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                    TCGv_i32 a3, TCGArg a4)
{
    tcg_gen_op4(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2),
                GET_TCGV_I32(a3), a4);
}

static inline void tcg_gen_op4i_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                    TCGv_i64 a3, TCGArg a4)
{
    tcg_gen_op4(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2),
                GET_TCGV_I64(a3), a4);
}

static inline void tcg_gen_op4ii_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                     TCGArg a3, TCGArg a4)
{
    tcg_gen_op4(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2), a3, a4);
}

static inline void tcg_gen_op4ii_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                     TCGArg a3, TCGArg a4)
{
    tcg_gen_op4(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2), a3, a4);
}

static inline void tcg_gen_op5_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                   TCGv_i32 a3, TCGv_i32 a4, TCGv_i32 a5)
{
    tcg_gen_op5(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2),
                GET_TCGV_I32(a3), GET_TCGV_I32(a4), GET_TCGV_I32(a5));
}

static inline void tcg_gen_op5_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                   TCGv_i64 a3, TCGv_i64 a4, TCGv_i64 a5)
{
    tcg_gen_op5(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2),
                GET_TCGV_I64(a3), GET_TCGV_I64(a4), GET_TCGV_I64(a5));
}

static inline void tcg_gen_op5i_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                    TCGv_i32 a3, TCGv_i32 a4, TCGArg a5)
{
    tcg_gen_op5(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2),
                GET_TCGV_I32(a3), GET_TCGV_I32(a4), a5);
}

static inline void tcg_gen_op5i_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                    TCGv_i64 a3, TCGv_i64 a4, TCGArg a5)
{
    tcg_gen_op5(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2),
                GET_TCGV_I64(a3), GET_TCGV_I64(a4), a5);
}

static inline void tcg_gen_op5ii_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1,
                                     TCGv_i32 a2, TCGv_i32 a3,
                                     TCGArg a4, TCGArg a5)
{
    tcg_gen_op5(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2),
                GET_TCGV_I32(a3), a4, a5);
}

static inline void tcg_gen_op5ii_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1,
                                     TCGv_i64 a2, TCGv_i64 a3,
                                     TCGArg a4, TCGArg a5)
{
    tcg_gen_op5(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2),
                GET_TCGV_I64(a3), a4, a5);
}

static inline void tcg_gen_op6_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                   TCGv_i32 a3, TCGv_i32 a4, TCGv_i32 a5,
                                   TCGv_i32 a6)
{
    tcg_gen_op6(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2),
                GET_TCGV_I32(a3), GET_TCGV_I32(a4), GET_TCGV_I32(a5),
                GET_TCGV_I32(a6));
}

static inline void tcg_gen_op6_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                   TCGv_i64 a3, TCGv_i64 a4, TCGv_i64 a5,
                                   TCGv_i64 a6)
{
    tcg_gen_op6(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2),
                GET_TCGV_I64(a3), GET_TCGV_I64(a4), GET_TCGV_I64(a5),
                GET_TCGV_I64(a6));
}

static inline void tcg_gen_op6i_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1, TCGv_i32 a2,
                                    TCGv_i32 a3, TCGv_i32 a4,
                                    TCGv_i32 a5, TCGArg a6)
{
    tcg_gen_op6(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2),
                GET_TCGV_I32(a3), GET_TCGV_I32(a4), GET_TCGV_I32(a5), a6);
}

static inline void tcg_gen_op6i_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1, TCGv_i64 a2,
                                    TCGv_i64 a3, TCGv_i64 a4,
                                    TCGv_i64 a5, TCGArg a6)
{
    tcg_gen_op6(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2),
                GET_TCGV_I64(a3), GET_TCGV_I64(a4), GET_TCGV_I64(a5), a6);
}

static inline void tcg_gen_op6ii_i32(TCGContext *s, TCGOpcode opc, TCGv_i32 a1,
                                     TCGv_i32 a2, TCGv_i32 a3,
                                     TCGv_i32 a4, TCGArg a5, TCGArg a6)
{
    tcg_gen_op6(s, opc, GET_TCGV_I32(a1), GET_TCGV_I32(a2),
                GET_TCGV_I32(a3), GET_TCGV_I32(a4), a5, a6);
}

static inline void tcg_gen_op6ii_i64(TCGContext *s, TCGOpcode opc, TCGv_i64 a1,
                                     TCGv_i64 a2, TCGv_i64 a3,
                                     TCGv_i64 a4, TCGArg a5, TCGArg a6)
{
    tcg_gen_op6(s, opc, GET_TCGV_I64(a1), GET_TCGV_I64(a2),
                GET_TCGV_I64(a3), GET_TCGV_I64(a4), a5, a6);
}

/* Generic ops.  */

static inline void gen_set_label(TCGContext *s, TCGLabel *l)
{
    tcg_gen_op1(s, INDEX_op_set_label, label_arg(s, l));
}

static inline void tcg_gen_br(TCGContext *s, TCGLabel *l)
{
    tcg_gen_op1(s, INDEX_op_br, label_arg(s, l));
}

/* Helper calls. */

/* 32 bit ops */

void tcg_gen_addi_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);
void tcg_gen_subfi_i32(TCGContext *s, TCGv_i32 ret, int32_t arg1, TCGv_i32 arg2);
void tcg_gen_subi_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);
void tcg_gen_andi_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, uint32_t arg2);
void tcg_gen_ori_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);
void tcg_gen_xori_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);
void tcg_gen_shli_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);
void tcg_gen_shri_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);
void tcg_gen_sari_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);
void tcg_gen_muli_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2);
void tcg_gen_div_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_rem_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_divu_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_remu_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_andc_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_eqv_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_nand_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_nor_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_orc_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_rotl_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_rotli_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);
void tcg_gen_rotr_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_rotri_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2);
void tcg_gen_deposit_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2,
                         unsigned int ofs, unsigned int len);
void tcg_gen_brcond_i32(TCGContext *s, TCGCond cond, TCGv_i32 arg1, TCGv_i32 arg2, TCGLabel *l);
void tcg_gen_brcondi_i32(TCGContext *s, TCGCond cond, TCGv_i32 arg1, int32_t arg2, TCGLabel *l);
void tcg_gen_setcond_i32(TCGContext *s, TCGCond cond, TCGv_i32 ret,
                         TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_setcondi_i32(TCGContext *s, TCGCond cond, TCGv_i32 ret,
                          TCGv_i32 arg1, int32_t arg2);
void tcg_gen_movcond_i32(TCGContext *s, TCGCond cond, TCGv_i32 ret, TCGv_i32 c1,
                         TCGv_i32 c2, TCGv_i32 v1, TCGv_i32 v2);
void tcg_gen_add2_i32(TCGContext *s, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 al,
                      TCGv_i32 ah, TCGv_i32 bl, TCGv_i32 bh);
void tcg_gen_sub2_i32(TCGContext *s, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 al,
                      TCGv_i32 ah, TCGv_i32 bl, TCGv_i32 bh);
void tcg_gen_mulu2_i32(TCGContext *s, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_muls2_i32(TCGContext *s, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2);
void tcg_gen_ext8s_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg);
void tcg_gen_ext16s_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg);
void tcg_gen_ext8u_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg);
void tcg_gen_ext16u_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg);
void tcg_gen_bswap16_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg);
void tcg_gen_bswap32_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg);

static inline void tcg_gen_discard_i32(TCGContext *s, TCGv_i32 arg)
{
    tcg_gen_op1_i32(s, INDEX_op_discard, arg);
}

static inline void tcg_gen_mov_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg)
{
    if (!TCGV_EQUAL_I32(ret, arg)) {
        tcg_gen_op2_i32(s, INDEX_op_mov_i32, ret, arg);
    }
}

static inline void tcg_gen_movi_i32(TCGContext *s, TCGv_i32 ret, int32_t arg)
{
    tcg_gen_op2i_i32(s, INDEX_op_movi_i32, ret, arg);
}

static inline void tcg_gen_ld8u_i32(TCGContext *s, TCGv_i32 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(s, INDEX_op_ld8u_i32, ret, arg2, offset);
}

static inline void tcg_gen_ld8s_i32(TCGContext *s, TCGv_i32 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(s, INDEX_op_ld8s_i32, ret, arg2, offset);
}

static inline void tcg_gen_ld16u_i32(TCGContext *s, TCGv_i32 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(s, INDEX_op_ld16u_i32, ret, arg2, offset);
}

static inline void tcg_gen_ld16s_i32(TCGContext *s, TCGv_i32 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(s, INDEX_op_ld16s_i32, ret, arg2, offset);
}

static inline void tcg_gen_ld_i32(TCGContext *s, TCGv_i32 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(s, INDEX_op_ld_i32, ret, arg2, offset);
}

static inline void tcg_gen_st8_i32(TCGContext *s, TCGv_i32 arg1, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(s, INDEX_op_st8_i32, arg1, arg2, offset);
}

static inline void tcg_gen_st16_i32(TCGContext *s, TCGv_i32 arg1, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(s, INDEX_op_st16_i32, arg1, arg2, offset);
}

static inline void tcg_gen_st_i32(TCGContext *s, TCGv_i32 arg1, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ldst_op_i32(s, INDEX_op_st_i32, arg1, arg2, offset);
}

static inline void tcg_gen_add_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_add_i32, ret, arg1, arg2);
}

static inline void tcg_gen_sub_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_sub_i32, ret, arg1, arg2);
}

static inline void tcg_gen_and_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_and_i32, ret, arg1, arg2);
}

static inline void tcg_gen_or_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_or_i32, ret, arg1, arg2);
}

static inline void tcg_gen_xor_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_xor_i32, ret, arg1, arg2);
}

static inline void tcg_gen_shl_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_shl_i32, ret, arg1, arg2);
}

static inline void tcg_gen_shr_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_shr_i32, ret, arg1, arg2);
}

static inline void tcg_gen_sar_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_sar_i32, ret, arg1, arg2);
}

static inline void tcg_gen_mul_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    tcg_gen_op3_i32(s, INDEX_op_mul_i32, ret, arg1, arg2);
}

static inline void tcg_gen_neg_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_neg_i32) {
        tcg_gen_op2_i32(s, INDEX_op_neg_i32, ret, arg);
    } else {
        tcg_gen_subfi_i32(s, ret, 0, arg);
    }
}

static inline void tcg_gen_not_i32(TCGContext *s, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_not_i32) {
        tcg_gen_op2_i32(s, INDEX_op_not_i32, ret, arg);
    } else {
        tcg_gen_xori_i32(s, ret, arg, -1);
    }
}

/* 64 bit ops */

void tcg_gen_addi_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);
void tcg_gen_subfi_i64(TCGContext *s, TCGv_i64 ret, int64_t arg1, TCGv_i64 arg2);
void tcg_gen_subi_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);
void tcg_gen_andi_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2);
void tcg_gen_ori_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);
void tcg_gen_xori_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);
void tcg_gen_shli_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);
void tcg_gen_shri_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);
void tcg_gen_sari_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);
void tcg_gen_muli_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2);
void tcg_gen_div_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_rem_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_divu_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_remu_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_andc_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_eqv_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_nand_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_nor_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_orc_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_rotl_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_rotli_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);
void tcg_gen_rotr_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_rotri_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2);
void tcg_gen_deposit_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2,
                         unsigned int ofs, unsigned int len);
void tcg_gen_brcond_i64(TCGContext *s, TCGCond cond, TCGv_i64 arg1, TCGv_i64 arg2, TCGLabel *l);
void tcg_gen_brcondi_i64(TCGContext *s, TCGCond cond, TCGv_i64 arg1, int64_t arg2, TCGLabel *l);
void tcg_gen_setcond_i64(TCGContext *s, TCGCond cond, TCGv_i64 ret,
                         TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_setcondi_i64(TCGContext *s, TCGCond cond, TCGv_i64 ret,
                          TCGv_i64 arg1, int64_t arg2);
void tcg_gen_movcond_i64(TCGContext *s, TCGCond cond, TCGv_i64 ret, TCGv_i64 c1,
                         TCGv_i64 c2, TCGv_i64 v1, TCGv_i64 v2);
void tcg_gen_add2_i64(TCGContext *s, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 al,
                      TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh);
void tcg_gen_sub2_i64(TCGContext *s, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 al,
                      TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh);
void tcg_gen_mulu2_i64(TCGContext *s, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_muls2_i64(TCGContext *s, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_not_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_ext8s_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_ext16s_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_ext32s_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_ext8u_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_ext16u_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_ext32u_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_bswap16_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_bswap32_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_bswap64_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);

#if TCG_TARGET_REG_BITS == 64
static inline void tcg_gen_discard_i64(TCGContext *s, TCGv_i64 arg)
{
    tcg_gen_op1_i64(s, INDEX_op_discard, arg);
}

static inline void tcg_gen_mov_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg)
{
    if (!TCGV_EQUAL_I64(ret, arg)) {
        tcg_gen_op2_i64(s, INDEX_op_mov_i64, ret, arg);
    }
}

static inline void tcg_gen_movi_i64(TCGContext *s, TCGv_i64 ret, int64_t arg)
{
    tcg_gen_op2i_i64(s, INDEX_op_movi_i64, ret, arg);
}

static inline void tcg_gen_ld8u_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_ld8u_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld8s_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_ld8s_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld16u_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2,
                                     tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_ld16u_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld16s_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2,
                                     tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_ld16s_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld32u_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2,
                                     tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_ld32u_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld32s_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2,
                                     tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_ld32s_i64, ret, arg2, offset);
}

static inline void tcg_gen_ld_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2,
                                  tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_ld_i64, ret, arg2, offset);
}

static inline void tcg_gen_st8_i64(TCGContext *s, TCGv_i64 arg1, TCGv_ptr arg2,
                                   tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_st8_i64, arg1, arg2, offset);
}

static inline void tcg_gen_st16_i64(TCGContext *s, TCGv_i64 arg1, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_st16_i64, arg1, arg2, offset);
}

static inline void tcg_gen_st32_i64(TCGContext *s, TCGv_i64 arg1, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_st32_i64, arg1, arg2, offset);
}

static inline void tcg_gen_st_i64(TCGContext *s, TCGv_i64 arg1, TCGv_ptr arg2,
                                  tcg_target_long offset)
{
    tcg_gen_ldst_op_i64(s, INDEX_op_st_i64, arg1, arg2, offset);
}

static inline void tcg_gen_add_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_add_i64, ret, arg1, arg2);
}

static inline void tcg_gen_sub_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_sub_i64, ret, arg1, arg2);
}

static inline void tcg_gen_and_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_and_i64, ret, arg1, arg2);
}

static inline void tcg_gen_or_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_or_i64, ret, arg1, arg2);
}

static inline void tcg_gen_xor_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_xor_i64, ret, arg1, arg2);
}

static inline void tcg_gen_shl_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_shl_i64, ret, arg1, arg2);
}

static inline void tcg_gen_shr_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_shr_i64, ret, arg1, arg2);
}

static inline void tcg_gen_sar_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_sar_i64, ret, arg1, arg2);
}

static inline void tcg_gen_mul_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_op3_i64(s, INDEX_op_mul_i64, ret, arg1, arg2);
}
#else /* TCG_TARGET_REG_BITS == 32 */
static inline void tcg_gen_st8_i64(TCGContext *s, TCGv_i64 arg1, TCGv_ptr arg2,
                                   tcg_target_long offset)
{
    tcg_gen_st8_i32(s, TCGV_LOW(arg1), arg2, offset);
}

static inline void tcg_gen_st16_i64(TCGContext *s, TCGv_i64 arg1, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_st16_i32(s, TCGV_LOW(arg1), arg2, offset);
}

static inline void tcg_gen_st32_i64(TCGContext *s, TCGv_i64 arg1, TCGv_ptr arg2,
                                    tcg_target_long offset)
{
    tcg_gen_st_i32(s, TCGV_LOW(arg1), arg2, offset);
}

static inline void tcg_gen_add_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_add2_i32(s, TCGV_LOW(ret), TCGV_HIGH(ret), TCGV_LOW(arg1),
                     TCGV_HIGH(arg1), TCGV_LOW(arg2), TCGV_HIGH(arg2));
}

static inline void tcg_gen_sub_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_sub2_i32(s, TCGV_LOW(ret), TCGV_HIGH(ret), TCGV_LOW(arg1),
                     TCGV_HIGH(arg1), TCGV_LOW(arg2), TCGV_HIGH(arg2));
}

void tcg_gen_discard_i64(TCGContext *s, TCGv_i64 arg);
void tcg_gen_mov_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg);
void tcg_gen_movi_i64(TCGContext *s, TCGv_i64 ret, int64_t arg);
void tcg_gen_ld8u_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);
void tcg_gen_ld8s_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);
void tcg_gen_ld16u_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);
void tcg_gen_ld16s_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);
void tcg_gen_ld32u_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);
void tcg_gen_ld32s_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);
void tcg_gen_ld_i64(TCGContext *s, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset);
void tcg_gen_st_i64(TCGContext *s, TCGv_i64 arg1, TCGv_ptr arg2, tcg_target_long offset);
void tcg_gen_and_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_or_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_xor_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_shl_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_shr_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_sar_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
void tcg_gen_mul_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2);
#endif /* TCG_TARGET_REG_BITS */

static inline void tcg_gen_neg_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg)
{
    if (TCG_TARGET_HAS_neg_i64) {
        tcg_gen_op2_i64(s, INDEX_op_neg_i64, ret, arg);
    } else {
        tcg_gen_subfi_i64(s, ret, 0, arg);
    }
}

/* Size changing operations.  */

void tcg_gen_extu_i32_i64(TCGContext *s, TCGv_i64 ret, TCGv_i32 arg);
void tcg_gen_ext_i32_i64(TCGContext *s, TCGv_i64 ret, TCGv_i32 arg);
void tcg_gen_concat_i32_i64(TCGContext *s, TCGv_i64 dest, TCGv_i32 low, TCGv_i32 high);
void tcg_gen_extrl_i64_i32(TCGContext *s, TCGv_i32 ret, TCGv_i64 arg);
void tcg_gen_extrh_i64_i32(TCGContext *s, TCGv_i32 ret, TCGv_i64 arg);
void tcg_gen_extr_i64_i32(TCGContext *s, TCGv_i32 lo, TCGv_i32 hi, TCGv_i64 arg);
void tcg_gen_extr32_i64(TCGContext *s, TCGv_i64 lo, TCGv_i64 hi, TCGv_i64 arg);

static inline void tcg_gen_concat32_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 lo, TCGv_i64 hi)
{
    tcg_gen_deposit_i64(s, ret, lo, hi, 32, 32);
}

static inline void tcg_gen_trunc_i64_i32(TCGContext *s, TCGv_i32 ret, TCGv_i64 arg)
{
    tcg_gen_extrl_i64_i32(s, ret, arg);
}

/* QEMU specific operations.  */

#ifndef TARGET_LONG_BITS
#error must include QEMU headers
#endif

/* debug info: write the PC of the corresponding QEMU CPU instruction */
static inline void tcg_gen_debug_insn_start(TCGContext *s, uint64_t pc)
{
    /* XXX: must really use a 32 bit size for TCGArg in all cases */
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
    tcg_gen_op2ii(s, INDEX_op_debug_insn_start,
                  (uint32_t)(pc), (uint32_t)(pc >> 32));
#else
    tcg_gen_op1i(s, INDEX_op_debug_insn_start, pc);
#endif
}

static inline void tcg_gen_exit_tb(TCGContext *s, uintptr_t val)
{
    tcg_gen_op1i(s, INDEX_op_exit_tb, val);
}

void tcg_gen_goto_tb(TCGContext *s, unsigned idx);

#if TARGET_LONG_BITS == 32
#define TCGv TCGv_i32
#define tcg_temp_new(s) tcg_temp_new_i32(s)
#define tcg_global_reg_new tcg_global_reg_new_i32
#define tcg_global_mem_new tcg_global_mem_new_i32
#define tcg_temp_local_new(s) tcg_temp_local_new_i32(s)
#define tcg_temp_free tcg_temp_free_i32
#define TCGV_UNUSED(x) TCGV_UNUSED_I32(x)
#define TCGV_IS_UNUSED(x) TCGV_IS_UNUSED_I32(x)
#define TCGV_EQUAL(a, b) TCGV_EQUAL_I32(a, b)
#define tcg_gen_qemu_ld_tl tcg_gen_qemu_ld_i32
#define tcg_gen_qemu_st_tl tcg_gen_qemu_st_i32
#else
#define TCGv TCGv_i64
#define tcg_temp_new(s) tcg_temp_new_i64(s)
#define tcg_global_reg_new tcg_global_reg_new_i64
#define tcg_global_mem_new tcg_global_mem_new_i64
#define tcg_temp_local_new(s) tcg_temp_local_new_i64(s)
#define tcg_temp_free tcg_temp_free_i64
#define TCGV_UNUSED(x) TCGV_UNUSED_I64(x)
#define TCGV_IS_UNUSED(x) TCGV_IS_UNUSED_I64(x)
#define TCGV_EQUAL(a, b) TCGV_EQUAL_I64(a, b)
#define tcg_gen_qemu_ld_tl tcg_gen_qemu_ld_i64
#define tcg_gen_qemu_st_tl tcg_gen_qemu_st_i64
#endif

void tcg_gen_qemu_ld_i32(struct uc_struct *uc, TCGv_i32, TCGv, TCGArg, TCGMemOp);
void tcg_gen_qemu_st_i32(struct uc_struct *uc, TCGv_i32, TCGv, TCGArg, TCGMemOp);
void tcg_gen_qemu_ld_i64(struct uc_struct *uc, TCGv_i64, TCGv, TCGArg, TCGMemOp);
void tcg_gen_qemu_st_i64(struct uc_struct *uc, TCGv_i64, TCGv, TCGArg, TCGMemOp);

static inline void tcg_gen_qemu_ld8u(struct uc_struct *uc, TCGv ret, TCGv addr, int mem_index)
{
    tcg_gen_qemu_ld_tl(uc, ret, addr, mem_index, MO_UB);
}

static inline void tcg_gen_qemu_ld8s(struct uc_struct *uc, TCGv ret, TCGv addr, int mem_index)
{
    tcg_gen_qemu_ld_tl(uc, ret, addr, mem_index, MO_SB);
}

static inline void tcg_gen_qemu_ld16u(struct uc_struct *uc, TCGv ret, TCGv addr, int mem_index)
{
    tcg_gen_qemu_ld_tl(uc, ret, addr, mem_index, MO_TEUW);
}

static inline void tcg_gen_qemu_ld16s(struct uc_struct *uc, TCGv ret, TCGv addr, int mem_index)
{
    tcg_gen_qemu_ld_tl(uc, ret, addr, mem_index, MO_TESW);
}

static inline void tcg_gen_qemu_ld32u(struct uc_struct *uc, TCGv ret, TCGv addr, int mem_index)
{
    tcg_gen_qemu_ld_tl(uc, ret, addr, mem_index, MO_TEUL);
}

static inline void tcg_gen_qemu_ld32s(struct uc_struct *uc, TCGv ret, TCGv addr, int mem_index)
{
    tcg_gen_qemu_ld_tl(uc, ret, addr, mem_index, MO_TESL);
}

static inline void tcg_gen_qemu_ld64(struct uc_struct *uc, TCGv_i64 ret, TCGv addr, int mem_index)
{
    tcg_gen_qemu_ld_i64(uc, ret, addr, mem_index, MO_TEQ);
}

static inline void tcg_gen_qemu_st8(struct uc_struct *uc, TCGv arg, TCGv addr, int mem_index)
{
    tcg_gen_qemu_st_tl(uc, arg, addr, mem_index, MO_UB);
}

static inline void tcg_gen_qemu_st16(struct uc_struct *uc, TCGv arg, TCGv addr, int mem_index)
{
    tcg_gen_qemu_st_tl(uc, arg, addr, mem_index, MO_TEUW);
}

static inline void tcg_gen_qemu_st32(struct uc_struct *uc, TCGv arg, TCGv addr, int mem_index)
{
    tcg_gen_qemu_st_tl(uc, arg, addr, mem_index, MO_TEUL);
}

static inline void tcg_gen_qemu_st64(struct uc_struct *uc, TCGv_i64 arg, TCGv addr, int mem_index)
{
    tcg_gen_qemu_st_i64(uc, arg, addr, mem_index, MO_TEQ);
}

void check_exit_request(TCGContext *tcg_ctx);

#if TARGET_LONG_BITS == 64
#define tcg_gen_movi_tl tcg_gen_movi_i64
#define tcg_gen_mov_tl tcg_gen_mov_i64
#define tcg_gen_ld8u_tl tcg_gen_ld8u_i64
#define tcg_gen_ld8s_tl tcg_gen_ld8s_i64
#define tcg_gen_ld16u_tl tcg_gen_ld16u_i64
#define tcg_gen_ld16s_tl tcg_gen_ld16s_i64
#define tcg_gen_ld32u_tl tcg_gen_ld32u_i64
#define tcg_gen_ld32s_tl tcg_gen_ld32s_i64
#define tcg_gen_ld_tl tcg_gen_ld_i64
#define tcg_gen_st8_tl tcg_gen_st8_i64
#define tcg_gen_st16_tl tcg_gen_st16_i64
#define tcg_gen_st32_tl tcg_gen_st32_i64
#define tcg_gen_st_tl tcg_gen_st_i64
#define tcg_gen_add_tl tcg_gen_add_i64
#define tcg_gen_addi_tl tcg_gen_addi_i64
#define tcg_gen_sub_tl tcg_gen_sub_i64
#define tcg_gen_neg_tl tcg_gen_neg_i64
#define tcg_gen_subfi_tl tcg_gen_subfi_i64
#define tcg_gen_subi_tl tcg_gen_subi_i64
#define tcg_gen_and_tl tcg_gen_and_i64
#define tcg_gen_andi_tl tcg_gen_andi_i64
#define tcg_gen_or_tl tcg_gen_or_i64
#define tcg_gen_ori_tl tcg_gen_ori_i64
#define tcg_gen_xor_tl tcg_gen_xor_i64
#define tcg_gen_xori_tl tcg_gen_xori_i64
#define tcg_gen_not_tl tcg_gen_not_i64
#define tcg_gen_shl_tl tcg_gen_shl_i64
#define tcg_gen_shli_tl tcg_gen_shli_i64
#define tcg_gen_shr_tl tcg_gen_shr_i64
#define tcg_gen_shri_tl tcg_gen_shri_i64
#define tcg_gen_sar_tl tcg_gen_sar_i64
#define tcg_gen_sari_tl tcg_gen_sari_i64
#define tcg_gen_brcond_tl tcg_gen_brcond_i64
#define tcg_gen_brcondi_tl tcg_gen_brcondi_i64
#define tcg_gen_setcond_tl tcg_gen_setcond_i64
#define tcg_gen_setcondi_tl tcg_gen_setcondi_i64
#define tcg_gen_mul_tl tcg_gen_mul_i64
#define tcg_gen_muli_tl tcg_gen_muli_i64
#define tcg_gen_div_tl tcg_gen_div_i64
#define tcg_gen_rem_tl tcg_gen_rem_i64
#define tcg_gen_divu_tl tcg_gen_divu_i64
#define tcg_gen_remu_tl tcg_gen_remu_i64
#define tcg_gen_discard_tl tcg_gen_discard_i64
#define tcg_gen_trunc_tl_i32 tcg_gen_trunc_i64_i32
#define tcg_gen_trunc_i64_tl tcg_gen_mov_i64
#define tcg_gen_extu_i32_tl tcg_gen_extu_i32_i64
#define tcg_gen_ext_i32_tl tcg_gen_ext_i32_i64
#define tcg_gen_extu_tl_i64 tcg_gen_mov_i64
#define tcg_gen_ext_tl_i64 tcg_gen_mov_i64
#define tcg_gen_ext8u_tl tcg_gen_ext8u_i64
#define tcg_gen_ext8s_tl tcg_gen_ext8s_i64
#define tcg_gen_ext16u_tl tcg_gen_ext16u_i64
#define tcg_gen_ext16s_tl tcg_gen_ext16s_i64
#define tcg_gen_ext32u_tl tcg_gen_ext32u_i64
#define tcg_gen_ext32s_tl tcg_gen_ext32s_i64
#define tcg_gen_bswap16_tl tcg_gen_bswap16_i64
#define tcg_gen_bswap32_tl tcg_gen_bswap32_i64
#define tcg_gen_bswap64_tl tcg_gen_bswap64_i64
#define tcg_gen_concat_tl_i64 tcg_gen_concat32_i64
#define tcg_gen_extr_i64_tl tcg_gen_extr32_i64
#define tcg_gen_andc_tl tcg_gen_andc_i64
#define tcg_gen_eqv_tl tcg_gen_eqv_i64
#define tcg_gen_nand_tl tcg_gen_nand_i64
#define tcg_gen_nor_tl tcg_gen_nor_i64
#define tcg_gen_orc_tl tcg_gen_orc_i64
#define tcg_gen_rotl_tl tcg_gen_rotl_i64
#define tcg_gen_rotli_tl tcg_gen_rotli_i64
#define tcg_gen_rotr_tl tcg_gen_rotr_i64
#define tcg_gen_rotri_tl tcg_gen_rotri_i64
#define tcg_gen_deposit_tl tcg_gen_deposit_i64
#define tcg_const_tl tcg_const_i64
#define tcg_const_local_tl tcg_const_local_i64
#define tcg_gen_movcond_tl tcg_gen_movcond_i64
#define tcg_gen_add2_tl tcg_gen_add2_i64
#define tcg_gen_sub2_tl tcg_gen_sub2_i64
#define tcg_gen_mulu2_tl tcg_gen_mulu2_i64
#define tcg_gen_muls2_tl tcg_gen_muls2_i64
#else
#define tcg_gen_movi_tl tcg_gen_movi_i32
#define tcg_gen_mov_tl tcg_gen_mov_i32
#define tcg_gen_ld8u_tl tcg_gen_ld8u_i32
#define tcg_gen_ld8s_tl tcg_gen_ld8s_i32
#define tcg_gen_ld16u_tl tcg_gen_ld16u_i32
#define tcg_gen_ld16s_tl tcg_gen_ld16s_i32
#define tcg_gen_ld32u_tl tcg_gen_ld_i32
#define tcg_gen_ld32s_tl tcg_gen_ld_i32
#define tcg_gen_ld_tl tcg_gen_ld_i32
#define tcg_gen_st8_tl tcg_gen_st8_i32
#define tcg_gen_st16_tl tcg_gen_st16_i32
#define tcg_gen_st32_tl tcg_gen_st_i32
#define tcg_gen_st_tl tcg_gen_st_i32
#define tcg_gen_add_tl tcg_gen_add_i32
#define tcg_gen_addi_tl tcg_gen_addi_i32
#define tcg_gen_sub_tl tcg_gen_sub_i32
#define tcg_gen_neg_tl tcg_gen_neg_i32
#define tcg_gen_subfi_tl tcg_gen_subfi_i32
#define tcg_gen_subi_tl tcg_gen_subi_i32
#define tcg_gen_and_tl tcg_gen_and_i32
#define tcg_gen_andi_tl tcg_gen_andi_i32
#define tcg_gen_or_tl tcg_gen_or_i32
#define tcg_gen_ori_tl tcg_gen_ori_i32
#define tcg_gen_xor_tl tcg_gen_xor_i32
#define tcg_gen_xori_tl tcg_gen_xori_i32
#define tcg_gen_not_tl tcg_gen_not_i32
#define tcg_gen_shl_tl tcg_gen_shl_i32
#define tcg_gen_shli_tl tcg_gen_shli_i32
#define tcg_gen_shr_tl tcg_gen_shr_i32
#define tcg_gen_shri_tl tcg_gen_shri_i32
#define tcg_gen_sar_tl tcg_gen_sar_i32
#define tcg_gen_sari_tl tcg_gen_sari_i32
#define tcg_gen_brcond_tl tcg_gen_brcond_i32
#define tcg_gen_brcondi_tl tcg_gen_brcondi_i32
#define tcg_gen_setcond_tl tcg_gen_setcond_i32
#define tcg_gen_setcondi_tl tcg_gen_setcondi_i32
#define tcg_gen_mul_tl tcg_gen_mul_i32
#define tcg_gen_muli_tl tcg_gen_muli_i32
#define tcg_gen_div_tl tcg_gen_div_i32
#define tcg_gen_rem_tl tcg_gen_rem_i32
#define tcg_gen_divu_tl tcg_gen_divu_i32
#define tcg_gen_remu_tl tcg_gen_remu_i32
#define tcg_gen_discard_tl tcg_gen_discard_i32
#define tcg_gen_trunc_tl_i32 tcg_gen_mov_i32
#define tcg_gen_trunc_i64_tl tcg_gen_trunc_i64_i32
#define tcg_gen_extu_i32_tl tcg_gen_mov_i32
#define tcg_gen_ext_i32_tl tcg_gen_mov_i32
#define tcg_gen_extu_tl_i64 tcg_gen_extu_i32_i64
#define tcg_gen_ext_tl_i64 tcg_gen_ext_i32_i64
#define tcg_gen_ext8u_tl tcg_gen_ext8u_i32
#define tcg_gen_ext8s_tl tcg_gen_ext8s_i32
#define tcg_gen_ext16u_tl tcg_gen_ext16u_i32
#define tcg_gen_ext16s_tl tcg_gen_ext16s_i32
#define tcg_gen_ext32u_tl tcg_gen_mov_i32
#define tcg_gen_ext32s_tl tcg_gen_mov_i32
#define tcg_gen_bswap16_tl tcg_gen_bswap16_i32
#define tcg_gen_bswap32_tl tcg_gen_bswap32_i32
#define tcg_gen_concat_tl_i64 tcg_gen_concat_i32_i64
#define tcg_gen_extr_i64_tl tcg_gen_extr_i64_i32
#define tcg_gen_andc_tl tcg_gen_andc_i32
#define tcg_gen_eqv_tl tcg_gen_eqv_i32
#define tcg_gen_nand_tl tcg_gen_nand_i32
#define tcg_gen_nor_tl tcg_gen_nor_i32
#define tcg_gen_orc_tl tcg_gen_orc_i32
#define tcg_gen_rotl_tl tcg_gen_rotl_i32
#define tcg_gen_rotli_tl tcg_gen_rotli_i32
#define tcg_gen_rotr_tl tcg_gen_rotr_i32
#define tcg_gen_rotri_tl tcg_gen_rotri_i32
#define tcg_gen_deposit_tl tcg_gen_deposit_i32
#define tcg_const_tl tcg_const_i32
#define tcg_const_local_tl tcg_const_local_i32
#define tcg_gen_movcond_tl tcg_gen_movcond_i32
#define tcg_gen_add2_tl tcg_gen_add2_i32
#define tcg_gen_sub2_tl tcg_gen_sub2_i32
#define tcg_gen_mulu2_tl tcg_gen_mulu2_i32
#define tcg_gen_muls2_tl tcg_gen_muls2_i32
#endif

#if UINTPTR_MAX == UINT32_MAX
# define tcg_gen_ld_ptr(S, R, A, O) \
    tcg_gen_ld_i32(S, TCGV_PTR_TO_NAT(R), (A), (O))
# define tcg_gen_discard_ptr(A) \
    tcg_gen_discard_i32(TCGV_PTR_TO_NAT(A))
# define tcg_gen_add_ptr(S, R, A, B) \
    tcg_gen_add_i32(S, TCGV_PTR_TO_NAT(R), TCGV_PTR_TO_NAT(A), TCGV_PTR_TO_NAT(B))
# define tcg_gen_addi_ptr(S, R, A, B) \
    tcg_gen_addi_i32(S, TCGV_PTR_TO_NAT(R), TCGV_PTR_TO_NAT(A), (B))
# define tcg_gen_ext_i32_ptr(S, R, A) \
    tcg_gen_mov_i32(S, TCGV_PTR_TO_NAT(R), (A))
#else
# define tcg_gen_ld_ptr(S, R, A, O) \
    tcg_gen_ld_i64(S, TCGV_PTR_TO_NAT(R), (A), (O))
# define tcg_gen_discard_ptr(A) \
    tcg_gen_discard_i64(TCGV_PTR_TO_NAT(A))
# define tcg_gen_add_ptr(S, R, A, B) \
    tcg_gen_add_i64(S, TCGV_PTR_TO_NAT(R), TCGV_PTR_TO_NAT(A), TCGV_PTR_TO_NAT(B))
# define tcg_gen_addi_ptr(S, R, A, B) \
    tcg_gen_addi_i64(S, TCGV_PTR_TO_NAT(R), TCGV_PTR_TO_NAT(A), (B))
# define tcg_gen_ext_i32_ptr(S, R, A) \
    tcg_gen_ext_i32_i64(S, TCGV_PTR_TO_NAT(R), (A))
#endif /* UINTPTR_MAX == UINT32_MAX */
