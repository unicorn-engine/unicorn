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

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-mo.h"
#include "trace/mem.h"

/* Reduce the number of ifdefs below.  This assumes that all uses of
   TCGV_HIGH and TCGV_LOW are properly protected by a conditional that
   the compiler can eliminate.  */
#if TCG_TARGET_REG_BITS == 64
extern TCGv_i32 TCGV_LOW_link_error(TCGv_i64);
extern TCGv_i32 TCGV_HIGH_link_error(TCGv_i64);
#define TCGV_LOW  TCGV_LOW_link_error
#define TCGV_HIGH TCGV_HIGH_link_error
#endif

void tcg_gen_op1(TCGContext *tcg_ctx, TCGOpcode opc, TCGArg a1)
{
    TCGOp *op = tcg_emit_op(tcg_ctx, opc);
    op->args[0] = a1;
}

void tcg_gen_op2(TCGContext *tcg_ctx, TCGOpcode opc, TCGArg a1, TCGArg a2)
{
    TCGOp *op = tcg_emit_op(tcg_ctx, opc);
    op->args[0] = a1;
    op->args[1] = a2;
}

void tcg_gen_op3(TCGContext *tcg_ctx, TCGOpcode opc, TCGArg a1, TCGArg a2, TCGArg a3)
{
    TCGOp *op = tcg_emit_op(tcg_ctx, opc);
    op->args[0] = a1;
    op->args[1] = a2;
    op->args[2] = a3;
}

void tcg_gen_op4(TCGContext *tcg_ctx, TCGOpcode opc, TCGArg a1, TCGArg a2, TCGArg a3, TCGArg a4)
{
    TCGOp *op = tcg_emit_op(tcg_ctx, opc);
    op->args[0] = a1;
    op->args[1] = a2;
    op->args[2] = a3;
    op->args[3] = a4;
}

void tcg_gen_op5(TCGContext *tcg_ctx, TCGOpcode opc, TCGArg a1, TCGArg a2, TCGArg a3,
                 TCGArg a4, TCGArg a5)
{
    TCGOp *op = tcg_emit_op(tcg_ctx, opc);
    op->args[0] = a1;
    op->args[1] = a2;
    op->args[2] = a3;
    op->args[3] = a4;
    op->args[4] = a5;
}

void tcg_gen_op6(TCGContext *tcg_ctx, TCGOpcode opc, TCGArg a1, TCGArg a2, TCGArg a3,
                 TCGArg a4, TCGArg a5, TCGArg a6)
{
    TCGOp *op = tcg_emit_op(tcg_ctx, opc);
    op->args[0] = a1;
    op->args[1] = a2;
    op->args[2] = a3;
    op->args[3] = a4;
    op->args[4] = a5;
    op->args[5] = a6;
}

void tcg_gen_mb(TCGContext *tcg_ctx, TCGBar mb_type)
{
    if (tcg_ctx->tb_cflags & CF_PARALLEL) {
        tcg_gen_op1(tcg_ctx, INDEX_op_mb, mb_type);
    }
}

/* 32 bit ops */

void tcg_gen_addi_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_add_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_subfi_i32(TCGContext *tcg_ctx, TCGv_i32 ret, int32_t arg1, TCGv_i32 arg2)
{
    if (arg1 == 0 && TCG_TARGET_HAS_neg_i32) {
        /* Don't recurse with tcg_gen_neg_i32.  */
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_neg_i32, ret, arg2);
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg1);
        tcg_gen_sub_i32(tcg_ctx, ret, t0, arg2);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_subi_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_sub_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_andi_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    TCGv_i32 t0;
    /* Some cases can be optimized here.  */
    switch (arg2) {
    case 0:
        tcg_gen_movi_i32(tcg_ctx, ret, 0);
        return;
    case -1:
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
        return;
    case 0xff:
        /* Don't recurse with tcg_gen_ext8u_i32.  */
        if (TCG_TARGET_HAS_ext8u_i32) {
            tcg_gen_op2_i32(tcg_ctx, INDEX_op_ext8u_i32, ret, arg1);
            return;
        }
        break;
    case 0xffff:
        if (TCG_TARGET_HAS_ext16u_i32) {
            tcg_gen_op2_i32(tcg_ctx, INDEX_op_ext16u_i32, ret, arg1);
            return;
        }
        break;
    }
    t0 = tcg_const_i32(tcg_ctx, arg2);
    tcg_gen_and_i32(tcg_ctx, ret, arg1, t0);
    tcg_temp_free_i32(tcg_ctx, t0);
}

void tcg_gen_ori_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    /* Some cases can be optimized here.  */
    if (arg2 == -1) {
        tcg_gen_movi_i32(tcg_ctx, ret, -1);
    } else if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_or_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_xori_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    /* Some cases can be optimized here.  */
    if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else if (arg2 == -1 && TCG_TARGET_HAS_not_i32) {
        /* Don't recurse with tcg_gen_not_i32.  */
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_not_i32, ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_xor_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_shli_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_shl_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_shri_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_shr_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_sari_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 32);
    if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_sar_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_brcond_i32(TCGContext *tcg_ctx, TCGCond cond, TCGv_i32 arg1, TCGv_i32 arg2, TCGLabel *l)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_br(tcg_ctx, l);
    } else if (cond != TCG_COND_NEVER) {
        l->refs++;
        tcg_gen_op4ii_i32(tcg_ctx, INDEX_op_brcond_i32, arg1, arg2, cond, label_arg(l));
    }
}

void tcg_gen_brcondi_i32(TCGContext *tcg_ctx, TCGCond cond, TCGv_i32 arg1, int32_t arg2, TCGLabel *l)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_br(tcg_ctx, l);
    } else if (cond != TCG_COND_NEVER) {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_brcond_i32(tcg_ctx, cond, arg1, t0, l);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_setcond_i32(TCGContext *tcg_ctx, TCGCond cond, TCGv_i32 ret,
                         TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_movi_i32(tcg_ctx, ret, 1);
    } else if (cond == TCG_COND_NEVER) {
        tcg_gen_movi_i32(tcg_ctx, ret, 0);
    } else {
        tcg_gen_op4i_i32(tcg_ctx, INDEX_op_setcond_i32, ret, arg1, arg2, cond);
    }
}

void tcg_gen_setcondi_i32(TCGContext *tcg_ctx, TCGCond cond, TCGv_i32 ret,
                          TCGv_i32 arg1, int32_t arg2)
{
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
    tcg_gen_setcond_i32(tcg_ctx, cond, ret, arg1, t0);
    tcg_temp_free_i32(tcg_ctx, t0);
}

void tcg_gen_muli_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, int32_t arg2)
{
    if (arg2 == 0) {
        tcg_gen_movi_i32(tcg_ctx, ret, 0);
    } else if (is_power_of_2(arg2)) {
        tcg_gen_shli_i32(tcg_ctx, ret, arg1, ctz32(arg2));
    } else {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_mul_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_div_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_div_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_div_i32, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_div2_i32) {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_sari_i32(tcg_ctx, t0, arg1, 31);
        tcg_gen_op5_i32(tcg_ctx, INDEX_op_div2_i32, ret, t0, arg1, t0, arg2);
        tcg_temp_free_i32(tcg_ctx, t0);
    } else {
        gen_helper_div_i32(tcg_ctx, ret, arg1, arg2);
    }
}

void tcg_gen_rem_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_rem_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_rem_i32, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_div_i32) {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_div_i32, t0, arg1, arg2);
        tcg_gen_mul_i32(tcg_ctx, t0, t0, arg2);
        tcg_gen_sub_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    } else if (TCG_TARGET_HAS_div2_i32) {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_sari_i32(tcg_ctx, t0, arg1, 31);
        tcg_gen_op5_i32(tcg_ctx, INDEX_op_div2_i32, t0, ret, arg1, t0, arg2);
        tcg_temp_free_i32(tcg_ctx, t0);
    } else {
        gen_helper_rem_i32(tcg_ctx, ret, arg1, arg2);
    }
}

void tcg_gen_divu_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_div_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_divu_i32, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_div2_i32) {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_movi_i32(tcg_ctx, t0, 0);
        tcg_gen_op5_i32(tcg_ctx, INDEX_op_divu2_i32, ret, t0, arg1, t0, arg2);
        tcg_temp_free_i32(tcg_ctx, t0);
    } else {
        gen_helper_divu_i32(tcg_ctx, ret, arg1, arg2);
    }
}

void tcg_gen_remu_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_rem_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_remu_i32, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_div_i32) {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_divu_i32, t0, arg1, arg2);
        tcg_gen_mul_i32(tcg_ctx, t0, t0, arg2);
        tcg_gen_sub_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    } else if (TCG_TARGET_HAS_div2_i32) {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_movi_i32(tcg_ctx, t0, 0);
        tcg_gen_op5_i32(tcg_ctx, INDEX_op_divu2_i32, t0, ret, arg1, t0, arg2);
        tcg_temp_free_i32(tcg_ctx, t0);
    } else {
        gen_helper_remu_i32(tcg_ctx, ret, arg1, arg2);
    }
}

void tcg_gen_andc_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_andc_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_andc_i32, ret, arg1, arg2);
    } else {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_not_i32(tcg_ctx, t0,arg2);
        tcg_gen_and_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_eqv_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_eqv_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_eqv_i32, ret, arg1, arg2);
    } else {
        tcg_gen_xor_i32(tcg_ctx, ret, arg1, arg2);
        tcg_gen_not_i32(tcg_ctx, ret, ret);
    }
}

void tcg_gen_nand_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_nand_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_nand_i32, ret, arg1, arg2);
    } else {
        tcg_gen_and_i32(tcg_ctx, ret, arg1, arg2);
        tcg_gen_not_i32(tcg_ctx, ret, ret);
    }
}

void tcg_gen_nor_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_nor_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_nor_i32, ret, arg1, arg2);
    } else {
        tcg_gen_or_i32(tcg_ctx, ret, arg1, arg2);
        tcg_gen_not_i32(tcg_ctx, ret, ret);
    }
}

void tcg_gen_orc_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_orc_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_orc_i32, ret, arg1, arg2);
    } else {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_not_i32(tcg_ctx, t0,arg2);
        tcg_gen_or_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_clz_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_clz_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_clz_i32, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_clz_i64) {
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_extu_i32_i64(tcg_ctx, t1, arg1);
        tcg_gen_extu_i32_i64(tcg_ctx, t2, arg2);
        tcg_gen_addi_i64(tcg_ctx, t2, t2, 32);
        tcg_gen_clz_i64(tcg_ctx, t1, t1, t2);
        tcg_gen_extrl_i64_i32(tcg_ctx, ret, t1);
        tcg_temp_free_i64(tcg_ctx, t1);
        tcg_temp_free_i64(tcg_ctx, t2);
        tcg_gen_subi_i32(tcg_ctx, ret, ret, 32);
    } else {
        gen_helper_clz_i32(tcg_ctx, ret, arg1, arg2);
    }
}

void tcg_gen_clzi_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, uint32_t arg2)
{
    TCGv_i32 t = tcg_const_i32(tcg_ctx, arg2);
    tcg_gen_clz_i32(tcg_ctx, ret, arg1, t);
    tcg_temp_free_i32(tcg_ctx, t);
}

void tcg_gen_ctz_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_ctz_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_ctz_i32, ret, arg1, arg2);
    } else if (TCG_TARGET_HAS_ctz_i64) {
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_extu_i32_i64(tcg_ctx, t1, arg1);
        tcg_gen_extu_i32_i64(tcg_ctx, t2, arg2);
        tcg_gen_ctz_i64(tcg_ctx, t1, t1, t2);
        tcg_gen_extrl_i64_i32(tcg_ctx, ret, t1);
        tcg_temp_free_i64(tcg_ctx, t1);
        tcg_temp_free_i64(tcg_ctx, t2);
    } else if (TCG_TARGET_HAS_ctpop_i32
               || TCG_TARGET_HAS_ctpop_i64
               || TCG_TARGET_HAS_clz_i32
               || TCG_TARGET_HAS_clz_i64) {
        TCGv_i32 z, t = tcg_temp_new_i32(tcg_ctx);

        if (TCG_TARGET_HAS_ctpop_i32 || TCG_TARGET_HAS_ctpop_i64) {
            tcg_gen_subi_i32(tcg_ctx, t, arg1, 1);
            tcg_gen_andc_i32(tcg_ctx, t, t, arg1);
            tcg_gen_ctpop_i32(tcg_ctx, t, t);
        } else {
            /* Since all non-x86 hosts have clz(0) == 32, don't fight it.  */
            tcg_gen_neg_i32(tcg_ctx, t, arg1);
            tcg_gen_and_i32(tcg_ctx, t, t, arg1);
            tcg_gen_clzi_i32(tcg_ctx, t, t, 32);
            tcg_gen_xori_i32(tcg_ctx, t, t, 31);
        }
        z = tcg_const_i32(tcg_ctx, 0);
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, ret, arg1, z, arg2, t);
        tcg_temp_free_i32(tcg_ctx, t);
        tcg_temp_free_i32(tcg_ctx, z);
    } else {
        gen_helper_ctz_i32(tcg_ctx, ret, arg1, arg2);
    }
}

void tcg_gen_ctzi_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, uint32_t arg2)
{
    if (!TCG_TARGET_HAS_ctz_i32 && TCG_TARGET_HAS_ctpop_i32 && arg2 == 32) {
        /* This equivalence has the advantage of not requiring a fixup.  */
        TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_subi_i32(tcg_ctx, t, arg1, 1);
        tcg_gen_andc_i32(tcg_ctx, t, t, arg1);
        tcg_gen_ctpop_i32(tcg_ctx, ret, t);
        tcg_temp_free_i32(tcg_ctx, t);
    } else {
        TCGv_i32 t = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_ctz_i32(tcg_ctx, ret, arg1, t);
        tcg_temp_free_i32(tcg_ctx, t);
    }
}

void tcg_gen_clrsb_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_clz_i32) {
        TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_sari_i32(tcg_ctx, t, arg, 31);
        tcg_gen_xor_i32(tcg_ctx, t, t, arg);
        tcg_gen_clzi_i32(tcg_ctx, t, t, 32);
        tcg_gen_subi_i32(tcg_ctx, ret, t, 1);
        tcg_temp_free_i32(tcg_ctx, t);
    } else {
        gen_helper_clrsb_i32(tcg_ctx, ret, arg);
    }
}

void tcg_gen_ctpop_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1)
{
    if (TCG_TARGET_HAS_ctpop_i32) {
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_ctpop_i32, ret, arg1);
    } else if (TCG_TARGET_HAS_ctpop_i64) {
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_extu_i32_i64(tcg_ctx, t, arg1);
        tcg_gen_ctpop_i64(tcg_ctx, t, t);
        tcg_gen_extrl_i64_i32(tcg_ctx, ret, t);
        tcg_temp_free_i64(tcg_ctx, t);
    } else {
        gen_helper_ctpop_i32(tcg_ctx, ret, arg1);
    }
}

void tcg_gen_rotl_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_rot_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_rotl_i32, ret, arg1, arg2);
    } else {
        TCGv_i32 t0, t1;

        t0 = tcg_temp_new_i32(tcg_ctx);
        t1 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_shl_i32(tcg_ctx, t0, arg1, arg2);
        tcg_gen_subfi_i32(tcg_ctx, t1, 32, arg2);
        tcg_gen_shr_i32(tcg_ctx, t1, arg1, t1);
        tcg_gen_or_i32(tcg_ctx, ret, t0, t1);
        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
    }
}

void tcg_gen_rotli_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 32);
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else if (TCG_TARGET_HAS_rot_i32) {
        TCGv_i32 t0 = tcg_const_i32(tcg_ctx, arg2);
        tcg_gen_rotl_i32(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    } else {
        TCGv_i32 t0, t1;
        t0 = tcg_temp_new_i32(tcg_ctx);
        t1 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_shli_i32(tcg_ctx, t0, arg1, arg2);
        tcg_gen_shri_i32(tcg_ctx, t1, arg1, 32 - arg2);
        tcg_gen_or_i32(tcg_ctx, ret, t0, t1);
        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
    }
}

void tcg_gen_rotr_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_rot_i32) {
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_rotr_i32, ret, arg1, arg2);
    } else {
        TCGv_i32 t0, t1;

        t0 = tcg_temp_new_i32(tcg_ctx);
        t1 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_shr_i32(tcg_ctx, t0, arg1, arg2);
        tcg_gen_subfi_i32(tcg_ctx, t1, 32, arg2);
        tcg_gen_shl_i32(tcg_ctx, t1, arg1, t1);
        tcg_gen_or_i32(tcg_ctx, ret, t0, t1);
        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
    }
}

void tcg_gen_rotri_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 32);
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg1);
    } else {
        tcg_gen_rotli_i32(tcg_ctx, ret, arg1, 32 - arg2);
    }
}

void tcg_gen_deposit_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg1, TCGv_i32 arg2,
                         unsigned int ofs, unsigned int len)
{
    uint32_t mask;
    TCGv_i32 t1;

    tcg_debug_assert(ofs < 32);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 32);
    tcg_debug_assert(ofs + len <= 32);

    if (len == 32) {
        tcg_gen_mov_i32(tcg_ctx, ret, arg2);
        return;
    }
    if (TCG_TARGET_HAS_deposit_i32 && TCG_TARGET_deposit_i32_valid(ofs, len)) {
        tcg_gen_op5ii_i32(tcg_ctx, INDEX_op_deposit_i32, ret, arg1, arg2, ofs, len);
        return;
    }

    t1 = tcg_temp_new_i32(tcg_ctx);

    if (TCG_TARGET_HAS_extract2_i32) {
        if (ofs + len == 32) {
            tcg_gen_shli_i32(tcg_ctx, t1, arg1, len);
            tcg_gen_extract2_i32(tcg_ctx, ret, t1, arg2, len);
            goto done;
        }
        if (ofs == 0) {
            tcg_gen_extract2_i32(tcg_ctx, ret, arg1, arg2, len);
            tcg_gen_rotli_i32(tcg_ctx, ret, ret, len);
            goto done;
        }
    }

    mask = (1u << len) - 1;
    if (ofs + len < 32) {
        tcg_gen_andi_i32(tcg_ctx, t1, arg2, mask);
        tcg_gen_shli_i32(tcg_ctx, t1, t1, ofs);
    } else {
        tcg_gen_shli_i32(tcg_ctx, t1, arg2, ofs);
    }
    tcg_gen_andi_i32(tcg_ctx, ret, arg1, ~(mask << ofs));
    tcg_gen_or_i32(tcg_ctx, ret, ret, t1);
 done:
    tcg_temp_free_i32(tcg_ctx, t1);
}

void tcg_gen_deposit_z_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg,
                           unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 32);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 32);
    tcg_debug_assert(ofs + len <= 32);

    if (ofs + len == 32) {
        tcg_gen_shli_i32(tcg_ctx, ret, arg, ofs);
    } else if (ofs == 0) {
        tcg_gen_andi_i32(tcg_ctx, ret, arg, (1u << len) - 1);
    } else if (TCG_TARGET_HAS_deposit_i32
               && TCG_TARGET_deposit_i32_valid(ofs, len)) {
        TCGv_i32 zero = tcg_const_i32(tcg_ctx, 0);
        tcg_gen_op5ii_i32(tcg_ctx, INDEX_op_deposit_i32, ret, zero, arg, ofs, len);
        tcg_temp_free_i32(tcg_ctx, zero);
    } else {
        /* To help two-operand hosts we prefer to zero-extend first,
           which allows ARG to stay live.  */
        switch (len) {
        case 16:
            if (TCG_TARGET_HAS_ext16u_i32) {
                tcg_gen_ext16u_i32(tcg_ctx, ret, arg);
                tcg_gen_shli_i32(tcg_ctx, ret, ret, ofs);
                return;
            }
            break;
        case 8:
            if (TCG_TARGET_HAS_ext8u_i32) {
                tcg_gen_ext8u_i32(tcg_ctx, ret, arg);
                tcg_gen_shli_i32(tcg_ctx, ret, ret, ofs);
                return;
            }
            break;
        }
        /* Otherwise prefer zero-extension over AND for code size.  */
        switch (ofs + len) {
        case 16:
            if (TCG_TARGET_HAS_ext16u_i32) {
                tcg_gen_shli_i32(tcg_ctx, ret, arg, ofs);
                tcg_gen_ext16u_i32(tcg_ctx, ret, ret);
                return;
            }
            break;
        case 8:
            if (TCG_TARGET_HAS_ext8u_i32) {
                tcg_gen_shli_i32(tcg_ctx, ret, arg, ofs);
                tcg_gen_ext8u_i32(tcg_ctx, ret, ret);
                return;
            }
            break;
        }
        tcg_gen_andi_i32(tcg_ctx, ret, arg, (1u << len) - 1);
        tcg_gen_shli_i32(tcg_ctx, ret, ret, ofs);
    }
}

void tcg_gen_extract_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg,
                         unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 32);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 32);
    tcg_debug_assert(ofs + len <= 32);

    /* Canonicalize certain special cases, even if extract is supported.  */
    if (ofs + len == 32) {
        tcg_gen_shri_i32(tcg_ctx, ret, arg, 32 - len);
        return;
    }
    if (ofs == 0) {
        tcg_gen_andi_i32(tcg_ctx, ret, arg, (1u << len) - 1);
        return;
    }

    if (TCG_TARGET_HAS_extract_i32
        && TCG_TARGET_extract_i32_valid(ofs, len)) {
        tcg_gen_op4ii_i32(tcg_ctx, INDEX_op_extract_i32, ret, arg, ofs, len);
        return;
    }

    /* Assume that zero-extension, if available, is cheaper than a shift.  */
    switch (ofs + len) {
    case 16:
        if (TCG_TARGET_HAS_ext16u_i32) {
            tcg_gen_ext16u_i32(tcg_ctx, ret, arg);
            tcg_gen_shri_i32(tcg_ctx, ret, ret, ofs);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8u_i32) {
            tcg_gen_ext8u_i32(tcg_ctx, ret, arg);
            tcg_gen_shri_i32(tcg_ctx, ret, ret, ofs);
            return;
        }
        break;
    }

    /* ??? Ideally we'd know what values are available for immediate AND.
       Assume that 8 bits are available, plus the special case of 16,
       so that we get ext8u, ext16u.  */
    switch (len) {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 16:
        tcg_gen_shri_i32(tcg_ctx, ret, arg, ofs);
        tcg_gen_andi_i32(tcg_ctx, ret, ret, (1u << len) - 1);
        break;
    default:
        tcg_gen_shli_i32(tcg_ctx, ret, arg, 32 - len - ofs);
        tcg_gen_shri_i32(tcg_ctx, ret, ret, 32 - len);
        break;
    }
}

void tcg_gen_sextract_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg,
                          unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 32);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 32);
    tcg_debug_assert(ofs + len <= 32);

    /* Canonicalize certain special cases, even if extract is supported.  */
    if (ofs + len == 32) {
        tcg_gen_sari_i32(tcg_ctx, ret, arg, 32 - len);
        return;
    }
    if (ofs == 0) {
        switch (len) {
        case 16:
            tcg_gen_ext16s_i32(tcg_ctx, ret, arg);
            return;
        case 8:
            tcg_gen_ext8s_i32(tcg_ctx, ret, arg);
            return;
        }
    }

    if (TCG_TARGET_HAS_sextract_i32
        && TCG_TARGET_extract_i32_valid(ofs, len)) {
        tcg_gen_op4ii_i32(tcg_ctx, INDEX_op_sextract_i32, ret, arg, ofs, len);
        return;
    }

    /* Assume that sign-extension, if available, is cheaper than a shift.  */
    switch (ofs + len) {
    case 16:
        if (TCG_TARGET_HAS_ext16s_i32) {
            tcg_gen_ext16s_i32(tcg_ctx, ret, arg);
            tcg_gen_sari_i32(tcg_ctx, ret, ret, ofs);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8s_i32) {
            tcg_gen_ext8s_i32(tcg_ctx, ret, arg);
            tcg_gen_sari_i32(tcg_ctx, ret, ret, ofs);
            return;
        }
        break;
    }
    switch (len) {
    case 16:
        if (TCG_TARGET_HAS_ext16s_i32) {
            tcg_gen_shri_i32(tcg_ctx, ret, arg, ofs);
            tcg_gen_ext16s_i32(tcg_ctx, ret, ret);
            return;
        }
        break;
    case 8:
        if (TCG_TARGET_HAS_ext8s_i32) {
            tcg_gen_shri_i32(tcg_ctx, ret, arg, ofs);
            tcg_gen_ext8s_i32(tcg_ctx, ret, ret);
            return;
        }
        break;
    }

    tcg_gen_shli_i32(tcg_ctx, ret, arg, 32 - len - ofs);
    tcg_gen_sari_i32(tcg_ctx, ret, ret, 32 - len);
}

/*
 * Extract 32-bits from a 64-bit input, ah:al, starting from ofs.
 * Unlike tcg_gen_extract_i32 above, len is fixed at 32.
 */
void tcg_gen_extract2_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 al, TCGv_i32 ah,
                          unsigned int ofs)
{
    tcg_debug_assert(ofs <= 32);
    if (ofs == 0) {
        tcg_gen_mov_i32(tcg_ctx, ret, al);
    } else if (ofs == 32) {
        tcg_gen_mov_i32(tcg_ctx, ret, ah);
    } else if (al == ah) {
        tcg_gen_rotri_i32(tcg_ctx, ret, al, ofs);
    } else if (TCG_TARGET_HAS_extract2_i32) {
        tcg_gen_op4i_i32(tcg_ctx, INDEX_op_extract2_i32, ret, al, ah, ofs);
    } else {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_shri_i32(tcg_ctx, t0, al, ofs);
        tcg_gen_deposit_i32(tcg_ctx, ret, t0, ah, 32 - ofs, ofs);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_movcond_i32(TCGContext *tcg_ctx, TCGCond cond, TCGv_i32 ret, TCGv_i32 c1,
                         TCGv_i32 c2, TCGv_i32 v1, TCGv_i32 v2)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_mov_i32(tcg_ctx, ret, v1);
    } else if (cond == TCG_COND_NEVER) {
        tcg_gen_mov_i32(tcg_ctx, ret, v2);
    } else if (TCG_TARGET_HAS_movcond_i32) {
        tcg_gen_op6i_i32(tcg_ctx, INDEX_op_movcond_i32, ret, c1, c2, v1, v2, cond);
    } else {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_setcond_i32(tcg_ctx, cond, t0, c1, c2);
        tcg_gen_neg_i32(tcg_ctx, t0, t0);
        tcg_gen_and_i32(tcg_ctx, t1, v1, t0);
        tcg_gen_andc_i32(tcg_ctx, ret, v2, t0);
        tcg_gen_or_i32(tcg_ctx, ret, ret, t1);
        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
    }
}

void tcg_gen_add2_i32(TCGContext *tcg_ctx, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 al,
                      TCGv_i32 ah, TCGv_i32 bl, TCGv_i32 bh)
{
    if (TCG_TARGET_HAS_add2_i32) {
        tcg_gen_op6_i32(tcg_ctx, INDEX_op_add2_i32, rl, rh, al, ah, bl, bh);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_concat_i32_i64(tcg_ctx, t0, al, ah);
        tcg_gen_concat_i32_i64(tcg_ctx, t1, bl, bh);
        tcg_gen_add_i64(tcg_ctx, t0, t0, t1);
        tcg_gen_extr_i64_i32(tcg_ctx, rl, rh, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
    }
}

void tcg_gen_sub2_i32(TCGContext *tcg_ctx, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 al,
                      TCGv_i32 ah, TCGv_i32 bl, TCGv_i32 bh)
{
    uc_engine *uc = tcg_ctx->uc;

    if (TCG_TARGET_HAS_sub2_i32) {
        if (HOOK_EXISTS_BOUNDED(uc, UC_HOOK_TCG_OPCODE, tcg_ctx->pc_start)) {
            struct hook *hook;
            HOOK_FOREACH_VAR_DECLARE;
            HOOK_FOREACH(uc, hook, UC_HOOK_TCG_OPCODE) {
                if (hook->to_delete)
                    continue;
                if (hook->op == UC_TCG_OP_SUB && hook->op_flags == 0) {
                    // Calling tcg_gen_sub_i64 will cause infinite recursion.
                    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
                    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
                    tcg_gen_concat_i32_i64(tcg_ctx, t0, al, ah);
                    tcg_gen_concat_i32_i64(tcg_ctx, t1, bl, bh);
                    gen_uc_traceopcode(tcg_ctx, hook, t0, t1, 32, uc, tcg_ctx->pc_start);
                    tcg_temp_free_i64(tcg_ctx, t0);
                    tcg_temp_free_i64(tcg_ctx, t1);
                }
            }
        }
        tcg_gen_op6_i32(tcg_ctx, INDEX_op_sub2_i32, rl, rh, al, ah, bl, bh);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_concat_i32_i64(tcg_ctx, t0, al, ah);
        tcg_gen_concat_i32_i64(tcg_ctx, t1, bl, bh);
        tcg_gen_sub_i64(tcg_ctx, t0, t0, t1);
        tcg_gen_extr_i64_i32(tcg_ctx, rl, rh, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
    }
}

void tcg_gen_mulu2_i32(TCGContext *tcg_ctx, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_mulu2_i32) {
        tcg_gen_op4_i32(tcg_ctx, INDEX_op_mulu2_i32, rl, rh, arg1, arg2);
    } else if (TCG_TARGET_HAS_muluh_i32) {
        TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_mul_i32, t, arg1, arg2);
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_muluh_i32, rh, arg1, arg2);
        tcg_gen_mov_i32(tcg_ctx, rl, t);
        tcg_temp_free_i32(tcg_ctx, t);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_extu_i32_i64(tcg_ctx, t0, arg1);
        tcg_gen_extu_i32_i64(tcg_ctx, t1, arg2);
        tcg_gen_mul_i64(tcg_ctx, t0, t0, t1);
        tcg_gen_extr_i64_i32(tcg_ctx, rl, rh, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
    }
}

void tcg_gen_muls2_i32(TCGContext *tcg_ctx, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_HAS_muls2_i32) {
        tcg_gen_op4_i32(tcg_ctx, INDEX_op_muls2_i32, rl, rh, arg1, arg2);
    } else if (TCG_TARGET_HAS_mulsh_i32) {
        TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_mul_i32, t, arg1, arg2);
        tcg_gen_op3_i32(tcg_ctx, INDEX_op_mulsh_i32, rh, arg1, arg2);
        tcg_gen_mov_i32(tcg_ctx, rl, t);
        tcg_temp_free_i32(tcg_ctx, t);
    } else if (TCG_TARGET_REG_BITS == 32) {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t2 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t3 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_mulu2_i32(tcg_ctx, t0, t1, arg1, arg2);
        /* Adjust for negative inputs.  */
        tcg_gen_sari_i32(tcg_ctx, t2, arg1, 31);
        tcg_gen_sari_i32(tcg_ctx, t3, arg2, 31);
        tcg_gen_and_i32(tcg_ctx, t2, t2, arg2);
        tcg_gen_and_i32(tcg_ctx, t3, t3, arg1);
        tcg_gen_sub_i32(tcg_ctx, rh, t1, t2);
        tcg_gen_sub_i32(tcg_ctx, rh, rh, t3);
        tcg_gen_mov_i32(tcg_ctx, rl, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
        tcg_temp_free_i32(tcg_ctx, t2);
        tcg_temp_free_i32(tcg_ctx, t3);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_ext_i32_i64(tcg_ctx, t0, arg1);
        tcg_gen_ext_i32_i64(tcg_ctx, t1, arg2);
        tcg_gen_mul_i64(tcg_ctx, t0, t0, t1);
        tcg_gen_extr_i64_i32(tcg_ctx, rl, rh, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
    }
}

void tcg_gen_mulsu2_i32(TCGContext *tcg_ctx, TCGv_i32 rl, TCGv_i32 rh, TCGv_i32 arg1, TCGv_i32 arg2)
{
    if (TCG_TARGET_REG_BITS == 32) {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t2 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_mulu2_i32(tcg_ctx, t0, t1, arg1, arg2);
        /* Adjust for negative input for the signed arg1.  */
        tcg_gen_sari_i32(tcg_ctx, t2, arg1, 31);
        tcg_gen_and_i32(tcg_ctx, t2, t2, arg2);
        tcg_gen_sub_i32(tcg_ctx, rh, t1, t2);
        tcg_gen_mov_i32(tcg_ctx, rl, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
        tcg_temp_free_i32(tcg_ctx, t2);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_ext_i32_i64(tcg_ctx, t0, arg1);
        tcg_gen_extu_i32_i64(tcg_ctx, t1, arg2);
        tcg_gen_mul_i64(tcg_ctx, t0, t0, t1);
        tcg_gen_extr_i64_i32(tcg_ctx, rl, rh, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
    }
}

void tcg_gen_ext8s_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_ext8s_i32) {
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_ext8s_i32, ret, arg);
    } else {
        tcg_gen_shli_i32(tcg_ctx, ret, arg, 24);
        tcg_gen_sari_i32(tcg_ctx, ret, ret, 24);
    }
}

void tcg_gen_ext16s_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_ext16s_i32) {
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_ext16s_i32, ret, arg);
    } else {
        tcg_gen_shli_i32(tcg_ctx, ret, arg, 16);
        tcg_gen_sari_i32(tcg_ctx, ret, ret, 16);
    }
}

void tcg_gen_ext8u_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_ext8u_i32) {
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_ext8u_i32, ret, arg);
    } else {
        tcg_gen_andi_i32(tcg_ctx, ret, arg, 0xffu);
    }
}

void tcg_gen_ext16u_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_ext16u_i32) {
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_ext16u_i32, ret, arg);
    } else {
        tcg_gen_andi_i32(tcg_ctx, ret, arg, 0xffffu);
    }
}

/* Note: we assume the two high bytes are set to zero */
void tcg_gen_bswap16_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_bswap16_i32) {
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_bswap16_i32, ret, arg);
    } else {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);

        tcg_gen_ext8u_i32(tcg_ctx, t0, arg);
        tcg_gen_shli_i32(tcg_ctx, t0, t0, 8);
        tcg_gen_shri_i32(tcg_ctx, ret, arg, 8);
        tcg_gen_or_i32(tcg_ctx, ret, ret, t0);
        tcg_temp_free_i32(tcg_ctx, t0);
    }
}

void tcg_gen_bswap32_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg)
{
    if (TCG_TARGET_HAS_bswap32_i32) {
        tcg_gen_op2_i32(tcg_ctx, INDEX_op_bswap32_i32, ret, arg);
    } else {
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t2 = tcg_const_i32(tcg_ctx, 0x00ff00ff);

                                        /* arg = abcd */
        tcg_gen_shri_i32(tcg_ctx, t0, arg, 8);   /*  t0 = .abc */
        tcg_gen_and_i32(tcg_ctx, t1, arg, t2);   /*  t1 = .b.d */
        tcg_gen_and_i32(tcg_ctx, t0, t0, t2);    /*  t0 = .a.c */
        tcg_gen_shli_i32(tcg_ctx, t1, t1, 8);    /*  t1 = b.d. */
        tcg_gen_or_i32(tcg_ctx, ret, t0, t1);    /* ret = badc */

        tcg_gen_shri_i32(tcg_ctx, t0, ret, 16);  /*  t0 = ..ba */
        tcg_gen_shli_i32(tcg_ctx, t1, ret, 16);  /*  t1 = dc.. */
        tcg_gen_or_i32(tcg_ctx, ret, t0, t1);    /* ret = dcba */

        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
        tcg_temp_free_i32(tcg_ctx, t2);
    }
}

void tcg_gen_smin_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 a, TCGv_i32 b)
{
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LT, ret, a, b, a, b);
}

void tcg_gen_umin_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 a, TCGv_i32 b)
{
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, ret, a, b, a, b);
}

void tcg_gen_smax_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 a, TCGv_i32 b)
{
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LT, ret, a, b, b, a);
}

void tcg_gen_umax_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 a, TCGv_i32 b)
{
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LTU, ret, a, b, b, a);
}

void tcg_gen_abs_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 a)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_sari_i32(tcg_ctx, t, a, 31);
    tcg_gen_xor_i32(tcg_ctx, ret, a, t);
    tcg_gen_sub_i32(tcg_ctx, ret, ret, t);
    tcg_temp_free_i32(tcg_ctx, t);
}

/* 64-bit ops */

#if TCG_TARGET_REG_BITS == 32
/* These are all inline for TCG_TARGET_REG_BITS == 64.  */

void tcg_gen_discard_i64(TCGContext *tcg_ctx, TCGv_i64 arg)
{
    tcg_gen_discard_i32(tcg_ctx, TCGV_LOW(tcg_ctx, arg));
    tcg_gen_discard_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, arg));
}

void tcg_gen_mov_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
    tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
    tcg_gen_mov_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg));
}

void tcg_gen_movi_i64(TCGContext *tcg_ctx, TCGv_i64 ret, int64_t arg)
{
    tcg_gen_movi_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg);
    tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), arg >> 32);
}

void tcg_gen_ld8u_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ld8u_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg2, offset);
    tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
}

void tcg_gen_ld8s_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ld8s_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg2, offset);
    tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 31);
}

void tcg_gen_ld16u_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ld16u_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg2, offset);
    tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
}

void tcg_gen_ld16s_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ld16s_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg2, offset);
    tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 31);
}

void tcg_gen_ld32u_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ld_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg2, offset);
    tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
}

void tcg_gen_ld32s_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    tcg_gen_ld_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg2, offset);
    tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 31);
}

void tcg_gen_ld_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_ptr arg2, tcg_target_long offset)
{
    /* Since arg2 and ret have different types,
       they cannot be the same temporary */
#ifdef HOST_WORDS_BIGENDIAN
    tcg_gen_ld_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), arg2, offset);
    tcg_gen_ld_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg2, offset + 4);
#else
    tcg_gen_ld_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg2, offset);
    tcg_gen_ld_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), arg2, offset + 4);
#endif
}

void tcg_gen_st_i64(TCGContext *tcg_ctx, TCGv_i64 arg1, TCGv_ptr arg2, tcg_target_long offset)
{
#ifdef HOST_WORDS_BIGENDIAN
    tcg_gen_st_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, arg1), arg2, offset);
    tcg_gen_st_i32(tcg_ctx, TCGV_LOW(tcg_ctx, arg1), arg2, offset + 4);
#else
    tcg_gen_st_i32(tcg_ctx, TCGV_LOW(tcg_ctx, arg1), arg2, offset);
    tcg_gen_st_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, arg1), arg2, offset + 4);
#endif
}

void tcg_gen_and_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_and_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
    tcg_gen_and_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
}

void tcg_gen_or_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_or_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
    tcg_gen_or_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
}

void tcg_gen_xor_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    tcg_gen_xor_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
    tcg_gen_xor_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
}

void tcg_gen_shl_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    gen_helper_shl_i64(tcg_ctx, ret, arg1, arg2);
}

void tcg_gen_shr_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    gen_helper_shr_i64(tcg_ctx, ret, arg1, arg2);
}

void tcg_gen_sar_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    gen_helper_sar_i64(tcg_ctx, ret, arg1, arg2);
}

void tcg_gen_mul_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
    TCGv_i64 t0;
    TCGv_i32 t1;

    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_mulu2_i32(tcg_ctx, TCGV_LOW(tcg_ctx, t0), TCGV_HIGH(tcg_ctx, t0),
                      TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));

    tcg_gen_mul_i32(tcg_ctx, t1, TCGV_LOW(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
    tcg_gen_add_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, t0), TCGV_HIGH(tcg_ctx, t0), t1);
    tcg_gen_mul_i32(tcg_ctx, t1, TCGV_HIGH(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
    tcg_gen_add_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, t0), TCGV_HIGH(tcg_ctx, t0), t1);

    tcg_gen_mov_i64(tcg_ctx, ret, t0);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i32(tcg_ctx, t1);
}
#endif /* TCG_TARGET_REG_SIZE == 32 */

void tcg_gen_addi_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_add_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
}

void tcg_gen_subfi_i64(TCGContext *tcg_ctx, TCGv_i64 ret, int64_t arg1, TCGv_i64 arg2)
{
    if (arg1 == 0 && TCG_TARGET_HAS_neg_i64) {
        /* Don't recurse with tcg_gen_neg_i64.  */
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_neg_i64, ret, arg2);
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg1);
        tcg_gen_sub_i64(tcg_ctx, ret, t0, arg2);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
}

void tcg_gen_subi_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_sub_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
}

void tcg_gen_andi_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_andi_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), arg2);
        tcg_gen_andi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), arg2 >> 32);
        return;
#else
    TCGv_i64 t0;

    /* Some cases can be optimized here.  */
    switch (arg2) {
    case 0:
        tcg_gen_movi_i64(tcg_ctx, ret, 0);
        return;
    case -1:
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
        return;
    case 0xff:
        /* Don't recurse with tcg_gen_ext8u_i64.  */
        if (TCG_TARGET_HAS_ext8u_i64) {
            tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext8u_i64, ret, arg1);
            return;
        }
        break;
    case 0xffff:
        if (TCG_TARGET_HAS_ext16u_i64) {
            tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext16u_i64, ret, arg1);
            return;
        }
        break;
    case 0xffffffffu:
        if (TCG_TARGET_HAS_ext32u_i64) {
            tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext32u_i64, ret, arg1);
            return;
        }
        break;
    }
    t0 = tcg_const_i64(tcg_ctx, arg2);
    tcg_gen_and_i64(tcg_ctx, ret, arg1, t0);
    tcg_temp_free_i64(tcg_ctx, t0);
#endif
}

void tcg_gen_ori_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_ori_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), arg2);
        tcg_gen_ori_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), arg2 >> 32);
        return;
#else
    /* Some cases can be optimized here.  */
    if (arg2 == -1) {
        tcg_gen_movi_i64(tcg_ctx, ret, -1);
    } else if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_or_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
#endif
}

void tcg_gen_xori_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_xori_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), arg2);
        tcg_gen_xori_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), arg2 >> 32);
        return;
#else
    /* Some cases can be optimized here.  */
    if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else if (arg2 == -1 && TCG_TARGET_HAS_not_i64) {
        /* Don't recurse with tcg_gen_not_i64.  */
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_not_i64, ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_xor_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
#endif
}

#if TCG_TARGET_REG_BITS == 32
static inline void tcg_gen_shifti_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1,
                                      unsigned c, bool right, bool arith)
{
    tcg_debug_assert(c < 64);
    if (c == 0) {
        tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1));
        tcg_gen_mov_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1));
    } else if (c >= 32) {
        c -= 32;
        if (right) {
            if (arith) {
                tcg_gen_sari_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), c);
                tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), 31);
            } else {
                tcg_gen_shri_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), c);
                tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
            }
        } else {
            tcg_gen_shli_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), c);
            tcg_gen_movi_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), 0);
        }
    } else if (right) {
        if (TCG_TARGET_HAS_extract2_i32) {
            tcg_gen_extract2_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret),
                                 TCGV_LOW(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg1), c);
        } else {
            tcg_gen_shri_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), c);
            tcg_gen_deposit_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret),
                                TCGV_HIGH(tcg_ctx, arg1), 32 - c, c);
        }
        if (arith) {
            tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), c);
        } else {
            tcg_gen_shri_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), c);
        }
    } else {
        if (TCG_TARGET_HAS_extract2_i32) {
            tcg_gen_extract2_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret),
                                 TCGV_LOW(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg1), 32 - c);
        } else {
            TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
            tcg_gen_shri_i32(tcg_ctx, t0, TCGV_LOW(tcg_ctx, arg1), 32 - c);
            tcg_gen_deposit_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), t0,
                                TCGV_HIGH(tcg_ctx, arg1), c, 32 - c);
            tcg_temp_free_i32(tcg_ctx, t0);
        }
        tcg_gen_shli_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), c);
    }
}
#endif

void tcg_gen_shli_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 64);
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_shifti_i64(tcg_ctx, ret, arg1, arg2, 0, 0);
#else
    if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_shl_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
#endif
}

void tcg_gen_shri_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 64);
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_shifti_i64(tcg_ctx, ret, arg1, arg2, 1, 0);
#else
    if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_shr_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
#endif
}

void tcg_gen_sari_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    tcg_debug_assert(arg2 >= 0 && arg2 < 64);
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_shifti_i64(tcg_ctx, ret, arg1, arg2, 1, 1);
#else
    if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_sar_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
#endif
}

void tcg_gen_brcond_i64(TCGContext *tcg_ctx, TCGCond cond, TCGv_i64 arg1, TCGv_i64 arg2, TCGLabel *l)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_br(tcg_ctx, l);
    } else if (cond != TCG_COND_NEVER) {
        l->refs++;
#if TCG_TARGET_REG_BITS == 32
            tcg_gen_op6ii_i32(tcg_ctx, INDEX_op_brcond2_i32, TCGV_LOW(tcg_ctx, arg1),
                              TCGV_HIGH(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2),
                              TCGV_HIGH(tcg_ctx, arg2), cond, label_arg(l));
#else
            tcg_gen_op4ii_i64(tcg_ctx, INDEX_op_brcond_i64, arg1, arg2, cond,
                              label_arg(l));
#endif
    }
}

void tcg_gen_brcondi_i64(TCGContext *tcg_ctx, TCGCond cond, TCGv_i64 arg1, int64_t arg2, TCGLabel *l)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_br(tcg_ctx, l);
    } else if (cond != TCG_COND_NEVER) {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_brcond_i64(tcg_ctx, cond, arg1, t0, l);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
}

void tcg_gen_setcond_i64(TCGContext *tcg_ctx, TCGCond cond, TCGv_i64 ret,
                         TCGv_i64 arg1, TCGv_i64 arg2)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_movi_i64(tcg_ctx, ret, 1);
    } else if (cond == TCG_COND_NEVER) {
        tcg_gen_movi_i64(tcg_ctx, ret, 0);
    } else {
#if TCG_TARGET_REG_BITS == 32
            tcg_gen_op6i_i32(tcg_ctx, INDEX_op_setcond2_i32, TCGV_LOW(tcg_ctx, ret),
                             TCGV_LOW(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg1),
                             TCGV_LOW(tcg_ctx, arg2), TCGV_HIGH(tcg_ctx, arg2), cond);
            tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
#else
            tcg_gen_op4i_i64(tcg_ctx, INDEX_op_setcond_i64, ret, arg1, arg2, cond);
#endif
    }
}

void tcg_gen_setcondi_i64(TCGContext *tcg_ctx, TCGCond cond, TCGv_i64 ret,
                          TCGv_i64 arg1, int64_t arg2)
{
    TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
    tcg_gen_setcond_i64(tcg_ctx, cond, ret, arg1, t0);
    tcg_temp_free_i64(tcg_ctx, t0);
}

void tcg_gen_muli_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, int64_t arg2)
{
    if (arg2 == 0) {
        tcg_gen_movi_i64(tcg_ctx, ret, 0);
    } else if (is_power_of_2(arg2)) {
        tcg_gen_shli_i64(tcg_ctx, ret, arg1, ctz64(arg2));
    } else {
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_mul_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
}

void tcg_gen_div_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_div_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_div_i64, ret, arg1, arg2);
#elif TCG_TARGET_HAS_div2_i64
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_sari_i64(tcg_ctx, t0, arg1, 63);
        tcg_gen_op5_i64(tcg_ctx, INDEX_op_div2_i64, ret, t0, arg1, t0, arg2);
        tcg_temp_free_i64(tcg_ctx, t0);
#else
        gen_helper_div_i64(tcg_ctx, ret, arg1, arg2);
#endif
}

void tcg_gen_rem_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_rem_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_rem_i64, ret, arg1, arg2);
#elif TCG_TARGET_HAS_div_i64
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_div_i64, t0, arg1, arg2);
        tcg_gen_mul_i64(tcg_ctx, t0, t0, arg2);
        tcg_gen_sub_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
#elif TCG_TARGET_HAS_div2_i64
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_sari_i64(tcg_ctx, t0, arg1, 63);
        tcg_gen_op5_i64(tcg_ctx, INDEX_op_div2_i64, t0, ret, arg1, t0, arg2);
        tcg_temp_free_i64(tcg_ctx, t0);
#else
        gen_helper_rem_i64(tcg_ctx, ret, arg1, arg2);
#endif
}

void tcg_gen_divu_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_div_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_divu_i64, ret, arg1, arg2);
#elif TCG_TARGET_HAS_div2_i64
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_movi_i64(tcg_ctx, t0, 0);
        tcg_gen_op5_i64(tcg_ctx, INDEX_op_divu2_i64, ret, t0, arg1, t0, arg2);
        tcg_temp_free_i64(tcg_ctx, t0);
#else
        gen_helper_divu_i64(tcg_ctx, ret, arg1, arg2);
#endif
}

void tcg_gen_remu_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_rem_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_remu_i64, ret, arg1, arg2);
#elif TCG_TARGET_HAS_div_i64
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_divu_i64, t0, arg1, arg2);
        tcg_gen_mul_i64(tcg_ctx, t0, t0, arg2);
        tcg_gen_sub_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
#elif TCG_TARGET_HAS_div2_i64
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_movi_i64(tcg_ctx, t0, 0);
        tcg_gen_op5_i64(tcg_ctx, INDEX_op_divu2_i64, t0, ret, arg1, t0, arg2);
        tcg_temp_free_i64(tcg_ctx, t0);
#else
        gen_helper_remu_i64(tcg_ctx, ret, arg1, arg2);
#endif
}

void tcg_gen_ext8s_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_ext8s_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 31);
#elif TCG_TARGET_HAS_ext8s_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext8s_i64, ret, arg);
#else
        tcg_gen_shli_i64(tcg_ctx, ret, arg, 56);
        tcg_gen_sari_i64(tcg_ctx, ret, ret, 56);
#endif
}

void tcg_gen_ext16s_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_ext16s_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 31);
#elif TCG_TARGET_HAS_ext16s_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext16s_i64, ret, arg);
#else
        tcg_gen_shli_i64(tcg_ctx, ret, arg, 48);
        tcg_gen_sari_i64(tcg_ctx, ret, ret, 48);
#endif
}

void tcg_gen_ext32s_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 31);
#elif TCG_TARGET_HAS_ext32s_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext32s_i64, ret, arg);
#else
        tcg_gen_shli_i64(tcg_ctx, ret, arg, 32);
        tcg_gen_sari_i64(tcg_ctx, ret, ret, 32);
#endif
}

void tcg_gen_ext8u_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_ext8u_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
#elif TCG_TARGET_HAS_ext8u_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext8u_i64, ret, arg);
#else
        tcg_gen_andi_i64(tcg_ctx, ret, arg, 0xffu);
#endif
}

void tcg_gen_ext16u_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_ext16u_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
#elif TCG_TARGET_HAS_ext16u_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext16u_i64, ret, arg);
#else
        tcg_gen_andi_i64(tcg_ctx, ret, arg, 0xffffu);
#endif
}

void tcg_gen_ext32u_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
#elif TCG_TARGET_HAS_ext32u_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_ext32u_i64, ret, arg);
#else
        tcg_gen_andi_i64(tcg_ctx, ret, arg, 0xffffffffu);
#endif
}

/* Note: we assume the six high bytes are set to zero */
void tcg_gen_bswap16_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_bswap16_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
#elif TCG_TARGET_HAS_bswap16_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_bswap16_i64, ret, arg);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);

        tcg_gen_ext8u_i64(tcg_ctx, t0, arg);
        tcg_gen_shli_i64(tcg_ctx, t0, t0, 8);
        tcg_gen_shri_i64(tcg_ctx, ret, arg, 8);
        tcg_gen_or_i64(tcg_ctx, ret, ret, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
#endif
}

/* Note: we assume the four high bytes are set to zero */
void tcg_gen_bswap32_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_bswap32_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
#elif TCG_TARGET_HAS_bswap32_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_bswap32_i64, ret, arg);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t2 = tcg_const_i64(tcg_ctx, 0x00ff00ff);

                                        /* arg = ....abcd */
        tcg_gen_shri_i64(tcg_ctx, t0, arg, 8);   /*  t0 = .....abc */
        tcg_gen_and_i64(tcg_ctx, t1, arg, t2);   /*  t1 = .....b.d */
        tcg_gen_and_i64(tcg_ctx, t0, t0, t2);    /*  t0 = .....a.c */
        tcg_gen_shli_i64(tcg_ctx, t1, t1, 8);    /*  t1 = ....b.d. */
        tcg_gen_or_i64(tcg_ctx, ret, t0, t1);    /* ret = ....badc */

        tcg_gen_shli_i64(tcg_ctx, t1, ret, 48);  /*  t1 = dc...... */
        tcg_gen_shri_i64(tcg_ctx, t0, ret, 16);  /*  t0 = ......ba */
        tcg_gen_shri_i64(tcg_ctx, t1, t1, 32);   /*  t1 = ....dc.. */
        tcg_gen_or_i64(tcg_ctx, ret, t0, t1);    /* ret = ....dcba */

        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
        tcg_temp_free_i64(tcg_ctx, t2);
#endif
}

void tcg_gen_bswap64_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        TCGv_i32 t0, t1;
        t0 = tcg_temp_new_i32(tcg_ctx);
        t1 = tcg_temp_new_i32(tcg_ctx);

        tcg_gen_bswap32_i32(tcg_ctx, t0, TCGV_LOW(tcg_ctx, arg));
        tcg_gen_bswap32_i32(tcg_ctx, t1, TCGV_HIGH(tcg_ctx, arg));
        tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), t1);
        tcg_gen_mov_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), t0);
        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
#elif TCG_TARGET_HAS_bswap64_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_bswap64_i64, ret, arg);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

                                        /* arg = abcdefgh */
        tcg_gen_movi_i64(tcg_ctx, t2, 0x00ff00ff00ff00ffull);
        tcg_gen_shri_i64(tcg_ctx, t0, arg, 8);   /*  t0 = .abcdefg */
        tcg_gen_and_i64(tcg_ctx, t1, arg, t2);   /*  t1 = .b.d.f.h */
        tcg_gen_and_i64(tcg_ctx, t0, t0, t2);    /*  t0 = .a.c.e.g */
        tcg_gen_shli_i64(tcg_ctx, t1, t1, 8);    /*  t1 = b.d.f.h. */
        tcg_gen_or_i64(tcg_ctx, ret, t0, t1);    /* ret = badcfehg */

        tcg_gen_movi_i64(tcg_ctx, t2, 0x0000ffff0000ffffull);
        tcg_gen_shri_i64(tcg_ctx, t0, ret, 16);  /*  t0 = ..badcfe */
        tcg_gen_and_i64(tcg_ctx, t1, ret, t2);   /*  t1 = ..dc..hg */
        tcg_gen_and_i64(tcg_ctx, t0, t0, t2);    /*  t0 = ..ba..fe */
        tcg_gen_shli_i64(tcg_ctx, t1, t1, 16);   /*  t1 = dc..hg.. */
        tcg_gen_or_i64(tcg_ctx, ret, t0, t1);    /* ret = dcbahgfe */

        tcg_gen_shri_i64(tcg_ctx, t0, ret, 32);  /*  t0 = ....dcba */
        tcg_gen_shli_i64(tcg_ctx, t1, ret, 32);  /*  t1 = hgfe.... */
        tcg_gen_or_i64(tcg_ctx, ret, t0, t1);    /* ret = hgfedcba */

        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
        tcg_temp_free_i64(tcg_ctx, t2);
#endif
}

void tcg_gen_not_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_not_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
        tcg_gen_not_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg));
#elif TCG_TARGET_HAS_not_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_not_i64, ret, arg);
#else
        tcg_gen_xori_i64(tcg_ctx, ret, arg, -1);
#endif
}

void tcg_gen_andc_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_andc_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
        tcg_gen_andc_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
#elif TCG_TARGET_HAS_andc_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_andc_i64, ret, arg1, arg2);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_not_i64(tcg_ctx, t0, arg2);
        tcg_gen_and_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
#endif
}

void tcg_gen_eqv_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_eqv_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
        tcg_gen_eqv_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
#elif TCG_TARGET_HAS_eqv_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_eqv_i64, ret, arg1, arg2);
#else
        tcg_gen_xor_i64(tcg_ctx, ret, arg1, arg2);
        tcg_gen_not_i64(tcg_ctx, ret, ret);
#endif
}

void tcg_gen_nand_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_nand_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
        tcg_gen_nand_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
#elif TCG_TARGET_HAS_nand_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_nand_i64, ret, arg1, arg2);
#else
        tcg_gen_and_i64(tcg_ctx, ret, arg1, arg2);
        tcg_gen_not_i64(tcg_ctx, ret, ret);
#endif
}

void tcg_gen_nor_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_nor_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
        tcg_gen_nor_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
#elif TCG_TARGET_HAS_nor_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_nor_i64, ret, arg1, arg2);
#else
        tcg_gen_or_i64(tcg_ctx, ret, arg1, arg2);
        tcg_gen_not_i64(tcg_ctx, ret, ret);
#endif
}

void tcg_gen_orc_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_orc_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), TCGV_LOW(tcg_ctx, arg2));
        tcg_gen_orc_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), TCGV_HIGH(tcg_ctx, arg2));
#elif TCG_TARGET_HAS_orc_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_orc_i64, ret, arg1, arg2);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_not_i64(tcg_ctx, t0, arg2);
        tcg_gen_or_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
#endif
}

void tcg_gen_clz_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_clz_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_clz_i64, ret, arg1, arg2);
#else
        gen_helper_clz_i64(tcg_ctx, ret, arg1, arg2);
#endif
}

void tcg_gen_clzi_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2)
{
#if TCG_TARGET_REG_BITS == 32 && TCG_TARGET_HAS_clz_i32
    if (arg2 <= 0xffffffffu) {
        TCGv_i32 t = tcg_const_i32(tcg_ctx, (uint32_t)arg2 - 32);
        tcg_gen_clz_i32(tcg_ctx, t, TCGV_LOW(tcg_ctx, arg1), t);
        tcg_gen_addi_i32(tcg_ctx, t, t, 32);
        tcg_gen_clz_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1), t);
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
        tcg_temp_free_i32(tcg_ctx, t);
    } else
#endif
    {
        TCGv_i64 t = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_clz_i64(tcg_ctx, ret, arg1, t);
        tcg_temp_free_i64(tcg_ctx, t);
    }
}

void tcg_gen_ctz_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_ctz_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_ctz_i64, ret, arg1, arg2);
#elif TCG_TARGET_HAS_ctpop_i64 || TCG_TARGET_HAS_clz_i64
        TCGv_i64 z, t = tcg_temp_new_i64(tcg_ctx);
#if TCG_TARGET_HAS_ctpop_i64
            tcg_gen_subi_i64(tcg_ctx, t, arg1, 1);
            tcg_gen_andc_i64(tcg_ctx, t, t, arg1);
            tcg_gen_ctpop_i64(tcg_ctx, t, t);
#else
            /* Since all non-x86 hosts have clz(0) == 64, don't fight it.  */
            tcg_gen_neg_i64(tcg_ctx, t, arg1);
            tcg_gen_and_i64(tcg_ctx, t, t, arg1);
            tcg_gen_clzi_i64(tcg_ctx, t, t, 64);
            tcg_gen_xori_i64(tcg_ctx, t, t, 63);
#endif
        z = tcg_const_i64(tcg_ctx, 0);
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, ret, arg1, z, arg2, t);
        tcg_temp_free_i64(tcg_ctx, t);
        tcg_temp_free_i64(tcg_ctx, z);
#else
        gen_helper_ctz_i64(tcg_ctx, ret, arg1, arg2);
#endif
}

void tcg_gen_ctzi_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, uint64_t arg2)
{
#if TCG_TARGET_REG_BITS == 32 && TCG_TARGET_HAS_ctz_i32
    if (arg2 <= 0xffffffffu) {
        TCGv_i32 t32 = tcg_const_i32(tcg_ctx, (uint32_t)arg2 - 32);
        tcg_gen_ctz_i32(tcg_ctx, t32, TCGV_HIGH(tcg_ctx, arg1), t32);
        tcg_gen_addi_i32(tcg_ctx, t32, t32, 32);
        tcg_gen_ctz_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1), t32);
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
        tcg_temp_free_i32(tcg_ctx, t32);
    } else
#endif
#if !TCG_TARGET_HAS_ctz_i64 && TCG_TARGET_HAS_ctpop_i64
    if (arg2 == 64) {
        /* This equivalence has the advantage of not requiring a fixup.  */
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_subi_i64(tcg_ctx, t, arg1, 1);
        tcg_gen_andc_i64(tcg_ctx, t, t, arg1);
        tcg_gen_ctpop_i64(tcg_ctx, ret, t);
        tcg_temp_free_i64(tcg_ctx, t);
    } else
#endif
    {
        TCGv_i64 t64 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_ctz_i64(tcg_ctx, ret, arg1, t64);
        tcg_temp_free_i64(tcg_ctx, t64);
    }
}

void tcg_gen_clrsb_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg)
{
#if TCG_TARGET_HAS_clz_i64 || TCG_TARGET_HAS_clz_i32
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_sari_i64(tcg_ctx, t, arg, 63);
        tcg_gen_xor_i64(tcg_ctx, t, t, arg);
        tcg_gen_clzi_i64(tcg_ctx, t, t, 64);
        tcg_gen_subi_i64(tcg_ctx, ret, t, 1);
        tcg_temp_free_i64(tcg_ctx, t);
#else
        gen_helper_clrsb_i64(tcg_ctx, ret, arg);
#endif
}

void tcg_gen_ctpop_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1)
{
#if TCG_TARGET_HAS_ctpop_i64
        tcg_gen_op2_i64(tcg_ctx, INDEX_op_ctpop_i64, ret, arg1);
#elif TCG_TARGET_REG_BITS == 32 && TCG_TARGET_HAS_ctpop_i32
        tcg_gen_ctpop_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1));
        tcg_gen_ctpop_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1));
        tcg_gen_add_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, ret));
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
#else
        gen_helper_ctpop_i64(tcg_ctx, ret, arg1);
#endif
}

void tcg_gen_rotl_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_rot_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_rotl_i64, ret, arg1, arg2);
#else
        TCGv_i64 t0, t1;
        t0 = tcg_temp_new_i64(tcg_ctx);
        t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_shl_i64(tcg_ctx, t0, arg1, arg2);
        tcg_gen_subfi_i64(tcg_ctx, t1, 64, arg2);
        tcg_gen_shr_i64(tcg_ctx, t1, arg1, t1);
        tcg_gen_or_i64(tcg_ctx, ret, t0, t1);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
#endif
}

void tcg_gen_rotli_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 64);
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else {
#if TCG_TARGET_HAS_rot_i64
        TCGv_i64 t0 = tcg_const_i64(tcg_ctx, arg2);
        tcg_gen_rotl_i64(tcg_ctx, ret, arg1, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
#else
        TCGv_i64 t0, t1;
        t0 = tcg_temp_new_i64(tcg_ctx);
        t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_shli_i64(tcg_ctx, t0, arg1, arg2);
        tcg_gen_shri_i64(tcg_ctx, t1, arg1, 64 - arg2);
        tcg_gen_or_i64(tcg_ctx, ret, t0, t1);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
#endif
    }
}

void tcg_gen_rotr_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_rot_i64
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_rotr_i64, ret, arg1, arg2);
#else
        TCGv_i64 t0, t1;
        t0 = tcg_temp_new_i64(tcg_ctx);
        t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_shr_i64(tcg_ctx, t0, arg1, arg2);
        tcg_gen_subfi_i64(tcg_ctx, t1, 64, arg2);
        tcg_gen_shl_i64(tcg_ctx, t1, arg1, t1);
        tcg_gen_or_i64(tcg_ctx, ret, t0, t1);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
#endif
}

void tcg_gen_rotri_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, unsigned arg2)
{
    tcg_debug_assert(arg2 < 64);
    /* some cases can be optimized here */
    if (arg2 == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg1);
    } else {
        tcg_gen_rotli_i64(tcg_ctx, ret, arg1, 64 - arg2);
    }
}

void tcg_gen_deposit_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg1, TCGv_i64 arg2,
                         unsigned int ofs, unsigned int len)
{
    uint64_t mask;
    TCGv_i64 t1;

    tcg_debug_assert(ofs < 64);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 64);
    tcg_debug_assert(ofs + len <= 64);

    if (len == 64) {
        tcg_gen_mov_i64(tcg_ctx, ret, arg2);
        return;
    }

#if TCG_TARGET_HAS_deposit_i64
    if (TCG_TARGET_deposit_i64_valid(ofs, len)) {
        tcg_gen_op5ii_i64(tcg_ctx, INDEX_op_deposit_i64, ret, arg1, arg2, ofs, len);
        return;
    }
#endif

#if TCG_TARGET_REG_BITS == 32
        if (ofs >= 32) {
            tcg_gen_deposit_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1),
                                TCGV_LOW(tcg_ctx, arg2), ofs - 32, len);
            tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1));
            return;
        }
        if (ofs + len <= 32) {
            tcg_gen_deposit_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg1),
                                TCGV_LOW(tcg_ctx, arg2), ofs, len);
            tcg_gen_mov_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg1));
            return;
        }
#endif

    t1 = tcg_temp_new_i64(tcg_ctx);

#if TCG_TARGET_HAS_extract2_i64
        if (ofs + len == 64) {
            tcg_gen_shli_i64(tcg_ctx, t1, arg1, len);
            tcg_gen_extract2_i64(tcg_ctx, ret, t1, arg2, len);
            goto done;
        }
        if (ofs == 0) {
            tcg_gen_extract2_i64(tcg_ctx, ret, arg1, arg2, len);
            tcg_gen_rotli_i64(tcg_ctx, ret, ret, len);
            goto done;
        }
#endif

    mask = (1ull << len) - 1;
    if (ofs + len < 64) {
        tcg_gen_andi_i64(tcg_ctx, t1, arg2, mask);
        tcg_gen_shli_i64(tcg_ctx, t1, t1, ofs);
    } else {
        tcg_gen_shli_i64(tcg_ctx, t1, arg2, ofs);
    }
    tcg_gen_andi_i64(tcg_ctx, ret, arg1, ~(mask << ofs));
    tcg_gen_or_i64(tcg_ctx, ret, ret, t1);
#if TCG_TARGET_HAS_extract2_i64
 done:
#endif
    tcg_temp_free_i64(tcg_ctx, t1);
}

void tcg_gen_deposit_z_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg,
                           unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 64);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 64);
    tcg_debug_assert(ofs + len <= 64);

    if (ofs + len == 64) {
        tcg_gen_shli_i64(tcg_ctx, ret, arg, ofs);
    } else if (ofs == 0) {
        tcg_gen_andi_i64(tcg_ctx, ret, arg, (1ull << len) - 1);
#if TCG_TARGET_HAS_deposit_i64
    } else if (TCG_TARGET_deposit_i64_valid(ofs, len)) {
        TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);
        tcg_gen_op5ii_i64(tcg_ctx, INDEX_op_deposit_i64, ret, zero, arg, ofs, len);
        tcg_temp_free_i64(tcg_ctx, zero);
#endif
    } else {
#if TCG_TARGET_REG_BITS == 32
            if (ofs >= 32) {
                tcg_gen_deposit_z_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg),
                                      ofs - 32, len);
                tcg_gen_movi_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), 0);
                return;
            }
            if (ofs + len <= 32) {
                tcg_gen_deposit_z_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg), ofs, len);
                tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
                return;
            }
#endif
        /* To help two-operand hosts we prefer to zero-extend first,
           which allows ARG to stay live.  */
        switch (len) {
        case 32:
#if TCG_TARGET_HAS_ext32u_i64
                tcg_gen_ext32u_i64(tcg_ctx, ret, arg);
                tcg_gen_shli_i64(tcg_ctx, ret, ret, ofs);
                return;
#endif
            break;
        case 16:
#if TCG_TARGET_HAS_ext16u_i64
                tcg_gen_ext16u_i64(tcg_ctx, ret, arg);
                tcg_gen_shli_i64(tcg_ctx, ret, ret, ofs);
                return;
#endif
            break;
        case 8:
#if TCG_TARGET_HAS_ext8u_i64
                tcg_gen_ext8u_i64(tcg_ctx, ret, arg);
                tcg_gen_shli_i64(tcg_ctx, ret, ret, ofs);
                return;
#endif
            break;
        }
        /* Otherwise prefer zero-extension over AND for code size.  */
        switch (ofs + len) {
        case 32:
#if TCG_TARGET_HAS_ext32u_i64
                tcg_gen_shli_i64(tcg_ctx, ret, arg, ofs);
                tcg_gen_ext32u_i64(tcg_ctx, ret, ret);
                return;
#endif
            break;
        case 16:
#if TCG_TARGET_HAS_ext16u_i64
                tcg_gen_shli_i64(tcg_ctx, ret, arg, ofs);
                tcg_gen_ext16u_i64(tcg_ctx, ret, ret);
                return;
#endif
            break;
        case 8:
#if TCG_TARGET_HAS_ext8u_i64
                tcg_gen_shli_i64(tcg_ctx, ret, arg, ofs);
                tcg_gen_ext8u_i64(tcg_ctx, ret, ret);
                return;
#endif
            break;
        }
        tcg_gen_andi_i64(tcg_ctx, ret, arg, (1ull << len) - 1);
        tcg_gen_shli_i64(tcg_ctx, ret, ret, ofs);
    }
}

void tcg_gen_extract_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg,
                         unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 64);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 64);
    tcg_debug_assert(ofs + len <= 64);

    /* Canonicalize certain special cases, even if extract is supported.  */
    if (ofs + len == 64) {
        tcg_gen_shri_i64(tcg_ctx, ret, arg, 64 - len);
        return;
    }
    if (ofs == 0) {
        tcg_gen_andi_i64(tcg_ctx, ret, arg, (1ull << len) - 1);
        return;
    }

#if TCG_TARGET_REG_BITS == 32
        /* Look for a 32-bit extract within one of the two words.  */
        if (ofs >= 32) {
            tcg_gen_extract_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg), ofs - 32, len);
            tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
            return;
        }
        if (ofs + len <= 32) {
            tcg_gen_extract_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg), ofs, len);
            tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
            return;
        }
        /* The field is split across two words.  One double-word
           shift is better than two double-word shifts.  */
        goto do_shift_and;
#endif

#if TCG_TARGET_HAS_extract_i64
    if (TCG_TARGET_extract_i64_valid(ofs, len)) {
        tcg_gen_op4ii_i64(tcg_ctx, INDEX_op_extract_i64, ret, arg, ofs, len);
        return;
    }
#endif

    /* Assume that zero-extension, if available, is cheaper than a shift.  */
    switch (ofs + len) {
    case 32:
#if TCG_TARGET_HAS_ext32u_i64
            tcg_gen_ext32u_i64(tcg_ctx, ret, arg);
            tcg_gen_shri_i64(tcg_ctx, ret, ret, ofs);
            return;
#endif
        break;
    case 16:
#if TCG_TARGET_HAS_ext16u_i64
            tcg_gen_ext16u_i64(tcg_ctx, ret, arg);
            tcg_gen_shri_i64(tcg_ctx, ret, ret, ofs);
            return;
#endif
        break;
    case 8:
#if TCG_TARGET_HAS_ext8u_i64
            tcg_gen_ext8u_i64(tcg_ctx, ret, arg);
            tcg_gen_shri_i64(tcg_ctx, ret, ret, ofs);
            return;
#endif
        break;
    }

    /* ??? Ideally we'd know what values are available for immediate AND.
       Assume that 8 bits are available, plus the special cases of 16 and 32,
       so that we get ext8u, ext16u, and ext32u.  */
    switch (len) {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 16:
    case 32:
#if TCG_TARGET_REG_BITS == 32
    do_shift_and:
#endif
        tcg_gen_shri_i64(tcg_ctx, ret, arg, ofs);
        tcg_gen_andi_i64(tcg_ctx, ret, ret, (1ull << len) - 1);
        break;
    default:
        tcg_gen_shli_i64(tcg_ctx, ret, arg, 64 - len - ofs);
        tcg_gen_shri_i64(tcg_ctx, ret, ret, 64 - len);
        break;
    }
}

void tcg_gen_sextract_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg,
                          unsigned int ofs, unsigned int len)
{
    tcg_debug_assert(ofs < 64);
    tcg_debug_assert(len > 0);
    tcg_debug_assert(len <= 64);
    tcg_debug_assert(ofs + len <= 64);

    /* Canonicalize certain special cases, even if sextract is supported.  */
    if (ofs + len == 64) {
        tcg_gen_sari_i64(tcg_ctx, ret, arg, 64 - len);
        return;
    }
    if (ofs == 0) {
        switch (len) {
        case 32:
            tcg_gen_ext32s_i64(tcg_ctx, ret, arg);
            return;
        case 16:
            tcg_gen_ext16s_i64(tcg_ctx, ret, arg);
            return;
        case 8:
            tcg_gen_ext8s_i64(tcg_ctx, ret, arg);
            return;
        }
    }

#if TCG_TARGET_REG_BITS == 32
        /* Look for a 32-bit extract within one of the two words.  */
        if (ofs >= 32) {
            tcg_gen_sextract_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg), ofs - 32, len);
        } else if (ofs + len <= 32) {
            tcg_gen_sextract_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg), ofs, len);
        } else if (ofs == 0) {
            tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, arg));
            tcg_gen_sextract_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, arg), 0, len - 32);
            return;
        } else if (len > 32) {
            TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
            /* Extract the bits for the high word normally.  */
            tcg_gen_sextract_i32(tcg_ctx, t, TCGV_HIGH(tcg_ctx, arg), ofs + 32, len - 32);
            /* Shift the field down for the low part.  */
            tcg_gen_shri_i64(tcg_ctx, ret, arg, ofs);
            /* Overwrite the shift into the high part.  */
            tcg_gen_mov_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), t);
            tcg_temp_free_i32(tcg_ctx, t);
            return;
        } else {
            /* Shift the field down for the low part, such that the
               field sits at the MSB.  */
            tcg_gen_shri_i64(tcg_ctx, ret, arg, ofs + len - 32);
            /* Shift the field down from the MSB, sign extending.  */
            tcg_gen_sari_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 32 - len);
        }
        /* Sign-extend the field from 32 bits.  */
        tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 31);
        return;
#endif

#if TCG_TARGET_HAS_sextract_i64
    if (TCG_TARGET_extract_i64_valid(ofs, len)) {
        tcg_gen_op4ii_i64(tcg_ctx, INDEX_op_sextract_i64, ret, arg, ofs, len);
        return;
    }
#endif

    /* Assume that sign-extension, if available, is cheaper than a shift.  */
    switch (ofs + len) {
    case 32:
#if TCG_TARGET_HAS_ext32s_i64
            tcg_gen_ext32s_i64(tcg_ctx, ret, arg);
            tcg_gen_sari_i64(tcg_ctx, ret, ret, ofs);
            return;
#endif
        break;
    case 16:
#if TCG_TARGET_HAS_ext16s_i64
            tcg_gen_ext16s_i64(tcg_ctx, ret, arg);
            tcg_gen_sari_i64(tcg_ctx, ret, ret, ofs);
            return;
#endif
        break;
    case 8:
#if TCG_TARGET_HAS_ext8s_i64
            tcg_gen_ext8s_i64(tcg_ctx, ret, arg);
            tcg_gen_sari_i64(tcg_ctx, ret, ret, ofs);
            return;
#endif
        break;
    }
    switch (len) {
    case 32:
#if TCG_TARGET_HAS_ext32s_i64
            tcg_gen_shri_i64(tcg_ctx, ret, arg, ofs);
            tcg_gen_ext32s_i64(tcg_ctx, ret, ret);
            return;
#endif
        break;
    case 16:
#if TCG_TARGET_HAS_ext16s_i64
            tcg_gen_shri_i64(tcg_ctx, ret, arg, ofs);
            tcg_gen_ext16s_i64(tcg_ctx, ret, ret);
            return;
#endif
        break;
    case 8:
#if TCG_TARGET_HAS_ext8s_i64
            tcg_gen_shri_i64(tcg_ctx, ret, arg, ofs);
            tcg_gen_ext8s_i64(tcg_ctx, ret, ret);
            return;
#endif
        break;
    }
    tcg_gen_shli_i64(tcg_ctx, ret, arg, 64 - len - ofs);
    tcg_gen_sari_i64(tcg_ctx, ret, ret, 64 - len);
}

/*
 * Extract 64 bits from a 128-bit input, ah:al, starting from ofs.
 * Unlike tcg_gen_extract_i64 above, len is fixed at 64.
 */
void tcg_gen_extract2_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 al, TCGv_i64 ah,
                          unsigned int ofs)
{
    tcg_debug_assert(ofs <= 64);
    if (ofs == 0) {
        tcg_gen_mov_i64(tcg_ctx, ret, al);
    } else if (ofs == 64) {
        tcg_gen_mov_i64(tcg_ctx, ret, ah);
    } else if (al == ah) {
        tcg_gen_rotri_i64(tcg_ctx, ret, al, ofs);
    } else {
#if TCG_TARGET_HAS_extract2_i64
        tcg_gen_op4i_i64(tcg_ctx, INDEX_op_extract2_i64, ret, al, ah, ofs);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_shri_i64(tcg_ctx, t0, al, ofs);
        tcg_gen_deposit_i64(tcg_ctx, ret, t0, ah, 64 - ofs, ofs);
        tcg_temp_free_i64(tcg_ctx, t0);
#endif
    }
}

void tcg_gen_movcond_i64(TCGContext *tcg_ctx, TCGCond cond, TCGv_i64 ret, TCGv_i64 c1,
                         TCGv_i64 c2, TCGv_i64 v1, TCGv_i64 v2)
{
    if (cond == TCG_COND_ALWAYS) {
        tcg_gen_mov_i64(tcg_ctx, ret, v1);
    } else if (cond == TCG_COND_NEVER) {
        tcg_gen_mov_i64(tcg_ctx, ret, v2);
    } else {
#if TCG_TARGET_REG_BITS == 32
        TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_op6i_i32(tcg_ctx, INDEX_op_setcond2_i32, t0,
                         TCGV_LOW(tcg_ctx, c1), TCGV_HIGH(tcg_ctx, c1),
                         TCGV_LOW(tcg_ctx, c2), TCGV_HIGH(tcg_ctx, c2), cond);

#if TCG_TARGET_HAS_movcond_i32
            tcg_gen_movi_i32(tcg_ctx, t1, 0);
            tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, TCGV_LOW(tcg_ctx, ret), t0, t1,
                                TCGV_LOW(tcg_ctx, v1), TCGV_LOW(tcg_ctx, v2));
            tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, TCGV_HIGH(tcg_ctx, ret), t0, t1,
                                TCGV_HIGH(tcg_ctx, v1), TCGV_HIGH(tcg_ctx, v2));
#else
            tcg_gen_neg_i32(tcg_ctx, t0, t0);

            tcg_gen_and_i32(tcg_ctx, t1, TCGV_LOW(tcg_ctx, v1), t0);
            tcg_gen_andc_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, v2), t0);
            tcg_gen_or_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), t1);

            tcg_gen_and_i32(tcg_ctx, t1, TCGV_HIGH(tcg_ctx, v1), t0);
            tcg_gen_andc_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, v2), t0);
            tcg_gen_or_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_HIGH(tcg_ctx, ret), t1);
#endif
        tcg_temp_free_i32(tcg_ctx, t0);
        tcg_temp_free_i32(tcg_ctx, t1);
#elif TCG_TARGET_HAS_movcond_i64
        tcg_gen_op6i_i64(tcg_ctx, INDEX_op_movcond_i64, ret, c1, c2, v1, v2, cond);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_setcond_i64(tcg_ctx, cond, t0, c1, c2);
        tcg_gen_neg_i64(tcg_ctx, t0, t0);
        tcg_gen_and_i64(tcg_ctx, t1, v1, t0);
        tcg_gen_andc_i64(tcg_ctx, ret, v2, t0);
        tcg_gen_or_i64(tcg_ctx, ret, ret, t1);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
#endif
    }
}

void tcg_gen_add2_i64(TCGContext *tcg_ctx, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 al,
                      TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh)
{
#if TCG_TARGET_HAS_add2_i64
        tcg_gen_op6_i64(tcg_ctx, INDEX_op_add2_i64, rl, rh, al, ah, bl, bh);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_add_i64(tcg_ctx, t0, al, bl);
        tcg_gen_setcond_i64(tcg_ctx, TCG_COND_LTU, t1, t0, al);
        tcg_gen_add_i64(tcg_ctx, rh, ah, bh);
        tcg_gen_add_i64(tcg_ctx, rh, rh, t1);
        tcg_gen_mov_i64(tcg_ctx, rl, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
#endif
}

void tcg_gen_sub2_i64(TCGContext *tcg_ctx, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 al,
                      TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh)
{
#if TCG_TARGET_HAS_sub2_i64
        tcg_gen_op6_i64(tcg_ctx, INDEX_op_sub2_i64, rl, rh, al, ah, bl, bh);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_sub_i64(tcg_ctx, t0, al, bl);
        tcg_gen_setcond_i64(tcg_ctx, TCG_COND_LTU, t1, al, bl);
        tcg_gen_sub_i64(tcg_ctx, rh, ah, bh);
        tcg_gen_sub_i64(tcg_ctx, rh, rh, t1);
        tcg_gen_mov_i64(tcg_ctx, rl, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
#endif
}

void tcg_gen_mulu2_i64(TCGContext *tcg_ctx, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_mulu2_i64
        tcg_gen_op4_i64(tcg_ctx, INDEX_op_mulu2_i64, rl, rh, arg1, arg2);
#elif TCG_TARGET_HAS_muluh_i64
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_mul_i64, t, arg1, arg2);
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_muluh_i64, rh, arg1, arg2);
        tcg_gen_mov_i64(tcg_ctx, rl, t);
        tcg_temp_free_i64(tcg_ctx, t);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_mul_i64(tcg_ctx, t0, arg1, arg2);
        gen_helper_muluh_i64(tcg_ctx, rh, arg1, arg2);
        tcg_gen_mov_i64(tcg_ctx, rl, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
#endif
}

void tcg_gen_muls2_i64(TCGContext *tcg_ctx, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2)
{
#if TCG_TARGET_HAS_muls2_i64
        tcg_gen_op4_i64(tcg_ctx, INDEX_op_muls2_i64, rl, rh, arg1, arg2);
#elif TCG_TARGET_HAS_mulsh_i64
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_mul_i64, t, arg1, arg2);
        tcg_gen_op3_i64(tcg_ctx, INDEX_op_mulsh_i64, rh, arg1, arg2);
        tcg_gen_mov_i64(tcg_ctx, rl, t);
        tcg_temp_free_i64(tcg_ctx, t);
#elif TCG_TARGET_HAS_mulu2_i64 || TCG_TARGET_HAS_muluh_i64
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t3 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_mulu2_i64(tcg_ctx, t0, t1, arg1, arg2);
        /* Adjust for negative inputs.  */
        tcg_gen_sari_i64(tcg_ctx, t2, arg1, 63);
        tcg_gen_sari_i64(tcg_ctx, t3, arg2, 63);
        tcg_gen_and_i64(tcg_ctx, t2, t2, arg2);
        tcg_gen_and_i64(tcg_ctx, t3, t3, arg1);
        tcg_gen_sub_i64(tcg_ctx, rh, t1, t2);
        tcg_gen_sub_i64(tcg_ctx, rh, rh, t3);
        tcg_gen_mov_i64(tcg_ctx, rl, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
        tcg_temp_free_i64(tcg_ctx, t2);
        tcg_temp_free_i64(tcg_ctx, t3);
#else
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_mul_i64(tcg_ctx, t0, arg1, arg2);
        gen_helper_mulsh_i64(tcg_ctx, rh, arg1, arg2);
        tcg_gen_mov_i64(tcg_ctx, rl, t0);
        tcg_temp_free_i64(tcg_ctx, t0);
#endif
}

void tcg_gen_mulsu2_i64(TCGContext *tcg_ctx, TCGv_i64 rl, TCGv_i64 rh, TCGv_i64 arg1, TCGv_i64 arg2)
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_mulu2_i64(tcg_ctx, t0, t1, arg1, arg2);
    /* Adjust for negative input for the signed arg1.  */
    tcg_gen_sari_i64(tcg_ctx, t2, arg1, 63);
    tcg_gen_and_i64(tcg_ctx, t2, t2, arg2);
    tcg_gen_sub_i64(tcg_ctx, rh, t1, t2);
    tcg_gen_mov_i64(tcg_ctx, rl, t0);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
}

void tcg_gen_smin_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 a, TCGv_i64 b)
{
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LT, ret, a, b, a, b);
}

void tcg_gen_umin_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 a, TCGv_i64 b)
{
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, ret, a, b, a, b);
}

void tcg_gen_smax_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 a, TCGv_i64 b)
{
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LT, ret, a, b, b, a);
}

void tcg_gen_umax_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 a, TCGv_i64 b)
{
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, ret, a, b, b, a);
}

void tcg_gen_abs_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 a)
{
    TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_sari_i64(tcg_ctx, t, a, 63);
    tcg_gen_xor_i64(tcg_ctx, ret, a, t);
    tcg_gen_sub_i64(tcg_ctx, ret, ret, t);
    tcg_temp_free_i64(tcg_ctx, t);
}

/* Size changing operations.  */

void tcg_gen_extrl_i64_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_mov_i32(tcg_ctx, ret, TCGV_LOW(tcg_ctx, arg));
#elif TCG_TARGET_HAS_extrl_i64_i32
        tcg_gen_op2(tcg_ctx, INDEX_op_extrl_i64_i32,
                    tcgv_i32_arg(tcg_ctx, ret), tcgv_i64_arg(tcg_ctx, arg));
#else
        tcg_gen_mov_i32(tcg_ctx, ret, (TCGv_i32)arg);
#endif
}

void tcg_gen_extrh_i64_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_mov_i32(tcg_ctx, ret, TCGV_HIGH(tcg_ctx, arg));
#elif TCG_TARGET_HAS_extrh_i64_i32
        tcg_gen_op2(tcg_ctx, INDEX_op_extrh_i64_i32,
                    tcgv_i32_arg(tcg_ctx, ret), tcgv_i64_arg(tcg_ctx, arg));
#else
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_shri_i64(tcg_ctx, t, arg, 32);
        tcg_gen_mov_i32(tcg_ctx, ret, (TCGv_i32)t);
        tcg_temp_free_i64(tcg_ctx, t);
#endif
}

void tcg_gen_extu_i32_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i32 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg);
        tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), 0);
#else
        tcg_gen_op2(tcg_ctx, INDEX_op_extu_i32_i64,
                    tcgv_i64_arg(tcg_ctx, ret), tcgv_i32_arg(tcg_ctx, arg));
#endif
}

void tcg_gen_ext_i32_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i32 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, ret), arg);
        tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, ret), TCGV_LOW(tcg_ctx, ret), 31);
#else
        tcg_gen_op2(tcg_ctx, INDEX_op_ext_i32_i64,
                    tcgv_i64_arg(tcg_ctx, ret), tcgv_i32_arg(tcg_ctx, arg));
#endif
}

void tcg_gen_concat_i32_i64(TCGContext *tcg_ctx, TCGv_i64 dest, TCGv_i32 low, TCGv_i32 high)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_mov_i32(tcg_ctx, TCGV_LOW(tcg_ctx, dest), low);
        tcg_gen_mov_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, dest), high);
        return;
#else
    TCGv_i64 tmp;

    tmp = tcg_temp_new_i64(tcg_ctx);
    /* These extensions are only needed for type correctness.
       We may be able to do better given target specific information.  */
    tcg_gen_extu_i32_i64(tcg_ctx, tmp, high);
    tcg_gen_extu_i32_i64(tcg_ctx, dest, low);
    /* If deposit is available, use it.  Otherwise use the extra
       knowledge that we have of the zero-extensions above.  */
#if TCG_TARGET_HAS_deposit_i64
    if (TCG_TARGET_deposit_i64_valid(32, 32)) {
        tcg_gen_deposit_i64(tcg_ctx, dest, dest, tmp, 32, 32);
    } else {
#endif
        tcg_gen_shli_i64(tcg_ctx, tmp, tmp, 32);
        tcg_gen_or_i64(tcg_ctx, dest, dest, tmp);
#if TCG_TARGET_HAS_deposit_i64
    }
#endif
    tcg_temp_free_i64(tcg_ctx, tmp);
#endif
}

void tcg_gen_extr_i64_i32(TCGContext *tcg_ctx, TCGv_i32 lo, TCGv_i32 hi, TCGv_i64 arg)
{
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_mov_i32(tcg_ctx, lo, TCGV_LOW(tcg_ctx, arg));
        tcg_gen_mov_i32(tcg_ctx, hi, TCGV_HIGH(tcg_ctx, arg));
#else
        tcg_gen_extrl_i64_i32(tcg_ctx, lo, arg);
        tcg_gen_extrh_i64_i32(tcg_ctx, hi, arg);
#endif
}

void tcg_gen_extr32_i64(TCGContext *tcg_ctx, TCGv_i64 lo, TCGv_i64 hi, TCGv_i64 arg)
{
    tcg_gen_ext32u_i64(tcg_ctx, lo, arg);
    tcg_gen_shri_i64(tcg_ctx, hi, arg, 32);
}

/* QEMU specific operations.  */

void tcg_gen_exit_tb(TCGContext *tcg_ctx, TranslationBlock *tb, unsigned idx)
{
    uintptr_t val = (uintptr_t)tb + idx;

    if (tb == NULL) {
        tcg_debug_assert(idx == 0);
    } else if (idx <= TB_EXIT_IDXMAX) {
#ifdef CONFIG_DEBUG_TCG
        /* This is an exit following a goto_tb.  Verify that we have
           seen this numbered exit before, via tcg_gen_goto_tb.  */
        tcg_debug_assert(tcg_ctx->goto_tb_issue_mask & (1 << idx));
#endif
        /* When not chaining, exit without indicating a link.  */
        //if (qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        //    val = 0;
        //}
    } else {
        /* This is an exit via the exitreq label.  */
        tcg_debug_assert(idx == TB_EXIT_REQUESTED);
    }

    tcg_gen_op1i(tcg_ctx, INDEX_op_exit_tb, val);
}

void tcg_gen_goto_tb(TCGContext *tcg_ctx, unsigned idx)
{
    /* We only support two chained exits.  */
    tcg_debug_assert(idx <= TB_EXIT_IDXMAX);
#ifdef CONFIG_DEBUG_TCG
    /* Verify that we havn't seen this numbered exit before.  */
    tcg_debug_assert((tcg_ctx->goto_tb_issue_mask & (1 << idx)) == 0);
    tcg_ctx->goto_tb_issue_mask |= 1 << idx;
#endif
    /* When not chaining, we simply fall through to the "fallback" exit.  */

    // if (!qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN))
    tcg_gen_op1i(tcg_ctx, INDEX_op_goto_tb, idx);
}

void tcg_gen_lookup_and_goto_ptr(TCGContext *tcg_ctx)
{
#if TCG_TARGET_HAS_goto_ptr
        TCGv_ptr ptr;

        ptr = tcg_temp_new_ptr(tcg_ctx);
        gen_helper_lookup_tb_ptr(tcg_ctx, ptr, tcg_ctx->cpu_env);
        tcg_gen_op1i(tcg_ctx, INDEX_op_goto_ptr, tcgv_ptr_arg(tcg_ctx, ptr));
        tcg_temp_free_ptr(tcg_ctx, ptr);
#else
        tcg_gen_exit_tb(tcg_ctx, NULL, 0);
#endif
}

static inline MemOp tcg_canonicalize_memop(MemOp op, bool is64, bool st)
{
    /* Trigger the asserts within as early as possible.  */
    (void)get_alignment_bits(op);

    switch (op & MO_SIZE) {
    case MO_8:
        op &= ~MO_BSWAP;
        break;
    case MO_16:
        break;
    case MO_32:
        if (!is64) {
            op &= ~MO_SIGN;
        }
        break;
    case MO_64:
        if (!is64) {
            tcg_abort();
        }
        break;
    }
    if (st) {
        op &= ~MO_SIGN;
    }
    return op;
}

static void gen_ldst_i32(TCGContext *tcg_ctx, TCGOpcode opc, TCGv_i32 val, TCGv addr,
                         MemOp memop, TCGArg idx)
{
    TCGMemOpIdx oi = make_memop_idx(memop, idx);
#if TARGET_LONG_BITS == 32
    tcg_gen_op3i_i32(tcg_ctx, opc, val, addr, oi);
#else
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_op4i_i32(tcg_ctx, opc, val, TCGV_LOW(tcg_ctx, addr), TCGV_HIGH(tcg_ctx, addr), oi);
#else
        tcg_gen_op3(tcg_ctx, opc, tcgv_i32_arg(tcg_ctx, val), tcgv_i64_arg(tcg_ctx, addr), oi);
#endif
#endif
}

static void gen_ldst_i64(TCGContext *tcg_ctx, TCGOpcode opc, TCGv_i64 val, TCGv addr,
                         MemOp memop, TCGArg idx)
{
    TCGMemOpIdx oi = make_memop_idx(memop, idx);
#if TARGET_LONG_BITS == 32
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_op4i_i32(tcg_ctx, opc, TCGV_LOW(tcg_ctx, val), TCGV_HIGH(tcg_ctx, val), addr, oi);
#else
        tcg_gen_op3(tcg_ctx, opc, tcgv_i64_arg(tcg_ctx, val), tcgv_i32_arg(tcg_ctx, addr), oi);
#endif
#else
#if TCG_TARGET_REG_BITS == 32
        tcg_gen_op5i_i32(tcg_ctx, opc, TCGV_LOW(tcg_ctx, val), TCGV_HIGH(tcg_ctx, val),
                         TCGV_LOW(tcg_ctx, addr), TCGV_HIGH(tcg_ctx, addr), oi);
#else
        tcg_gen_op3i_i64(tcg_ctx, opc, val, addr, oi);
#endif
#endif
}

// Unicorn engine
// check if the last memory access was invalid
// if so, we jump to the block epilogue to quit immediately.
void check_exit_request(TCGContext *tcg_ctx)
{
    TCGv_i32 count;

    // Unicorn:
    //   For ARM IT block, we couldn't exit in the middle of the
    //   block and this is the our hack here.
    if (tcg_ctx->uc->no_exit_request) {
        return;
    }

    count = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_ld_i32(tcg_ctx, count, tcg_ctx->cpu_env,
                   offsetof(ArchCPU, neg.icount_decr.u32) -
                   offsetof(ArchCPU, env));

    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_LT, count, 0, tcg_ctx->exitreq_label);

    tcg_temp_free_i32(tcg_ctx, count);
}

static void tcg_gen_req_mo(TCGContext *tcg_ctx, TCGBar type)
{
#ifdef TCG_GUEST_DEFAULT_MO
    type &= TCG_GUEST_DEFAULT_MO;
#endif
    type &= ~TCG_TARGET_DEFAULT_MO;
    if (type) {
        tcg_gen_mb(tcg_ctx, type | TCG_BAR_SC);
    }
}

void tcg_gen_qemu_ld_i32(TCGContext *tcg_ctx, TCGv_i32 val, TCGv addr, TCGArg idx, MemOp memop)
{
    MemOp orig_memop;

    tcg_gen_req_mo(tcg_ctx, TCG_MO_LD_LD | TCG_MO_ST_LD);
    memop = tcg_canonicalize_memop(memop, 0, 0);

    orig_memop = memop;
    if (!TCG_TARGET_HAS_MEMORY_BSWAP && (memop & MO_BSWAP)) {
        memop &= ~MO_BSWAP;
        /* The bswap primitive requires zero-extended input.  */
        if ((memop & MO_SSIZE) == MO_SW) {
            memop &= ~MO_SIGN;
        }
    }

    gen_ldst_i32(tcg_ctx, INDEX_op_qemu_ld_i32, val, addr, memop, idx);

    if ((orig_memop ^ memop) & MO_BSWAP) {
        switch (orig_memop & MO_SIZE) {
        case MO_16:
            tcg_gen_bswap16_i32(tcg_ctx, val, val);
            if (orig_memop & MO_SIGN) {
                tcg_gen_ext16s_i32(tcg_ctx, val, val);
            }
            break;
        case MO_32:
            tcg_gen_bswap32_i32(tcg_ctx, val, val);
            break;
        default:
            g_assert_not_reached();
        }
    }

    check_exit_request(tcg_ctx);
}

void tcg_gen_qemu_st_i32(TCGContext *tcg_ctx, TCGv_i32 val, TCGv addr, TCGArg idx, MemOp memop)
{
    TCGv_i32 swap = NULL;

    tcg_gen_req_mo(tcg_ctx, TCG_MO_LD_ST | TCG_MO_ST_ST);
    memop = tcg_canonicalize_memop(memop, 0, 1);

#if !TCG_TARGET_HAS_MEMORY_BSWAP
    if (memop & MO_BSWAP) {
        swap = tcg_temp_new_i32(tcg_ctx);
        switch (memop & MO_SIZE) {
        case MO_16:
            tcg_gen_ext16u_i32(tcg_ctx, swap, val);
            tcg_gen_bswap16_i32(tcg_ctx, swap, swap);
            break;
        case MO_32:
            tcg_gen_bswap32_i32(tcg_ctx, swap, val);
            break;
        default:
            g_assert_not_reached();
        }
        val = swap;
        memop &= ~MO_BSWAP;
    }
#endif

    gen_ldst_i32(tcg_ctx, INDEX_op_qemu_st_i32, val, addr, memop, idx);

    if (swap) {
        tcg_temp_free_i32(tcg_ctx, swap);
    }

    check_exit_request(tcg_ctx);
}

void tcg_gen_qemu_ld_i64(TCGContext *tcg_ctx, TCGv_i64 val, TCGv addr, TCGArg idx, MemOp memop)
{
    MemOp orig_memop;

#if TCG_TARGET_REG_BITS == 32
    if ((memop & MO_SIZE) < MO_64) {
        tcg_gen_qemu_ld_i32(tcg_ctx, TCGV_LOW(tcg_ctx, val), addr, idx, memop);
        if (memop & MO_SIGN) {
            tcg_gen_sari_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, val), TCGV_LOW(tcg_ctx, val), 31);
        } else {
            tcg_gen_movi_i32(tcg_ctx, TCGV_HIGH(tcg_ctx, val), 0);
        }
        check_exit_request(tcg_ctx);
        return;
    }
#endif

    tcg_gen_req_mo(tcg_ctx, TCG_MO_LD_LD | TCG_MO_ST_LD);
    memop = tcg_canonicalize_memop(memop, 1, 0);

    orig_memop = memop;
#if !TCG_TARGET_HAS_MEMORY_BSWAP
    if (memop & MO_BSWAP) {
        memop &= ~MO_BSWAP;
        /* The bswap primitive requires zero-extended input.  */
        if ((memop & MO_SIGN) && (memop & MO_SIZE) < MO_64) {
            memop &= ~MO_SIGN;
        }
    }
#endif

    gen_ldst_i64(tcg_ctx, INDEX_op_qemu_ld_i64, val, addr, memop, idx);

    if ((orig_memop ^ memop) & MO_BSWAP) {
        switch (orig_memop & MO_SIZE) {
        case MO_16:
            tcg_gen_bswap16_i64(tcg_ctx, val, val);
            if (orig_memop & MO_SIGN) {
                tcg_gen_ext16s_i64(tcg_ctx, val, val);
            }
            break;
        case MO_32:
            tcg_gen_bswap32_i64(tcg_ctx, val, val);
            if (orig_memop & MO_SIGN) {
                tcg_gen_ext32s_i64(tcg_ctx, val, val);
            }
            break;
        case MO_64:
            tcg_gen_bswap64_i64(tcg_ctx, val, val);
            break;
        default:
            g_assert_not_reached();
        }
    }
    check_exit_request(tcg_ctx);
}

void tcg_gen_qemu_st_i64(TCGContext *tcg_ctx, TCGv_i64 val, TCGv addr, TCGArg idx, MemOp memop)
{
    TCGv_i64 swap = NULL;

#if TCG_TARGET_REG_BITS == 32
    if ((memop & MO_SIZE) < MO_64) {
        tcg_gen_qemu_st_i32(tcg_ctx, TCGV_LOW(tcg_ctx, val), addr, idx, memop);
        check_exit_request(tcg_ctx);
        return;
    }
#endif

    tcg_gen_req_mo(tcg_ctx, TCG_MO_LD_ST | TCG_MO_ST_ST);
    memop = tcg_canonicalize_memop(memop, 1, 1);

#if !TCG_TARGET_HAS_MEMORY_BSWAP
    if (memop & MO_BSWAP) {
        swap = tcg_temp_new_i64(tcg_ctx);
        switch (memop & MO_SIZE) {
        case MO_16:
            tcg_gen_ext16u_i64(tcg_ctx, swap, val);
            tcg_gen_bswap16_i64(tcg_ctx, swap, swap);
            break;
        case MO_32:
            tcg_gen_ext32u_i64(tcg_ctx, swap, val);
            tcg_gen_bswap32_i64(tcg_ctx, swap, swap);
            break;
        case MO_64:
            tcg_gen_bswap64_i64(tcg_ctx, swap, val);
            break;
        default:
            g_assert_not_reached();
        }
        val = swap;
        memop &= ~MO_BSWAP;
    }
#endif

    gen_ldst_i64(tcg_ctx, INDEX_op_qemu_st_i64, val, addr, memop, idx);

    if (swap) {
        tcg_temp_free_i64(tcg_ctx, swap);
    }
    check_exit_request(tcg_ctx);
}

static void tcg_gen_ext_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 val, MemOp opc)
{
    switch (opc & MO_SSIZE) {
    case MO_SB:
        tcg_gen_ext8s_i32(tcg_ctx, ret, val);
        break;
    case MO_UB:
        tcg_gen_ext8u_i32(tcg_ctx, ret, val);
        break;
    case MO_SW:
        tcg_gen_ext16s_i32(tcg_ctx, ret, val);
        break;
    case MO_UW:
        tcg_gen_ext16u_i32(tcg_ctx, ret, val);
        break;
    default:
        tcg_gen_mov_i32(tcg_ctx, ret, val);
        break;
    }
}

static void tcg_gen_ext_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 val, MemOp opc)
{
    switch (opc & MO_SSIZE) {
    case MO_SB:
        tcg_gen_ext8s_i64(tcg_ctx, ret, val);
        break;
    case MO_UB:
        tcg_gen_ext8u_i64(tcg_ctx, ret, val);
        break;
    case MO_SW:
        tcg_gen_ext16s_i64(tcg_ctx, ret, val);
        break;
    case MO_UW:
        tcg_gen_ext16u_i64(tcg_ctx, ret, val);
        break;
    case MO_SL:
        tcg_gen_ext32s_i64(tcg_ctx, ret, val);
        break;
    case MO_UL:
        tcg_gen_ext32u_i64(tcg_ctx, ret, val);
        break;
    default:
        tcg_gen_mov_i64(tcg_ctx, ret, val);
        break;
    }
}

typedef void (*gen_atomic_cx_i32)(TCGContext *tcg_ctx, TCGv_i32, TCGv_env, TCGv,
                                  TCGv_i32, TCGv_i32, TCGv_i32);
typedef void (*gen_atomic_cx_i64)(TCGContext *tcg_ctx, TCGv_i64, TCGv_env, TCGv,
                                  TCGv_i64, TCGv_i64, TCGv_i32);
typedef void (*gen_atomic_op_i32)(TCGContext *tcg_ctx, TCGv_i32, TCGv_env, TCGv,
                                  TCGv_i32, TCGv_i32);
typedef void (*gen_atomic_op_i64)(TCGContext *tcg_ctx, TCGv_i64, TCGv_env, TCGv,
                                  TCGv_i64, TCGv_i32);

#ifdef CONFIG_ATOMIC64
# define WITH_ATOMIC64(X) X,
#else
# define WITH_ATOMIC64(X)
#endif

static void * const table_cmpxchg[16] = {
    [MO_8] = gen_helper_atomic_cmpxchgb,
    [MO_16 | MO_LE] = gen_helper_atomic_cmpxchgw_le,
    [MO_16 | MO_BE] = gen_helper_atomic_cmpxchgw_be,
    [MO_32 | MO_LE] = gen_helper_atomic_cmpxchgl_le,
    [MO_32 | MO_BE] = gen_helper_atomic_cmpxchgl_be,
    WITH_ATOMIC64([MO_64 | MO_LE] = gen_helper_atomic_cmpxchgq_le)
    WITH_ATOMIC64([MO_64 | MO_BE] = gen_helper_atomic_cmpxchgq_be)
};

void tcg_gen_atomic_cmpxchg_i32(TCGContext *tcg_ctx, TCGv_i32 retv, TCGv addr, TCGv_i32 cmpv,
                                TCGv_i32 newv, TCGArg idx, MemOp memop)
{
    memop = tcg_canonicalize_memop(memop, 0, 0);

    if (!(tcg_ctx->tb_cflags & CF_PARALLEL)) {
        TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 t2 = tcg_temp_new_i32(tcg_ctx);

        tcg_gen_ext_i32(tcg_ctx, t2, cmpv, memop & MO_SIZE);

        tcg_gen_qemu_ld_i32(tcg_ctx, t1, addr, idx, memop & ~MO_SIGN);
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, t2, t1, t2, newv, t1);
        tcg_gen_qemu_st_i32(tcg_ctx, t2, addr, idx, memop);
        tcg_temp_free_i32(tcg_ctx, t2);

        if (memop & MO_SIGN) {
            tcg_gen_ext_i32(tcg_ctx, retv, t1, memop);
        } else {
            tcg_gen_mov_i32(tcg_ctx, retv, t1);
        }
        tcg_temp_free_i32(tcg_ctx, t1);
    } else {
        gen_atomic_cx_i32 gen;

        gen = table_cmpxchg[memop & (MO_SIZE | MO_BSWAP)];
        tcg_debug_assert(gen != NULL);

        {
            TCGv_i32 oi = tcg_const_i32(tcg_ctx, make_memop_idx(memop & ~MO_SIGN, idx));
            gen(tcg_ctx, retv, tcg_ctx->cpu_env, addr, cmpv, newv, oi);
            tcg_temp_free_i32(tcg_ctx, oi);
        }

        if (memop & MO_SIGN) {
            tcg_gen_ext_i32(tcg_ctx, retv, retv, memop);
        }
    }
}

void tcg_gen_atomic_cmpxchg_i64(TCGContext *tcg_ctx, TCGv_i64 retv, TCGv addr, TCGv_i64 cmpv,
                                TCGv_i64 newv, TCGArg idx, MemOp memop)
{
    memop = tcg_canonicalize_memop(memop, 1, 0);

    if (!(tcg_ctx->tb_cflags & CF_PARALLEL)) {
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

        tcg_gen_ext_i64(tcg_ctx, t2, cmpv, memop & MO_SIZE);

        tcg_gen_qemu_ld_i64(tcg_ctx, t1, addr, idx, memop & ~MO_SIGN);
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t2, t1, t2, newv, t1);
        tcg_gen_qemu_st_i64(tcg_ctx, t2, addr, idx, memop);
        tcg_temp_free_i64(tcg_ctx, t2);

        if (memop & MO_SIGN) {
            tcg_gen_ext_i64(tcg_ctx, retv, t1, memop);
        } else {
            tcg_gen_mov_i64(tcg_ctx, retv, t1);
        }
        tcg_temp_free_i64(tcg_ctx, t1);
    } else if ((memop & MO_SIZE) == MO_64) {
#ifdef CONFIG_ATOMIC64
        gen_atomic_cx_i64 gen;

        gen = table_cmpxchg[memop & (MO_SIZE | MO_BSWAP)];
        tcg_debug_assert(gen != NULL);

        {
            TCGv_i32 oi = tcg_const_i32(tcg_ctx, make_memop_idx(memop, idx));
            gen(tcg_ctx, retv, tcg_ctx->cpu_env, addr, cmpv, newv, oi);
            tcg_temp_free_i32(tcg_ctx, oi);
        }
#else
        gen_helper_exit_atomic(tcg_ctx, tcg_ctx->cpu_env);
        /* Produce a result, so that we have a well-formed opcode stream
           with respect to uses of the result in the (dead) code following.  */
        tcg_gen_movi_i64(tcg_ctx, retv, 0);
#endif /* CONFIG_ATOMIC64 */
    } else {
        TCGv_i32 c32 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 n32 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 r32 = tcg_temp_new_i32(tcg_ctx);

        tcg_gen_extrl_i64_i32(tcg_ctx, c32, cmpv);
        tcg_gen_extrl_i64_i32(tcg_ctx, n32, newv);
        tcg_gen_atomic_cmpxchg_i32(tcg_ctx, r32, addr, c32, n32, idx, memop & ~MO_SIGN);
        tcg_temp_free_i32(tcg_ctx, c32);
        tcg_temp_free_i32(tcg_ctx, n32);

        tcg_gen_extu_i32_i64(tcg_ctx, retv, r32);
        tcg_temp_free_i32(tcg_ctx, r32);

        if (memop & MO_SIGN) {
            tcg_gen_ext_i64(tcg_ctx, retv, retv, memop);
        }
    }
}

static void do_nonatomic_op_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv addr, TCGv_i32 val,
                                TCGArg idx, MemOp memop, bool new_val,
                                void (*gen)(TCGContext *tcg_ctx, TCGv_i32, TCGv_i32, TCGv_i32))
{
    TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 t2 = tcg_temp_new_i32(tcg_ctx);

    memop = tcg_canonicalize_memop(memop, 0, 0);

    tcg_gen_qemu_ld_i32(tcg_ctx, t1, addr, idx, memop & ~MO_SIGN);
    gen(tcg_ctx, t2, t1, val);
    tcg_gen_qemu_st_i32(tcg_ctx, t2, addr, idx, memop);

    tcg_gen_ext_i32(tcg_ctx, ret, (new_val ? t2 : t1), memop);
    tcg_temp_free_i32(tcg_ctx, t1);
    tcg_temp_free_i32(tcg_ctx, t2);
}

static void do_atomic_op_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv addr, TCGv_i32 val,
                             TCGArg idx, MemOp memop, void * const table[])
{
    gen_atomic_op_i32 gen;

    memop = tcg_canonicalize_memop(memop, 0, 0);

    gen = table[memop & (MO_SIZE | MO_BSWAP)];
    tcg_debug_assert(gen != NULL);

    {
        TCGv_i32 oi = tcg_const_i32(tcg_ctx, make_memop_idx(memop & ~MO_SIGN, idx));
        gen(tcg_ctx, ret, tcg_ctx->cpu_env, addr, val, oi);
        tcg_temp_free_i32(tcg_ctx, oi);
    }

    if (memop & MO_SIGN) {
        tcg_gen_ext_i32(tcg_ctx, ret, ret, memop);
    }
}

static void do_nonatomic_op_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv addr, TCGv_i64 val,
                                TCGArg idx, MemOp memop, bool new_val,
                                void (*gen)(TCGContext *tcg_ctx, TCGv_i64, TCGv_i64, TCGv_i64))
{
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

    memop = tcg_canonicalize_memop(memop, 1, 0);

    tcg_gen_qemu_ld_i64(tcg_ctx, t1, addr, idx, memop & ~MO_SIGN);
    gen(tcg_ctx, t2, t1, val);
    tcg_gen_qemu_st_i64(tcg_ctx, t2, addr, idx, memop);

    tcg_gen_ext_i64(tcg_ctx, ret, (new_val ? t2 : t1), memop);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
}

static void do_atomic_op_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv addr, TCGv_i64 val,
                             TCGArg idx, MemOp memop, void * const table[])
{
    memop = tcg_canonicalize_memop(memop, 1, 0);

    if ((memop & MO_SIZE) == MO_64) {
#ifdef CONFIG_ATOMIC64
        gen_atomic_op_i64 gen;

        gen = table[memop & (MO_SIZE | MO_BSWAP)];
        tcg_debug_assert(gen != NULL);

        {
            TCGv_i32 oi = tcg_const_i32(tcg_ctx, make_memop_idx(memop & ~MO_SIGN, idx));
            gen(tcg_ctx, ret, tcg_ctx->cpu_env, addr, val, oi);
            tcg_temp_free_i32(tcg_ctx, oi);
        }
#else
        gen_helper_exit_atomic(tcg_ctx, tcg_ctx->cpu_env);
        /* Produce a result, so that we have a well-formed opcode stream
           with respect to uses of the result in the (dead) code following.  */
        tcg_gen_movi_i64(tcg_ctx, ret, 0);
#endif /* CONFIG_ATOMIC64 */
    } else {
        TCGv_i32 v32 = tcg_temp_new_i32(tcg_ctx);
        TCGv_i32 r32 = tcg_temp_new_i32(tcg_ctx);

        tcg_gen_extrl_i64_i32(tcg_ctx, v32, val);
        do_atomic_op_i32(tcg_ctx, r32, addr, v32, idx, memop & ~MO_SIGN, table);
        tcg_temp_free_i32(tcg_ctx, v32);

        tcg_gen_extu_i32_i64(tcg_ctx, ret, r32);
        tcg_temp_free_i32(tcg_ctx, r32);

        if (memop & MO_SIGN) {
            tcg_gen_ext_i64(tcg_ctx, ret, ret, memop);
        }
    }
}

#define GEN_ATOMIC_HELPER(NAME, OP, NEW)                                \
static void * const table_##NAME[16] = {                                \
    [MO_8] = gen_helper_atomic_##NAME##b,                               \
    [MO_16 | MO_LE] = gen_helper_atomic_##NAME##w_le,                   \
    [MO_16 | MO_BE] = gen_helper_atomic_##NAME##w_be,                   \
    [MO_32 | MO_LE] = gen_helper_atomic_##NAME##l_le,                   \
    [MO_32 | MO_BE] = gen_helper_atomic_##NAME##l_be,                   \
    WITH_ATOMIC64([MO_64 | MO_LE] = gen_helper_atomic_##NAME##q_le)     \
    WITH_ATOMIC64([MO_64 | MO_BE] = gen_helper_atomic_##NAME##q_be)     \
};                                                                      \
void tcg_gen_atomic_##NAME##_i32                                        \
    (TCGContext *tcg_ctx, TCGv_i32 ret, TCGv addr, TCGv_i32 val, TCGArg idx, MemOp memop)    \
{                                                                       \
    if (tcg_ctx->tb_cflags & CF_PARALLEL) {                             \
        do_atomic_op_i32(tcg_ctx, ret, addr, val, idx, memop, table_##NAME);     \
    } else {                                                            \
        do_nonatomic_op_i32(tcg_ctx, ret, addr, val, idx, memop, NEW,            \
                            tcg_gen_##OP##_i32);                        \
    }                                                                   \
}                                                                       \
void tcg_gen_atomic_##NAME##_i64                                        \
    (TCGContext *tcg_ctx, TCGv_i64 ret, TCGv addr, TCGv_i64 val, TCGArg idx, MemOp memop)    \
{                                                                       \
    if (tcg_ctx->tb_cflags & CF_PARALLEL) {                             \
        do_atomic_op_i64(tcg_ctx, ret, addr, val, idx, memop, table_##NAME);     \
    } else {                                                            \
        do_nonatomic_op_i64(tcg_ctx, ret, addr, val, idx, memop, NEW,            \
                            tcg_gen_##OP##_i64);                        \
    }                                                                   \
}

GEN_ATOMIC_HELPER(fetch_add, add, 0)
GEN_ATOMIC_HELPER(fetch_and, and, 0)
GEN_ATOMIC_HELPER(fetch_or, or, 0)
GEN_ATOMIC_HELPER(fetch_xor, xor, 0)
GEN_ATOMIC_HELPER(fetch_smin, smin, 0)
GEN_ATOMIC_HELPER(fetch_umin, umin, 0)
GEN_ATOMIC_HELPER(fetch_smax, smax, 0)
GEN_ATOMIC_HELPER(fetch_umax, umax, 0)

GEN_ATOMIC_HELPER(add_fetch, add, 1)
GEN_ATOMIC_HELPER(and_fetch, and, 1)
GEN_ATOMIC_HELPER(or_fetch, or, 1)
GEN_ATOMIC_HELPER(xor_fetch, xor, 1)
GEN_ATOMIC_HELPER(smin_fetch, smin, 1)
GEN_ATOMIC_HELPER(umin_fetch, umin, 1)
GEN_ATOMIC_HELPER(smax_fetch, smax, 1)
GEN_ATOMIC_HELPER(umax_fetch, umax, 1)

static void tcg_gen_mov2_i32(TCGContext *tcg_ctx, TCGv_i32 r, TCGv_i32 a, TCGv_i32 b)
{
    tcg_gen_mov_i32(tcg_ctx, r, b);
}

static void tcg_gen_mov2_i64(TCGContext *tcg_ctx, TCGv_i64 r, TCGv_i64 a, TCGv_i64 b)
{
    tcg_gen_mov_i64(tcg_ctx, r, b);
}

GEN_ATOMIC_HELPER(xchg, mov2, 0)

#undef GEN_ATOMIC_HELPER
