#ifndef GEN_ICOUNT_H
#define GEN_ICOUNT_H

#include "qemu/timer.h"

/* Helpers for instruction counting code generation.  */

//static int icount_start_insn_idx
//static TCGLabel *icount_label;
//static TCGLabel *exitreq_label;

static inline void gen_tb_start(TCGContext *tcg_ctx, TranslationBlock *tb)
{
    //TCGv_i32 count, flag, imm;
    TCGv_i32 flag;

    tcg_ctx->exitreq_label = gen_new_label(tcg_ctx);
    flag = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_ld_i32(tcg_ctx, flag, tcg_ctx->cpu_env,
                   offsetof(CPUState, tcg_exit_req) - ENV_OFFSET);
    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_NE, flag, 0, tcg_ctx->exitreq_label);
    tcg_temp_free_i32(tcg_ctx, flag);

#if 0
    if (!(tb->cflags & CF_USE_ICOUNT))
        return;
    }

    icount_label = gen_new_label(tcg_ctx);
    count = tcg_temp_local_new_i32(tcg_ctx);
    tcg_gen_ld_i32(tcg_ctx, count, tcg_ctx->tcg_env,
                   -ENV_OFFSET + offsetof(CPUState, icount_decr.u32));
    imm = tcg_temp_new_i32(tcg_ctx);
    /* We emit a movi with a dummy immediate argument. Keep the insn index
     * of the movi so that we later (when we know the actual insn count)
     * can update the immediate argument with the actual insn count.  */
    icount_start_insn_idx = tcg_op_buf_count(tcg_ctx);
    tcg_gen_movi_i32(tcg_ctx, imm, 0xdeadbeef);

    tcg_gen_sub_i32(tcg_ctx, count, count, imm);
    tcg_temp_free_i32(tcg_ctx, imm);

    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_LT, count, 0, icount_label);
    tcg_gen_st16_i32(tcg_ctx, count, tcg_ctx->tcg_env,
                     -ENV_OFFSET + offsetof(CPUState, icount_decr.u16.low));
    tcg_temp_free_i32(tcg_ctx, count);
#endif
}

static inline void gen_tb_end(TCGContext *tcg_ctx, TranslationBlock *tb, int num_insns)
{
    gen_set_label(tcg_ctx, tcg_ctx->exitreq_label);
    tcg_gen_exit_tb(tcg_ctx, (uintptr_t)tb + TB_EXIT_REQUESTED);

#if 0
    if (tb->cflags & CF_USE_ICOUNT) {
        /* Update the num_insn immediate parameter now that we know
         * the actual insn count.  */
        tcg_set_insn_param(tcg_ctx, icount_start_insn_idx, 1, num_insns);
        gen_set_label(tcg_ctx, icount_label);
        tcg_gen_exit_tb(tcg_ctx, (uintptr_t)tb + TB_EXIT_ICOUNT_EXPIRED);
    }
#endif

     /* Terminate the linked list.  */
    tcg_ctx->gen_op_buf[tcg_ctx->gen_op_buf[0].prev].next = 0;

}

#if 0
static inline void gen_io_start(TCGContext *tcg_ctx)
{
    TCGv_i32 tmp = tcg_const_i32(tcg_ctx, 1);
    tcg_gen_st_i32(tcg_ctx, tmp, tcg_ctx->tcg_env, -ENV_OFFSET + offsetof(CPUState, can_do_io));
    tcg_temp_free_i32(tcg_ctx, tmp);
}

static inline void gen_io_end(TCGContext *tcg_ctx)
{
    TCGv_i32 tmp = tcg_const_i32(tcg_ctx, 0);
    tcg_gen_st_i32(tcg_ctx, tmp, tcg_ctx->tcg_env, -ENV_OFFSET + offsetof(CPUState, can_do_io));
    tcg_temp_free_i32(tcg_ctx, tmp);
}
#endif

#endif
