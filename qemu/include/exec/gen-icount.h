#ifndef GEN_ICOUNT_H
#define GEN_ICOUNT_H 1

#include "qemu/timer.h"

/* Helpers for instruction counting code generation.  */

static inline void gen_tb_start(TCGContext *tcg_ctx)
{
    // TCGv_i32 count;
    TCGv_i32 flag;

    tcg_ctx->exitreq_label = gen_new_label(tcg_ctx);
    flag = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_ld_i32(tcg_ctx, flag, tcg_ctx->cpu_env,
                   offsetof(CPUState, tcg_exit_req) - ENV_OFFSET);
    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_NE, flag, 0, tcg_ctx->exitreq_label);
    tcg_temp_free_i32(tcg_ctx, flag);
}

static inline void gen_tb_end(TCGContext *tcg_ctx, TranslationBlock *tb, int num_insns)
{
    gen_set_label(tcg_ctx, tcg_ctx->exitreq_label);
    tcg_gen_exit_tb(tcg_ctx, (uintptr_t)tb + TB_EXIT_REQUESTED);
}

#endif
