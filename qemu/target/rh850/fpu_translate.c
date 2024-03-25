#include "fpu_translate.h"
#include "instmap.h"

extern TCGv_i32 cpu_ZF;

/* Helpers */
void fpu_load_i64(TCGContext *tcg_ctx, TCGv_i64 dst, int reg_n);
void fpu_load_i64_2(TCGContext *tcg_ctx, TCGv_i64 dst0, TCGv_i64 dst1, int reg_n0, int reg_n1);
void fpu_store_i64(TCGContext *tcg_ctx, int reg_n, TCGv_i64 src);

/* Single-precision */
void fpu_gen_sp_ir_3(CPURH850State *env, DisasContext *ctx, int operands, int op, int rs1, int rs2, int rs3);
void fpu_gen_sp_ir_2(CPURH850State *env, DisasContext *ctx, int operands, int op, int rs2, int rs3);
void fpu_gen_cmpf_s(CPURH850State *env, DisasContext *ctx, int rs1, int rs2, int fcond, int fcbit);
void fpu_gen_cmov_s(CPURH850State *env, DisasContext *ctx, int rs1, int rs2, int rs3, int fcbit);
void fpu_gen_trfsr(CPURH850State *env, DisasContext *ctx, int fcbit);
void fpu_gen_cat1_ir(CPURH850State *env, DisasContext *ctx, int op, int frs1, int frs2, int frs3);


/* Double precision */
void fpu_gen_cmpf_d(CPURH850State *env, DisasContext *ctx, int rs1, int rs2, int fcond, int fcbit);
void fpu_gen_cmov_d(CPURH850State *env, DisasContext *ctx, int rs1, int rs2, int rs3, int fcbit);
void fpu_gen_dp_ir_3(CPURH850State *env, DisasContext *ctx, int operands, int op, int rs1, int rs2, int rs3);
void fpu_gen_dp_ir_2(CPURH850State *env, DisasContext *ctx, int operands, int op, int rs2, int rs3);


/**
 * Helpers for 64-bit register load/store
 **/

void fpu_load_i64(TCGContext *tcg_ctx, TCGv_i64 dst, int reg_n)
{
    TCGv_i32 rl = tcg_temp_local_new_i32(tcg_ctx);
    TCGv_i32 rh = tcg_temp_local_new_i32(tcg_ctx);

    /* Read float64 from (reg_n/reg_n+1). */
    gen_get_gpr(tcg_ctx, rl, reg_n);
    gen_get_gpr(tcg_ctx, rh, reg_n+1);
    tcg_gen_concat_i32_i64(tcg_ctx, dst, rl, rh);

    /* Free temporary variables. */
    tcg_temp_free_i32(tcg_ctx, rl);
    tcg_temp_free_i32(tcg_ctx, rh);
}

void fpu_store_i64(TCGContext *tcg_ctx, int reg_n, TCGv_i64 src)
{
    TCGv_i32 rl = tcg_temp_local_new_i32(tcg_ctx);
    TCGv_i32 rh = tcg_temp_local_new_i32(tcg_ctx);
    TCGv_i64 shift = tcg_temp_local_new_i64(tcg_ctx);

    tcg_gen_movi_i64(tcg_ctx, shift, 32);
    tcg_gen_extrl_i64_i32(tcg_ctx, rl, src);
    tcg_gen_shr_i64(tcg_ctx, src, src, shift);
    tcg_gen_extrl_i64_i32(tcg_ctx, rh, src);
    gen_set_gpr(tcg_ctx, reg_n, rl);
    gen_set_gpr(tcg_ctx, reg_n + 1, rh);

    /* Free temporary variables. */
    tcg_temp_free_i32(tcg_ctx, rl);
    tcg_temp_free_i32(tcg_ctx, rh);
}

void fpu_load_i64_2(TCGContext *tcg_ctx, TCGv_i64 dst0, TCGv_i64 dst1, int reg_n0, int reg_n1)
{
    TCGv_i32 rl = tcg_temp_local_new_i32(tcg_ctx);
    TCGv_i32 rh = tcg_temp_local_new_i32(tcg_ctx);

    /* Read float64 from (reg_n0/reg_n0 + 1). */
    gen_get_gpr(tcg_ctx, rl, reg_n0);
    gen_get_gpr(tcg_ctx, rh, reg_n0 + 1);
    tcg_gen_concat_i32_i64(tcg_ctx, dst0, rl, rh);

    /* Read float64 from (reg_n1/reg_n1 + 1). */
    gen_get_gpr(tcg_ctx, rl, reg_n1);
    gen_get_gpr(tcg_ctx, rh, reg_n1 + 1);
    tcg_gen_concat_i32_i64(tcg_ctx, dst1, rl, rh);

    /* Free temporary variables. */
    tcg_temp_free_i32(tcg_ctx, rl);
    tcg_temp_free_i32(tcg_ctx, rh);
}

/**
 * Floating-point simple-precision IR generators.
 **/

void fpu_gen_cat1_ir(CPURH850State *env, DisasContext *ctx, int op, int frs1, int frs2, int frs3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv r1 = tcg_temp_local_new(tcg_ctx);
    TCGv r2 = tcg_temp_local_new(tcg_ctx);
    TCGv r3 = tcg_temp_local_new(tcg_ctx);

    /* Load register content from frs1, frs2 and frs3. */
    gen_get_gpr(tcg_ctx, r1, frs1);
    gen_get_gpr(tcg_ctx, r2, frs2);
    gen_get_gpr(tcg_ctx, r3, frs3);

    switch(op)
    {
        case OPC_RH850_FPU_FMAF_S:
            gen_helper_fmaf_s(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2, r3);
            break;

        case OPC_RH850_FPU_FMSF_S:
            gen_helper_fmsf_s(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2, r3);
            break;
        
        case OPC_RH850_FPU_FNMAF_S:
            gen_helper_fnmaf_s(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2, r3);
            break;

        case OPC_RH850_FPU_FNMSF_S:
            gen_helper_fnmsf_s(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2, r3);
            break;

        default:
            /* Unknown instruction. */
            break;
    }

    /* Store r3 register into frs3. */
    gen_set_gpr(tcg_ctx, frs3, r3);

    /* Free locals. */
    tcg_temp_free(tcg_ctx, r1);
    tcg_temp_free(tcg_ctx, r2);
    tcg_temp_free(tcg_ctx, r3);
}


void fpu_gen_sp_ir_2(CPURH850State *env, DisasContext *ctx, int operands, int op, int rs2, int rs3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    /* rs1, rs2 and rs3 for TCG */
	TCGv r2 = tcg_temp_local_new_i32(tcg_ctx);
    TCGv r3 = tcg_temp_local_new_i32(tcg_ctx);
    TCGv_i64 r3_64 = tcg_temp_local_new_i64(tcg_ctx);

    /* Load contents from registers. */
    switch(operands)
    {
        case FPU_TYPE_S:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r2, rs2);
	
                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_ABS:
                        gen_helper_fabs_s(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_NEG:
                        gen_helper_fneg_s(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_SQRT:
                        gen_helper_fsqrt_s(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_RECIP:
                        gen_helper_frecip_s(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_RSQRT:
                        gen_helper_frsqrt_s(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;
                }

                /* Store result. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_SL:
            {
                /* Load simple-precision float. */
                gen_get_gpr(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_TRNC:
                        gen_helper_ftrnc_sl(tcg_ctx, r3_64, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CEIL:
                        gen_helper_fceil_sl(tcg_ctx, r3_64, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_FLOOR:
                        gen_helper_ffloor_sl(tcg_ctx, r3_64, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CVT:
                        gen_helper_fcvt_sl(tcg_ctx, r3_64, tcg_ctx->cpu_env, r2);
                        break;
                }

                /* Store result as long. */
                fpu_store_i64(tcg_ctx, rs3, r3_64);
            }
            break;

        case FPU_TYPE_SUL:
            {
                /* Load simple-precision float. */
                gen_get_gpr(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_TRNC:
                        gen_helper_ftrnc_sul(tcg_ctx, r3_64, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CEIL:
                        gen_helper_fceil_sul(tcg_ctx, r3_64, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_FLOOR:
                        gen_helper_ffloor_sul(tcg_ctx, r3_64, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CVT:
                        gen_helper_fcvt_sul(tcg_ctx, r3_64, tcg_ctx->cpu_env, r2);
                        break;
                }

                /* Store result as long. */
                fpu_store_i64(tcg_ctx, rs3, r3_64);
            }
            break;


        case FPU_TYPE_SW:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_TRNC:
                        gen_helper_ftrnc_sw(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CEIL:
                        gen_helper_fceil_sw(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_FLOOR:
                        gen_helper_ffloor_sw(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CVT:
                        gen_helper_fcvt_sw(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;
                }

                /* Store result. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_SUW:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_TRNC:
                        gen_helper_ftrnc_suw(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CEIL:
                        gen_helper_fceil_suw(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_FLOOR:
                        gen_helper_ffloor_suw(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CVT:
                        gen_helper_fcvt_suw(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;
                }

                /* Store result. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_LS:
            {
                /* Load content from register. */
                fpu_load_i64(tcg_ctx, r3_64, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_ls(tcg_ctx, r3, tcg_ctx->cpu_env, r3_64);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result into rs3. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_HS:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r2, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_hs(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result into rs3. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_WS:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r2, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_ws(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result into rs3. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;


        case FPU_TYPE_SH:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r2, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_sh(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result into rs3. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_ULS:
            {
                /* Load content from register. */
                fpu_load_i64(tcg_ctx, r3_64, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_uls(tcg_ctx, r3, tcg_ctx->cpu_env, r3_64);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result into rs3. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_UWS:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r2, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_uws(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result into rs3. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;
        
    }

    /* Mov softfloat flags into our register. */
    gen_helper_f_sync_fflags(tcg_ctx, tcg_ctx->cpu_env);

    /* Free temp. */
    tcg_temp_free(tcg_ctx, r2);
    tcg_temp_free(tcg_ctx, r3);
    tcg_temp_free_i64(tcg_ctx, r3_64);
}

/**
 * refactored
 **/

void fpu_gen_sp_ir_3(CPURH850State *env, DisasContext *ctx, int operands, int op, int rs1, int rs2, int rs3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    /* rs1, rs2 and rs3 for TCG */
    TCGv r1 = tcg_temp_local_new_i32(tcg_ctx);
	TCGv r2 = tcg_temp_local_new_i32(tcg_ctx);
    TCGv r3 = tcg_temp_local_new_i32(tcg_ctx);

    /* Load contents from registers. */
    switch(operands)
    {
        case FPU_TYPE_S:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r1, rs1);
                gen_get_gpr(tcg_ctx, r2, rs2);
            }
            break;
    }

    /* Apply operation. */
    switch(op)
    {
        case FPU_OP_ADD:
            gen_helper_fadd_s(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2);
            break;

        case FPU_OP_DIV:
            gen_helper_fdiv_s(tcg_ctx, r3, tcg_ctx->cpu_env, r2, r1);
            break;

        case FPU_OP_SUB:
            gen_helper_fsub_s(tcg_ctx, r3, tcg_ctx->cpu_env, r2, r1);
            break;

        case FPU_OP_MAX:
            gen_helper_fmax_s(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2);
            break;

        case FPU_OP_MIN:
            gen_helper_fmin_s(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2);
            break;

        case FPU_OP_MUL:
            gen_helper_fmul_s(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2);
            break;
    }

    /* Store result. */
    switch(operands)
    {
        case FPU_TYPE_S:
            {
                /* Set reg3. */
                gen_set_gpr(tcg_ctx, rs3, r3);
            }
            break;
    }

    /* Mov softfloat flags into our register. */
    gen_helper_f_sync_fflags(tcg_ctx, tcg_ctx->cpu_env);

    /* Free temp. */
    tcg_temp_free(tcg_ctx, r1);
    tcg_temp_free(tcg_ctx, r2);
    tcg_temp_free(tcg_ctx, r3);
}


void fpu_gen_trfsr(CPURH850State *env, DisasContext *ctx, int fcbit)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv fpsr = tcg_temp_local_new(tcg_ctx);
    TCGv mask = tcg_temp_local_new(tcg_ctx);
    TCGv shift = tcg_temp_local_new(tcg_ctx);
    TCGv one = tcg_const_i32(tcg_ctx, 1);
    TCGv value = tcg_temp_local_new(tcg_ctx);

    /* Load fpsr and compute mask. */
    gen_get_spr(tcg_ctx, BANK_ID_BASIC_0, FPSR_IDX, fpsr);
    tcg_gen_movi_i32(tcg_ctx, shift, 24 + fcbit);
    tcg_gen_shl_i32(tcg_ctx, mask, one, shift);
    
    /* Extract CCn bit. */
    tcg_gen_and_i32(tcg_ctx, value, fpsr, mask);
    tcg_gen_shr_i32(tcg_ctx, value, value, shift);

    /* Set Z flag. */
    tcg_gen_mov_i32(tcg_ctx, cpu_ZF, value);
    gen_set_gpr(tcg_ctx, 1, value);

    /* Free locals. */
    tcg_temp_free(tcg_ctx, fpsr);
    tcg_temp_free(tcg_ctx, mask);
    tcg_temp_free(tcg_ctx, shift);
    tcg_temp_free(tcg_ctx, one);
    tcg_temp_free(tcg_ctx, value);
}

void fpu_gen_cmov_s(CPURH850State *env, DisasContext *ctx, int rs1, int rs2, int rs3, int fcbit)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *end, *otherwise;
    TCGv r1 = tcg_temp_local_new(tcg_ctx);
	TCGv r2 = tcg_temp_local_new(tcg_ctx);
    TCGv final_shift = tcg_temp_local_new(tcg_ctx);
    TCGv res = tcg_temp_local_new(tcg_ctx);
    TCGv fpsr = tcg_temp_local_new(tcg_ctx);

    end = gen_new_label(tcg_ctx);
    otherwise = gen_new_label(tcg_ctx);
    

    /* Load register contents. */
    gen_get_gpr(tcg_ctx, r1, rs1);
    gen_get_gpr(tcg_ctx, r2, rs2);

    /* Check if FPSR.CCn is set (with n=fcbit). */
    gen_get_spr(tcg_ctx, BANK_ID_BASIC_0, FPSR_IDX, fpsr);
    tcg_gen_movi_i32(tcg_ctx, res, 1);
    tcg_gen_movi_i32(tcg_ctx, final_shift, 24 + fcbit);
    tcg_gen_shl_i32(tcg_ctx, res, res, final_shift);
    tcg_gen_and_i32(tcg_ctx, res, fpsr, res);

    /* If not set, r2 -> r3. */
    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_EQ, res, 0, otherwise);

    /* If set, do the move ! */
    gen_set_gpr(tcg_ctx, rs3, r1);

    tcg_gen_br(tcg_ctx, end);

    gen_set_label(tcg_ctx, otherwise);

    gen_set_gpr(tcg_ctx, rs3, r2);

    /* End. */
    gen_set_label(tcg_ctx, end);

    /* Free variables. */
    tcg_temp_free(tcg_ctx, r1);
    tcg_temp_free(tcg_ctx, r2);
    tcg_temp_free(tcg_ctx, final_shift);
    tcg_temp_free(tcg_ctx, res);
    tcg_temp_free(tcg_ctx, fpsr);
}

void fpu_gen_cmpf_s(CPURH850State *env, DisasContext *ctx, int rs1, int rs2, int fcond, int fcbit)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *handle_nan;
    TCGLabel *end;

    end = gen_new_label(tcg_ctx);
    handle_nan = gen_new_label(tcg_ctx);

    TCGv r1 = tcg_temp_local_new(tcg_ctx);
	TCGv r2 = tcg_temp_local_new(tcg_ctx);
    TCGv nan1 = tcg_temp_local_new(tcg_ctx);
    TCGv nan2 = tcg_temp_local_new(tcg_ctx);
    TCGv less = tcg_temp_local_new(tcg_ctx);
    TCGv equal = tcg_temp_local_new(tcg_ctx);
    TCGv unordered = tcg_temp_local_new(tcg_ctx);
    TCGv res = tcg_temp_local_new(tcg_ctx);
    TCGv final_shift = tcg_temp_local_new(tcg_ctx);
    TCGv one = tcg_temp_local_new(tcg_ctx);
    TCGv mask = tcg_temp_local_new(tcg_ctx);

    tcg_gen_movi_i32(tcg_ctx, one, 1);

    /* Load rs1 and rs2 registers. */
    gen_get_gpr(tcg_ctx, r1, rs1);
    gen_get_gpr(tcg_ctx, r2, rs2);

    /* If r1 or r2 is a Nan, then error. */
    gen_helper_f_is_nan_s(tcg_ctx, nan1, tcg_ctx->cpu_env, r1);
    gen_helper_f_is_nan_s(tcg_ctx, nan2, tcg_ctx->cpu_env, r2);
    tcg_gen_brcond_i32(tcg_ctx, TCG_COND_EQ, nan1, one, handle_nan);
    tcg_gen_brcond_i32(tcg_ctx, TCG_COND_EQ, nan2, one, handle_nan);

    gen_helper_flt_s(tcg_ctx, less, tcg_ctx->cpu_env, r2, r1);
    gen_helper_feq_s(tcg_ctx, equal, tcg_ctx->cpu_env, r2, r1);
    tcg_gen_movi_i32(tcg_ctx, unordered, 0);
    tcg_gen_br(tcg_ctx, end);

    gen_set_label(tcg_ctx, handle_nan);

    tcg_gen_movi_i32(tcg_ctx, less, 0);
    tcg_gen_movi_i32(tcg_ctx, equal, 0);
    tcg_gen_movi_i32(tcg_ctx, unordered, 1);
    if (fcond & 0x8)
    {
        /* Invalid operation detected. */
        /* TODO: raise exception ? */
    }

    /* This is the end =) */
    gen_set_label(tcg_ctx, end);

    /* Compute logical result. */
    tcg_gen_movi_i32(tcg_ctx, res, 0);
    if (fcond & 1)
        tcg_gen_or_i32(tcg_ctx, res, res, unordered);
    if (fcond & 2)
        tcg_gen_or_i32(tcg_ctx, res, res, equal);
    if (fcond & 4)
        tcg_gen_or_i32(tcg_ctx, res, res, less);
    
    /**
     * Set CCn bit into FPSR (with n=fcbit).
     *  1. Load FPSR into r1
     *  2. AND r1 with NOT bitmask for CCn
     *  3. OR bitmask if res == 1
     *  4. Store r1 into FPSR
     **/
    gen_get_spr(tcg_ctx, BANK_ID_BASIC_0, FPSR_IDX, r1);
    tcg_gen_movi_i32(tcg_ctx, final_shift, 24 + fcbit);
    tcg_gen_shl_i32(tcg_ctx, mask, one, final_shift);
    tcg_gen_andc_tl(tcg_ctx, r1, r1, mask);
    tcg_gen_shl_i32(tcg_ctx, res, res, final_shift);
    tcg_gen_or_i32(tcg_ctx, r1, r1, res);
    gen_set_spr(tcg_ctx, BANK_ID_BASIC_0, FPSR_IDX, r1);

    /* Free variables. */
    tcg_temp_free(tcg_ctx, r1);
    tcg_temp_free(tcg_ctx, r2);
    tcg_temp_free(tcg_ctx, nan1);
    tcg_temp_free(tcg_ctx, nan2);
    tcg_temp_free(tcg_ctx, less);
    tcg_temp_free(tcg_ctx, equal);
    tcg_temp_free(tcg_ctx, unordered);
    tcg_temp_free(tcg_ctx, final_shift);
    tcg_temp_free(tcg_ctx, one);
    tcg_temp_free(tcg_ctx, res);
}


/**
 * Floating-point double-precision IR generators.
 **/

void fpu_gen_dp_ir_2(CPURH850State *env, DisasContext *ctx, int operands, int op, int rs2, int rs3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    /* rs1, rs2 and rs3 for TCG */
	TCGv_i64 r2 = tcg_temp_local_new_i64(tcg_ctx);
    TCGv_i64 r3 = tcg_temp_local_new_i64(tcg_ctx);
    TCGv r3_32 = tcg_temp_local_new_i32(tcg_ctx);

    /* Load contents from registers. */
    switch(operands)
    {
        case FPU_TYPE_D:
            {
                /* Extract value from register rs2. */
                fpu_load_i64(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_ABS:
                        gen_helper_fabs_d(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_NEG:
                        gen_helper_fneg_d(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_SQRT:
                        gen_helper_fsqrt_d(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_RECIP:
                        gen_helper_frecip_d(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_RSQRT:
                        gen_helper_frsqrt_d(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;
                }
                
                /* Store result. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_DL:
            {
                /* Extract value from register rs2. */
                fpu_load_i64(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_TRNC:
                        gen_helper_ftrnc_dl(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CEIL:
                        gen_helper_fceil_dl(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_FLOOR:
                        gen_helper_ffloor_dl(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CVT:
                        gen_helper_fcvt_dl(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                }
                
                /* Store result. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_DUL:
            {
                /* Extract value from register rs2. */
                fpu_load_i64(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_TRNC:
                        gen_helper_ftrnc_dul(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CEIL:
                        gen_helper_fceil_dul(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_FLOOR:
                        gen_helper_ffloor_dul(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CVT:
                        gen_helper_fcvt_dul(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                        break;

                }
                
                /* Store result. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;


        case FPU_TYPE_DW:
            {
                /* Extract value from register rs2. */
                fpu_load_i64(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_TRNC:
                        gen_helper_ftrnc_dw(tcg_ctx, r3_32, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CEIL:
                        gen_helper_fceil_dw(tcg_ctx, r3_32, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_FLOOR:
                        gen_helper_ffloor_dw(tcg_ctx, r3_32, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CVT:
                        gen_helper_fcvt_dw(tcg_ctx, r3_32, tcg_ctx->cpu_env, r2);
                        break;

                }
                
                /* Store result. */
                gen_set_gpr(tcg_ctx, rs3, r3_32);
            }
            break;

        case FPU_TYPE_DUW:
            {
                /* Extract value from register rs2. */
                fpu_load_i64(tcg_ctx, r2, rs2);

                /* Apply operation. */
                switch(op)
                {
                    case FPU_OP_TRNC:
                        gen_helper_ftrnc_duw(tcg_ctx, r3_32, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CEIL:
                        gen_helper_fceil_duw(tcg_ctx, r3_32, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_FLOOR:
                        gen_helper_ffloor_duw(tcg_ctx, r3_32, tcg_ctx->cpu_env, r2);
                        break;

                    case FPU_OP_CVT:
                        gen_helper_fcvt_duw(tcg_ctx, r3_32, tcg_ctx->cpu_env, r2);
                        break;

                }
                
                /* Store result. */
                gen_set_gpr(tcg_ctx, rs3, r3_32);
            }
            break;


        case FPU_TYPE_LD:
            {
                /* Load content from register. */
                fpu_load_i64(tcg_ctx, r2, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_ld(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;


        case FPU_TYPE_WD:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r3_32, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_wd(tcg_ctx, r3, tcg_ctx->cpu_env, r3_32);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;


        case FPU_TYPE_SD:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r3_32, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_sd(tcg_ctx, r3, tcg_ctx->cpu_env, r3_32);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_UWD:
            {
                /* Extract value of reg1 and reg2. */
                gen_get_gpr(tcg_ctx, r3_32, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_uwd(tcg_ctx, r3, tcg_ctx->cpu_env, r3_32);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;

        case FPU_TYPE_ULD:
            {
                /* Load content from register. */
                fpu_load_i64(tcg_ctx, r2, rs2);

                /* Apply operation. */
                if (op == FPU_OP_CVT)
                {
                    gen_helper_fcvt_uld(tcg_ctx, r3, tcg_ctx->cpu_env, r2);
                }
                else
                {
                    /* Unsupported operation. */
                }

                /* Store result. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;

    }

    /* Mov softfloat flags into our register. */
    gen_helper_f_sync_fflags(tcg_ctx, tcg_ctx->cpu_env);

    /* Free temp. */
    tcg_temp_free_i64(tcg_ctx, r2);
    tcg_temp_free_i64(tcg_ctx, r3);
    tcg_temp_free_i32(tcg_ctx, r3_32);
}


void fpu_gen_dp_ir_3(CPURH850State *env, DisasContext *ctx, int operands, int op, int rs1, int rs2, int rs3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    /* rs1, rs2 and rs3 for TCG */
    TCGv_i64 r1 = tcg_temp_local_new_i64(tcg_ctx);
	TCGv_i64 r2 = tcg_temp_local_new_i64(tcg_ctx);
    TCGv_i64 r3 = tcg_temp_local_new_i64(tcg_ctx);

    /* Load contents from registers. */
    switch(operands)
    {
        case FPU_TYPE_D:
            {
                /* Load float64 values from regpairs designed by rs1 and rs2. */
                fpu_load_i64_2(tcg_ctx, r1, r2, rs1, rs2);
            }
            break;
    }

    switch(op)
    {
        case FPU_OP_ADD:
            gen_helper_fadd_d(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2);
            break;

        case FPU_OP_DIV:
            gen_helper_fdiv_d(tcg_ctx, r3, tcg_ctx->cpu_env, r2, r1);
            break;

        case FPU_OP_SUB:
            gen_helper_fsub_d(tcg_ctx, r3, tcg_ctx->cpu_env, r2, r1);
            break;

        case FPU_OP_MAX:
            gen_helper_fmax_d(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2);
            break;

        case FPU_OP_MIN:
            gen_helper_fmin_d(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2);
            break;

        case FPU_OP_MUL:
            gen_helper_fmul_d(tcg_ctx, r3, tcg_ctx->cpu_env, r1, r2);
            break;
    }

    switch(operands)
    {
        case FPU_TYPE_D:
            {
                /* Store result as float64 in regpair designed by rs3. */
                fpu_store_i64(tcg_ctx, rs3, r3);
            }
            break;
    }

    /* Mov softfloat flags into our register. */
    gen_helper_f_sync_fflags(tcg_ctx, tcg_ctx->cpu_env);

    /* Free temp. */
    tcg_temp_free_i64(tcg_ctx, r1);
    tcg_temp_free_i64(tcg_ctx, r2);
    tcg_temp_free_i64(tcg_ctx, r3);
}


void fpu_gen_cmpf_d(CPURH850State *env, DisasContext *ctx, int rs1, int rs2, int fcond, int fcbit)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *handle_nan;
    TCGLabel *end;

    end = gen_new_label(tcg_ctx);
    handle_nan = gen_new_label(tcg_ctx);

    TCGv_i64 r1 = tcg_temp_local_new_i64(tcg_ctx);
	TCGv_i64 r2 = tcg_temp_local_new_i64(tcg_ctx);
    TCGv nan1 = tcg_temp_local_new(tcg_ctx);
    TCGv nan2 = tcg_temp_local_new(tcg_ctx);
    TCGv less = tcg_temp_local_new(tcg_ctx);
    TCGv equal = tcg_temp_local_new(tcg_ctx);
    TCGv unordered = tcg_temp_local_new(tcg_ctx);
    TCGv res = tcg_temp_local_new(tcg_ctx);
    TCGv final_shift = tcg_temp_local_new(tcg_ctx);
    TCGv one = tcg_temp_local_new(tcg_ctx);
    TCGv mask = tcg_temp_local_new(tcg_ctx);

    tcg_gen_movi_i32(tcg_ctx, one, 1);

    /* Load rs1 and rs2 registers. */
    fpu_load_i64(tcg_ctx, r1, rs1);
    fpu_load_i64(tcg_ctx, r2, rs2);

    /* If r1 or r2 is a Nan, then error. */
    gen_helper_f_is_nan_d(tcg_ctx, nan1, tcg_ctx->cpu_env, r1);
    gen_helper_f_is_nan_d(tcg_ctx, nan2, tcg_ctx->cpu_env, r2);
    tcg_gen_or_i32(tcg_ctx, nan1, nan1, nan2);
    tcg_gen_brcond_i32(tcg_ctx, TCG_COND_EQ, nan1, one, handle_nan);
    tcg_gen_brcond_i32(tcg_ctx, TCG_COND_EQ, nan2, one, handle_nan);

    gen_helper_flt_d(tcg_ctx, less, tcg_ctx->cpu_env, r2, r1);
    gen_helper_feq_d(tcg_ctx, equal, tcg_ctx->cpu_env, r2, r1);
    tcg_gen_movi_i32(tcg_ctx, unordered, 0);
    tcg_gen_br(tcg_ctx, end);

    gen_set_label(tcg_ctx, handle_nan);

    tcg_gen_movi_i32(tcg_ctx, less, 0);
    tcg_gen_movi_i32(tcg_ctx, equal, 0);
    tcg_gen_movi_i32(tcg_ctx, unordered, 1);
    if (fcond & 0x8)
    {
        /* Invalid operation detected. */
        /* TODO: raise exception ? */
    }

    /* This is the end =) */
    gen_set_label(tcg_ctx, end);

    /* Set FPSR.CCn */
    tcg_gen_movi_i32(tcg_ctx, res, 0);
    if (fcond & 1)
        tcg_gen_or_i32(tcg_ctx, res, res, unordered);
    if (fcond & 2)
        tcg_gen_or_i32(tcg_ctx, res, res, equal);
    if (fcond & 4)
        tcg_gen_or_i32(tcg_ctx, res, res, less);
    
    /**
     * Set CCn bit into FPSR (with n=fcbit).
     *  1. Load FPSR into r1
     *  2. AND r1 with NOT bitmask for CCn
     *  3. OR bitmask if res == 1
     *  4. Store r1 into FPSR
     **/
    gen_get_spr(tcg_ctx, BANK_ID_BASIC_0, FPSR_IDX, nan1);
    tcg_gen_movi_i32(tcg_ctx, final_shift, 24 + fcbit);
    tcg_gen_shl_i32(tcg_ctx, mask, one, final_shift);
    tcg_gen_andc_tl(tcg_ctx, nan1, nan1, mask);
    tcg_gen_shl_i32(tcg_ctx, res, res, final_shift);
    tcg_gen_or_i32(tcg_ctx, nan1, nan1, res);
    gen_set_spr(tcg_ctx, BANK_ID_BASIC_0, FPSR_IDX, nan1);

    /* Free variables. */
    tcg_temp_free_i64(tcg_ctx, r1);
    tcg_temp_free_i64(tcg_ctx, r2);
    tcg_temp_free(tcg_ctx, nan1);
    tcg_temp_free(tcg_ctx, nan2);
    tcg_temp_free(tcg_ctx, less);
    tcg_temp_free(tcg_ctx, equal);
    tcg_temp_free(tcg_ctx, unordered);
    tcg_temp_free(tcg_ctx, final_shift);
    tcg_temp_free(tcg_ctx, one);
    tcg_temp_free(tcg_ctx, mask);
}

void fpu_gen_cmov_d(CPURH850State *env, DisasContext *ctx, int rs1, int rs2, int rs3, int fcbit)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *end, *otherwise;
    TCGv_i64 r1 = tcg_temp_local_new_i64(tcg_ctx);
	TCGv_i64 r2 = tcg_temp_local_new_i64(tcg_ctx);
    TCGv final_shift = tcg_temp_local_new(tcg_ctx);
    TCGv res = tcg_temp_local_new(tcg_ctx);
    TCGv fpsr = tcg_temp_local_new(tcg_ctx);

    end = gen_new_label(tcg_ctx);
    otherwise = gen_new_label(tcg_ctx);
    

    /* Load register contents. */
    fpu_load_i64(tcg_ctx, r1, rs1);
    fpu_load_i64(tcg_ctx, r2, rs2);

    /* Check if FPSR.CCn is set (with n=fcbit). */
    gen_get_spr(tcg_ctx, BANK_ID_BASIC_0, FPSR_IDX, fpsr);
    tcg_gen_movi_i32(tcg_ctx, res, 1);
    tcg_gen_movi_i32(tcg_ctx, final_shift, 24 + fcbit);
    tcg_gen_shl_i32(tcg_ctx, res, res, final_shift);
    tcg_gen_and_i32(tcg_ctx, res, fpsr, res);

    /* If not set, r2 -> r3. */
    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_EQ, res, 0, otherwise);

    /* If set, do the move ! */
    fpu_store_i64(tcg_ctx, rs3, r1);

    tcg_gen_br(tcg_ctx, end);

    gen_set_label(tcg_ctx, otherwise);

    fpu_store_i64(tcg_ctx, rs3, r2);

    /* End. */
    gen_set_label(tcg_ctx, end);

    /* Free variables. */
    tcg_temp_free_i64(tcg_ctx, r1);
    tcg_temp_free_i64(tcg_ctx, r2);
    tcg_temp_free(tcg_ctx, final_shift);
    tcg_temp_free(tcg_ctx, res);
    tcg_temp_free(tcg_ctx, fpsr);
}


/**
 * Instruction decoding and IR generation.
 **/

void fpu_decode_cat0_instn(CPURH850State *env, DisasContext *ctx)
{
    int rs1 = GET_RS1(ctx->opcode);
    int rs2 = GET_RS2(ctx->opcode);
    int rs3 = GET_RS3(ctx->opcode);
    
    switch(MASK_OP_FORMAT_FI(ctx->opcode))
    {
        case OPC_RH850_FPU_GROUP_SW:
            switch(rs1)
            {
                case OPC_RH850_FPU_TRNCF_SW:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SW, FPU_OP_TRNC, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CEILF_SW:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SW, FPU_OP_CEIL, rs2, rs3);
                    break;

                case OPC_RH850_FPU_FLOORF_SW:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SW, FPU_OP_FLOOR, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_SW:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SW, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_TRNCF_SUW:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SUW, FPU_OP_TRNC, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CEILF_SUW:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SUW, FPU_OP_CEIL, rs2, rs3);
                    break;

                case OPC_RH850_FPU_FLOORF_SUW:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SW, FPU_OP_FLOOR, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_SUW:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SUW, FPU_OP_CVT, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_DS:
            switch(rs1)
            {
                case OPC_RH850_FPU_CVTF_WS:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_WS, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_LS:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_LS, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_HS:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_HS, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_SH:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SH, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_UWS:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_UWS, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_ULS:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_ULS, FPU_OP_CVT, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_SL:
            switch(rs1)
            {
                case OPC_RH850_FPU_TRNCF_SL:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SL, FPU_OP_TRNC, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CEILF_SL:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SL, FPU_OP_CEIL, rs2, rs3);
                    break;

                case OPC_RH850_FPU_FLOORF_SL:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SL, FPU_OP_FLOOR, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_SL:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SL, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_TRNCF_SUL:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SUL, FPU_OP_TRNC, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CEILF_SUL:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SUL, FPU_OP_CEIL, rs2, rs3);
                    break;

                case OPC_RH850_FPU_FLOORF_SUL:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SUL, FPU_OP_FLOOR, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_SUL:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_SUL, FPU_OP_CVT, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_ABSS:
            switch(rs1)
            {
                case OPC_RH850_FPU_ABSF_S:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_S, FPU_OP_ABS, rs2, rs3);
                    break;

                case OPC_RH850_FPU_NEGF_S:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_S, FPU_OP_NEG, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_S:
            switch(rs1)
            {
                case OPC_RH850_FPU_SQRTF_S:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_S, FPU_OP_SQRT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_RECIPF_S:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_S, FPU_OP_RECIP, rs2, rs3);
                    break;

                case OPC_RH850_FPU_RSQRTF_S:
                    fpu_gen_sp_ir_2(env, ctx, FPU_TYPE_S, FPU_OP_RSQRT, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_DW:
            switch(rs1)
            {
                case OPC_RH850_FPU_TRNCF_DW:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DW, FPU_OP_TRNC, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CEILF_DW:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DW, FPU_OP_CEIL, rs2, rs3);
                    break;

                case OPC_RH850_FPU_FLOORF_DW:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DW, FPU_OP_FLOOR, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_DW:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DW, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_TRNCF_DUW:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DUW, FPU_OP_TRNC, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CEILF_DUW:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DUW, FPU_OP_CEIL, rs2, rs3);
                    break;

                case OPC_RH850_FPU_FLOORF_DUW:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DUW, FPU_OP_FLOOR, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_DUW:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DUW, FPU_OP_CVT, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_DD:
            switch(rs1)
            {
                case OPC_RH850_FPU_CVTF_WD:
                    //fpu_gen_cvtf_wd(env, ctx, rs2, rs3);
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_WD, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_LD:
                    //fpu_gen_cvtf_ld(env, ctx, rs2, rs3);
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_LD, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_SD:
                    //fpu_gen_cvtf_sd(env, ctx, rs2, rs3);
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_SD, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_UWD:
                    //fpu_gen_cvtf_uwd(env, ctx, rs2, rs3);
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_UWD, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_ULD:
                    //fpu_gen_cvtf_uld(env, ctx, rs2, rs3);
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_ULD, FPU_OP_CVT, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_DL:
            switch(rs1)
            {
                case OPC_RH850_FPU_TRNCF_DL:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DL, FPU_OP_TRNC, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CEILF_DL:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DL, FPU_OP_CEIL, rs2, rs3);
                    break;

                case OPC_RH850_FPU_FLOORF_DL:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DL, FPU_OP_FLOOR, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_DL:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DL, FPU_OP_CVT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_TRNCF_DUL:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DUL, FPU_OP_TRNC, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CEILF_DUL:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DUL, FPU_OP_CEIL, rs2, rs3);
                    break;

                case OPC_RH850_FPU_FLOORF_DUL:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DUL, FPU_OP_FLOOR, rs2, rs3);
                    break;

                case OPC_RH850_FPU_CVTF_DUL:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_DUL, FPU_OP_CVT, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_ABSD:
            switch(rs1)
            {
                case OPC_RH850_FPU_ABSF_D:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_D, FPU_OP_ABS, rs2, rs3);
                    break;

                case OPC_RH850_FPU_NEGF_D:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_D, FPU_OP_NEG, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_GROUP_D:
            switch(rs1)
            {
                case OPC_RH850_FPU_SQRTF_D:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_D, FPU_OP_SQRT, rs2, rs3);
                    break;

                case OPC_RH850_FPU_RECIPF_D:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_D, FPU_OP_RECIP, rs2, rs3);
                    break;

                case OPC_RH850_FPU_RSQRTF_D:
                    fpu_gen_dp_ir_2(env, ctx, FPU_TYPE_D, FPU_OP_RSQRT, rs2, rs3);
                    break;
            }
            break;

        case OPC_RH850_FPU_ADDF_S:
            fpu_gen_sp_ir_3(env, ctx, FPU_TYPE_S, FPU_OP_ADD, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_ADDF_D:
            /* rs1, rs2 and rs3 must have bit 0 set to 0. */
            if ((rs1 & 1) || (rs2 & 1) || (rs3 & 1))
            {
                /* TODO: Invalid instruction, must trigger exception.  */
            }
            else
                fpu_gen_dp_ir_3(env, ctx, FPU_TYPE_D, FPU_OP_ADD, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_SUBF_S:
            fpu_gen_sp_ir_3(env, ctx, FPU_TYPE_S, FPU_OP_SUB, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_SUBF_D:
            fpu_gen_dp_ir_3(env, ctx, FPU_TYPE_D, FPU_OP_SUB, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_MULF_S:
            fpu_gen_sp_ir_3(env, ctx, FPU_TYPE_S, FPU_OP_MUL, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_MULF_D:
            fpu_gen_dp_ir_3(env, ctx, FPU_TYPE_D, FPU_OP_MUL, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_MAXF_S:
            fpu_gen_sp_ir_3(env, ctx, FPU_TYPE_S, FPU_OP_MAX, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_MAXF_D:
            fpu_gen_dp_ir_3(env, ctx, FPU_TYPE_D, FPU_OP_MAX, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_MINF_S:
            fpu_gen_sp_ir_3(env, ctx, FPU_TYPE_S, FPU_OP_MIN, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_MINF_D:
            fpu_gen_dp_ir_3(env, ctx, FPU_TYPE_D, FPU_OP_MIN, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_DIVF_S:
            fpu_gen_sp_ir_3(env, ctx, FPU_TYPE_S, FPU_OP_DIV, rs1, rs2, rs3);
            break;

        case OPC_RH850_FPU_DIVF_D:
            fpu_gen_dp_ir_3(env, ctx, FPU_TYPE_D, FPU_OP_DIV, rs1, rs2, rs3);
            break;


        default:
            switch(ctx->opcode & (0x70 << 16))
            {
                case OPC_RH850_FPU_CMOV_S_OR_TRFSR:

                    /* If reg1==reg2==reg3==0, then it is a TRSFR instruction. */
                    if ((rs1 == 0) && (rs2 == 0) && (rs3 == 0))
                    {
                        fpu_gen_trfsr(env, ctx, (ctx->opcode & (0xe << 16))>>17 );
                    }
                    else
                    {
                        /* Call generator with fcbit. */
                        fpu_gen_cmov_s(env, ctx, rs1, rs2, rs3, (ctx->opcode & (0xe << 16))>>17 );
                    }
                    break;

                case OPC_RH850_FPU_CMOV_D:
                    /* Call generator with fcbit. */
                    fpu_gen_cmov_d(env, ctx, rs1, rs2, rs3, (ctx->opcode & (0xe << 16))>>17 );
                    break;

                case OPC_RH850_FPU_CMP_S:
                    /* Call generator with fcond (rs3) and fcbit. */
                    fpu_gen_cmpf_s(env, ctx, rs1, rs2, rs3, (ctx->opcode & (0xe << 16))>>17 );
                    break;

                case OPC_RH850_FPU_CMP_D:
                    /* Call generator with fcond (rs3) and fcbit. */
                    fpu_gen_cmpf_d(env, ctx, rs1, rs2, rs3, (ctx->opcode & (0xe << 16))>>17 );
                    break;

                default:
                    /* Unknown inst. */
                    break;
            }
            break;
    }
}

void fpu_decode_cat1_instn(CPURH850State *env, DisasContext *ctx)
{
    int rs1 = GET_RS1(ctx->opcode);
    int rs2 = GET_RS2(ctx->opcode);
    int rs3 = GET_RS3(ctx->opcode);

    fpu_gen_cat1_ir(env, ctx, MASK_OP_FORMAT_FI(ctx->opcode), rs1, rs2, rs3);
}

/**
 * Initialize FPU.
 **/

void rh850_fpu_translate_init(void)
{
}