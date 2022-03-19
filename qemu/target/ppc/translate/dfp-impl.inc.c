/*** Decimal Floating Point ***/

static inline TCGv_ptr gen_fprp_ptr(TCGContext *tcg_ctx, int reg)
{
    TCGv_ptr r = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, r, tcg_ctx->cpu_env, offsetof(CPUPPCState, vsr[reg].u64[0]));
    return r;
}

#define GEN_DFP_T_A_B_Rc(name)                   \
static void gen_##name(DisasContext *ctx)        \
{                                                \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;      \
    TCGv_ptr rd, ra, rb;                         \
    if (unlikely(!ctx->fpu_enabled)) {           \
        gen_exception(ctx, POWERPC_EXCP_FPU);    \
        return;                                  \
    }                                            \
    gen_update_nip(ctx, ctx->base.pc_next - 4);  \
    rd = gen_fprp_ptr(tcg_ctx, rD(ctx->opcode));          \
    ra = gen_fprp_ptr(tcg_ctx, rA(ctx->opcode));          \
    rb = gen_fprp_ptr(tcg_ctx, rB(ctx->opcode));          \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, rd, ra, rb);      \
    if (unlikely(Rc(ctx->opcode) != 0)) {        \
        gen_set_cr1_from_fpscr(ctx);             \
    }                                            \
    tcg_temp_free_ptr(tcg_ctx, rd);                       \
    tcg_temp_free_ptr(tcg_ctx, ra);                       \
    tcg_temp_free_ptr(tcg_ctx, rb);                       \
}

#define GEN_DFP_BF_A_B(name)                      \
static void gen_##name(DisasContext *ctx)         \
{                                                 \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;      \
    TCGv_ptr ra, rb;                              \
    if (unlikely(!ctx->fpu_enabled)) {            \
        gen_exception(ctx, POWERPC_EXCP_FPU);     \
        return;                                   \
    }                                             \
    gen_update_nip(ctx, ctx->base.pc_next - 4);            \
    ra = gen_fprp_ptr(tcg_ctx, rA(ctx->opcode));           \
    rb = gen_fprp_ptr(tcg_ctx, rB(ctx->opcode));           \
    gen_helper_##name(tcg_ctx, cpu_crf[crfD(ctx->opcode)], \
                      tcg_ctx->cpu_env, ra, rb);           \
    tcg_temp_free_ptr(tcg_ctx, ra);                        \
    tcg_temp_free_ptr(tcg_ctx, rb);                        \
}

#define GEN_DFP_BF_I_B(name)                      \
static void gen_##name(DisasContext *ctx)         \
{                                                 \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;      \
    TCGv_i32 uim;                                 \
    TCGv_ptr rb;                                  \
    if (unlikely(!ctx->fpu_enabled)) {            \
        gen_exception(ctx, POWERPC_EXCP_FPU);     \
        return;                                   \
    }                                             \
    gen_update_nip(ctx, ctx->base.pc_next - 4);            \
    uim = tcg_const_i32(tcg_ctx, UIMM5(ctx->opcode));      \
    rb = gen_fprp_ptr(tcg_ctx, rB(ctx->opcode));           \
    gen_helper_##name(tcg_ctx, cpu_crf[crfD(ctx->opcode)], \
                      tcg_ctx->cpu_env, uim, rb);          \
    tcg_temp_free_i32(tcg_ctx, uim);                       \
    tcg_temp_free_ptr(tcg_ctx, rb);                        \
}

#define GEN_DFP_BF_A_DCM(name)                    \
static void gen_##name(DisasContext *ctx)         \
{                                                 \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;      \
    TCGv_ptr ra;                                  \
    TCGv_i32 dcm;                                 \
    if (unlikely(!ctx->fpu_enabled)) {            \
        gen_exception(ctx, POWERPC_EXCP_FPU);     \
        return;                                   \
    }                                             \
    gen_update_nip(ctx, ctx->base.pc_next - 4);   \
    ra = gen_fprp_ptr(tcg_ctx, rA(ctx->opcode));           \
    dcm = tcg_const_i32(tcg_ctx, DCM(ctx->opcode));        \
    gen_helper_##name(tcg_ctx, cpu_crf[crfD(ctx->opcode)], \
                      tcg_ctx->cpu_env, ra, dcm);          \
    tcg_temp_free_ptr(tcg_ctx, ra);                        \
    tcg_temp_free_i32(tcg_ctx, dcm);                       \
}

#define GEN_DFP_T_B_U32_U32_Rc(name, u32f1, u32f2)    \
static void gen_##name(DisasContext *ctx)             \
{                                                     \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;      \
    TCGv_ptr rt, rb;                                  \
    TCGv_i32 u32_1, u32_2;                            \
    if (unlikely(!ctx->fpu_enabled)) {                \
        gen_exception(ctx, POWERPC_EXCP_FPU);         \
        return;                                       \
    }                                                 \
    gen_update_nip(ctx, ctx->base.pc_next - 4);       \
    rt = gen_fprp_ptr(tcg_ctx, rD(ctx->opcode));               \
    rb = gen_fprp_ptr(tcg_ctx, rB(ctx->opcode));               \
    u32_1 = tcg_const_i32(tcg_ctx, u32f1(ctx->opcode));        \
    u32_2 = tcg_const_i32(tcg_ctx, u32f2(ctx->opcode));        \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, rt, rb, u32_1, u32_2); \
    if (unlikely(Rc(ctx->opcode) != 0)) {             \
        gen_set_cr1_from_fpscr(ctx);                  \
    }                                                 \
    tcg_temp_free_ptr(tcg_ctx, rt);                            \
    tcg_temp_free_ptr(tcg_ctx, rb);                            \
    tcg_temp_free_i32(tcg_ctx, u32_1);                         \
    tcg_temp_free_i32(tcg_ctx, u32_2);                         \
}

#define GEN_DFP_T_A_B_I32_Rc(name, i32fld)       \
static void gen_##name(DisasContext *ctx)        \
{                                                \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;      \
    TCGv_ptr rt, ra, rb;                         \
    TCGv_i32 i32;                                \
    if (unlikely(!ctx->fpu_enabled)) {           \
        gen_exception(ctx, POWERPC_EXCP_FPU);    \
        return;                                  \
    }                                            \
    gen_update_nip(ctx, ctx->base.pc_next - 4);  \
    rt = gen_fprp_ptr(tcg_ctx, rD(ctx->opcode));          \
    ra = gen_fprp_ptr(tcg_ctx, rA(ctx->opcode));          \
    rb = gen_fprp_ptr(tcg_ctx, rB(ctx->opcode));          \
    i32 = tcg_const_i32(tcg_ctx, i32fld(ctx->opcode));    \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, rt, ra, rb, i32); \
    if (unlikely(Rc(ctx->opcode) != 0)) {        \
        gen_set_cr1_from_fpscr(ctx);             \
    }                                            \
    tcg_temp_free_ptr(tcg_ctx, rt);                       \
    tcg_temp_free_ptr(tcg_ctx, rb);                       \
    tcg_temp_free_ptr(tcg_ctx, ra);                       \
    tcg_temp_free_i32(tcg_ctx, i32);                      \
    }

#define GEN_DFP_T_B_Rc(name)                     \
static void gen_##name(DisasContext *ctx)        \
{                                                \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;      \
    TCGv_ptr rt, rb;                             \
    if (unlikely(!ctx->fpu_enabled)) {           \
        gen_exception(ctx, POWERPC_EXCP_FPU);    \
        return;                                  \
    }                                            \
    gen_update_nip(ctx, ctx->base.pc_next - 4);  \
    rt = gen_fprp_ptr(tcg_ctx, rD(ctx->opcode));          \
    rb = gen_fprp_ptr(tcg_ctx, rB(ctx->opcode));          \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, rt, rb);          \
    if (unlikely(Rc(ctx->opcode) != 0)) {        \
        gen_set_cr1_from_fpscr(ctx);             \
    }                                            \
    tcg_temp_free_ptr(tcg_ctx, rt);                       \
    tcg_temp_free_ptr(tcg_ctx, rb);                       \
    }

#define GEN_DFP_T_FPR_I32_Rc(name, fprfld, i32fld) \
static void gen_##name(DisasContext *ctx)          \
{                                                  \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;      \
    TCGv_ptr rt, rs;                               \
    TCGv_i32 i32;                                  \
    if (unlikely(!ctx->fpu_enabled)) {             \
        gen_exception(ctx, POWERPC_EXCP_FPU);      \
        return;                                    \
    }                                              \
    gen_update_nip(ctx, ctx->base.pc_next - 4);    \
    rt = gen_fprp_ptr(tcg_ctx, rD(ctx->opcode));            \
    rs = gen_fprp_ptr(tcg_ctx, fprfld(ctx->opcode));        \
    i32 = tcg_const_i32(tcg_ctx, i32fld(ctx->opcode));      \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, rt, rs, i32);       \
    if (unlikely(Rc(ctx->opcode) != 0)) {          \
        gen_set_cr1_from_fpscr(ctx);               \
    }                                              \
    tcg_temp_free_ptr(tcg_ctx, rt);                         \
    tcg_temp_free_ptr(tcg_ctx, rs);                         \
    tcg_temp_free_i32(tcg_ctx, i32);                        \
}

GEN_DFP_T_A_B_Rc(dadd)
GEN_DFP_T_A_B_Rc(daddq)
GEN_DFP_T_A_B_Rc(dsub)
GEN_DFP_T_A_B_Rc(dsubq)
GEN_DFP_T_A_B_Rc(dmul)
GEN_DFP_T_A_B_Rc(dmulq)
GEN_DFP_T_A_B_Rc(ddiv)
GEN_DFP_T_A_B_Rc(ddivq)
GEN_DFP_BF_A_B(dcmpu)
GEN_DFP_BF_A_B(dcmpuq)
GEN_DFP_BF_A_B(dcmpo)
GEN_DFP_BF_A_B(dcmpoq)
GEN_DFP_BF_A_DCM(dtstdc)
GEN_DFP_BF_A_DCM(dtstdcq)
GEN_DFP_BF_A_DCM(dtstdg)
GEN_DFP_BF_A_DCM(dtstdgq)
GEN_DFP_BF_A_B(dtstex)
GEN_DFP_BF_A_B(dtstexq)
GEN_DFP_BF_A_B(dtstsf)
GEN_DFP_BF_A_B(dtstsfq)
GEN_DFP_BF_I_B(dtstsfi)
GEN_DFP_BF_I_B(dtstsfiq)
GEN_DFP_T_B_U32_U32_Rc(dquai, SIMM5, RMC)
GEN_DFP_T_B_U32_U32_Rc(dquaiq, SIMM5, RMC)
GEN_DFP_T_A_B_I32_Rc(dqua, RMC)
GEN_DFP_T_A_B_I32_Rc(dquaq, RMC)
GEN_DFP_T_A_B_I32_Rc(drrnd, RMC)
GEN_DFP_T_A_B_I32_Rc(drrndq, RMC)
GEN_DFP_T_B_U32_U32_Rc(drintx, FPW, RMC)
GEN_DFP_T_B_U32_U32_Rc(drintxq, FPW, RMC)
GEN_DFP_T_B_U32_U32_Rc(drintn, FPW, RMC)
GEN_DFP_T_B_U32_U32_Rc(drintnq, FPW, RMC)
GEN_DFP_T_B_Rc(dctdp)
GEN_DFP_T_B_Rc(dctqpq)
GEN_DFP_T_B_Rc(drsp)
GEN_DFP_T_B_Rc(drdpq)
GEN_DFP_T_B_Rc(dcffix)
GEN_DFP_T_B_Rc(dcffixq)
GEN_DFP_T_B_Rc(dctfix)
GEN_DFP_T_B_Rc(dctfixq)
GEN_DFP_T_FPR_I32_Rc(ddedpd, rB, SP)
GEN_DFP_T_FPR_I32_Rc(ddedpdq, rB, SP)
GEN_DFP_T_FPR_I32_Rc(denbcd, rB, SP)
GEN_DFP_T_FPR_I32_Rc(denbcdq, rB, SP)
GEN_DFP_T_B_Rc(dxex)
GEN_DFP_T_B_Rc(dxexq)
GEN_DFP_T_A_B_Rc(diex)
GEN_DFP_T_A_B_Rc(diexq)
GEN_DFP_T_FPR_I32_Rc(dscli, rA, DCM)
GEN_DFP_T_FPR_I32_Rc(dscliq, rA, DCM)
GEN_DFP_T_FPR_I32_Rc(dscri, rA, DCM)
GEN_DFP_T_FPR_I32_Rc(dscriq, rA, DCM)

#undef GEN_DFP_T_A_B_Rc
#undef GEN_DFP_BF_A_B
#undef GEN_DFP_BF_A_DCM
#undef GEN_DFP_T_B_U32_U32_Rc
#undef GEN_DFP_T_A_B_I32_Rc
#undef GEN_DFP_T_B_Rc
#undef GEN_DFP_T_FPR_I32_Rc
