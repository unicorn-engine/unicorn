/***                           VSX extension                               ***/

static inline void get_cpu_vsrh(TCGContext *tcg_ctx, TCGv_i64 dst, int n)
{
    tcg_gen_ld_i64(tcg_ctx, dst, tcg_ctx->cpu_env, vsr64_offset(n, true));
}

static inline void get_cpu_vsrl(TCGContext *tcg_ctx, TCGv_i64 dst, int n)
{
    tcg_gen_ld_i64(tcg_ctx, dst, tcg_ctx->cpu_env, vsr64_offset(n, false));
}

static inline void set_cpu_vsrh(TCGContext *tcg_ctx, int n, TCGv_i64 src)
{
    tcg_gen_st_i64(tcg_ctx, src, tcg_ctx->cpu_env, vsr64_offset(n, true));
}

static inline void set_cpu_vsrl(TCGContext *tcg_ctx, int n, TCGv_i64 src)
{
    tcg_gen_st_i64(tcg_ctx, src, tcg_ctx->cpu_env, vsr64_offset(n, false));
}

static inline TCGv_ptr gen_vsr_ptr(TCGContext *tcg_ctx, int reg)
{
    TCGv_ptr r = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, r, tcg_ctx->cpu_env, vsr_full_offset(reg));
    return r;
}

#define VSX_LOAD_SCALAR(name, operation)                      \
static void gen_##name(DisasContext *ctx)                     \
{                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv EA;                                                  \
    TCGv_i64 t0;                                              \
    if (unlikely(!ctx->vsx_enabled)) {                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                \
        return;                                               \
    }                                                         \
    t0 = tcg_temp_new_i64(tcg_ctx);                                  \
    gen_set_access_type(ctx, ACCESS_INT);                     \
    EA = tcg_temp_new(tcg_ctx);                                      \
    gen_addr_reg_index(ctx, EA);                              \
    gen_qemu_##operation(ctx, t0, EA);                        \
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), t0);                        \
    /* NOTE: cpu_vsrl is undefined */                         \
    tcg_temp_free(tcg_ctx, EA);                                        \
    tcg_temp_free_i64(tcg_ctx, t0);                                    \
}

VSX_LOAD_SCALAR(lxsdx, ld64_i64)
VSX_LOAD_SCALAR(lxsiwax, ld32s_i64)
VSX_LOAD_SCALAR(lxsibzx, ld8u_i64)
VSX_LOAD_SCALAR(lxsihzx, ld16u_i64)
VSX_LOAD_SCALAR(lxsiwzx, ld32u_i64)
VSX_LOAD_SCALAR(lxsspx, ld32fs)

static void gen_lxvd2x(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 t0;
    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    t0 = tcg_temp_new_i64(tcg_ctx);
    gen_set_access_type(ctx, ACCESS_INT);
    EA = tcg_temp_new(tcg_ctx);
    gen_addr_reg_index(ctx, EA);
    gen_qemu_ld64_i64(ctx, t0, EA);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), t0);
    tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
    gen_qemu_ld64_i64(ctx, t0, EA);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), t0);
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void gen_lxvdsx(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 t0;
    TCGv_i64 t1;
    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);
    gen_set_access_type(ctx, ACCESS_INT);
    EA = tcg_temp_new(tcg_ctx);
    gen_addr_reg_index(ctx, EA);
    gen_qemu_ld64_i64(ctx, t0, EA);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), t0);
    tcg_gen_mov_i64(tcg_ctx, t1, t0);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), t1);
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

static void gen_lxvw4x(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);

    gen_set_access_type(ctx, ACCESS_INT);
    EA = tcg_temp_new(tcg_ctx);

    gen_addr_reg_index(ctx, EA);
    if (ctx->le_mode) {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);

        tcg_gen_qemu_ld_i64(tcg_ctx, t0, EA, ctx->mem_idx, MO_LEQ);
        tcg_gen_shri_i64(tcg_ctx, t1, t0, 32);
        tcg_gen_deposit_i64(tcg_ctx, xth, t1, t0, 32, 32);
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
        tcg_gen_qemu_ld_i64(tcg_ctx, t0, EA, ctx->mem_idx, MO_LEQ);
        tcg_gen_shri_i64(tcg_ctx, t1, t0, 32);
        tcg_gen_deposit_i64(tcg_ctx, xtl, t1, t0, 32, 32);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
    } else {
        tcg_gen_qemu_ld_i64(tcg_ctx, xth, EA, ctx->mem_idx, MO_BEQ);
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
        tcg_gen_qemu_ld_i64(tcg_ctx, xtl, EA, ctx->mem_idx, MO_BEQ);
    }
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
}

static void gen_bswap16x8(TCGContext *tcg_ctx, TCGv_i64 outh, TCGv_i64 outl,
                          TCGv_i64 inh, TCGv_i64 inl)
{
    TCGv_i64 mask = tcg_const_i64(tcg_ctx, 0x00FF00FF00FF00FF);
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);

    /* outh = ((inh & mask) << 8) | ((inh >> 8) & mask) */
    tcg_gen_and_i64(tcg_ctx, t0, inh, mask);
    tcg_gen_shli_i64(tcg_ctx, t0, t0, 8);
    tcg_gen_shri_i64(tcg_ctx, t1, inh, 8);
    tcg_gen_and_i64(tcg_ctx, t1, t1, mask);
    tcg_gen_or_i64(tcg_ctx, outh, t0, t1);

    /* outl = ((inl & mask) << 8) | ((inl >> 8) & mask) */
    tcg_gen_and_i64(tcg_ctx, t0, inl, mask);
    tcg_gen_shli_i64(tcg_ctx, t0, t0, 8);
    tcg_gen_shri_i64(tcg_ctx, t1, inl, 8);
    tcg_gen_and_i64(tcg_ctx, t1, t1, mask);
    tcg_gen_or_i64(tcg_ctx, outl, t0, t1);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, mask);
}

static void gen_bswap32x4(TCGContext *tcg_ctx, TCGv_i64 outh, TCGv_i64 outl,
                          TCGv_i64 inh, TCGv_i64 inl)
{
    TCGv_i64 hi = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 lo = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_bswap64_i64(tcg_ctx, hi, inh);
    tcg_gen_bswap64_i64(tcg_ctx, lo, inl);
    tcg_gen_shri_i64(tcg_ctx, outh, hi, 32);
    tcg_gen_deposit_i64(tcg_ctx, outh, outh, hi, 32, 32);
    tcg_gen_shri_i64(tcg_ctx, outl, lo, 32);
    tcg_gen_deposit_i64(tcg_ctx, outl, outl, lo, 32, 32);

    tcg_temp_free_i64(tcg_ctx, hi);
    tcg_temp_free_i64(tcg_ctx, lo);
}

static void gen_lxvh8x(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 xth;
    TCGv_i64 xtl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    gen_set_access_type(ctx, ACCESS_INT);

    EA = tcg_temp_new(tcg_ctx);
    gen_addr_reg_index(ctx, EA);
    tcg_gen_qemu_ld_i64(tcg_ctx, xth, EA, ctx->mem_idx, MO_BEQ);
    tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
    tcg_gen_qemu_ld_i64(tcg_ctx, xtl, EA, ctx->mem_idx, MO_BEQ);
    if (ctx->le_mode) {
        gen_bswap16x8(tcg_ctx, xth, xtl, xth, xtl);
    }
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
}

static void gen_lxvb16x(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 xth;
    TCGv_i64 xtl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    gen_set_access_type(ctx, ACCESS_INT);
    EA = tcg_temp_new(tcg_ctx);
    gen_addr_reg_index(ctx, EA);
    tcg_gen_qemu_ld_i64(tcg_ctx, xth, EA, ctx->mem_idx, MO_BEQ);
    tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
    tcg_gen_qemu_ld_i64(tcg_ctx, xtl, EA, ctx->mem_idx, MO_BEQ);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
}

#define VSX_VECTOR_LOAD(name, op, indexed)                  \
static void gen_##name(DisasContext *ctx)                   \
{                                                           \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    int xt;                                                 \
    TCGv EA;                                                \
    TCGv_i64 xth;                                           \
    TCGv_i64 xtl;                                           \
                                                            \
    if (indexed) {                                          \
        xt = xT(ctx->opcode);                               \
    } else {                                                \
        xt = DQxT(ctx->opcode);                             \
    }                                                       \
                                                            \
    if (xt < 32) {                                          \
        if (unlikely(!ctx->vsx_enabled)) {                  \
            gen_exception(ctx, POWERPC_EXCP_VSXU);          \
            return;                                         \
        }                                                   \
    } else {                                                \
        if (unlikely(!ctx->altivec_enabled)) {              \
            gen_exception(ctx, POWERPC_EXCP_VPU);           \
            return;                                         \
        }                                                   \
    }                                                       \
    xth = tcg_temp_new_i64(tcg_ctx);                               \
    xtl = tcg_temp_new_i64(tcg_ctx);                               \
    gen_set_access_type(ctx, ACCESS_INT);                   \
    EA = tcg_temp_new(tcg_ctx);                                    \
    if (indexed) {                                          \
        gen_addr_reg_index(ctx, EA);                        \
    } else {                                                \
        gen_addr_imm_index(ctx, EA, 0x0F);                  \
    }                                                       \
    if (ctx->le_mode) {                                     \
        tcg_gen_qemu_##op(tcg_ctx, xtl, EA, ctx->mem_idx, MO_LEQ);   \
        set_cpu_vsrl(tcg_ctx, xt, xtl);                              \
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);                         \
        tcg_gen_qemu_##op(tcg_ctx, xth, EA, ctx->mem_idx, MO_LEQ);   \
        set_cpu_vsrh(tcg_ctx, xt, xth);                              \
    } else {                                                \
        tcg_gen_qemu_##op(tcg_ctx, xth, EA, ctx->mem_idx, MO_BEQ);   \
        set_cpu_vsrh(tcg_ctx, xt, xth);                              \
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);                         \
        tcg_gen_qemu_##op(tcg_ctx, xtl, EA, ctx->mem_idx, MO_BEQ);   \
        set_cpu_vsrl(tcg_ctx, xt, xtl);                              \
    }                                                       \
    tcg_temp_free(tcg_ctx, EA);                                      \
    tcg_temp_free_i64(tcg_ctx, xth);                                 \
    tcg_temp_free_i64(tcg_ctx, xtl);                                 \
}

VSX_VECTOR_LOAD(lxv, ld_i64, 0)
VSX_VECTOR_LOAD(lxvx, ld_i64, 1)

#define VSX_VECTOR_STORE(name, op, indexed)                 \
static void gen_##name(DisasContext *ctx)                   \
{                                                           \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    int xt;                                                 \
    TCGv EA;                                                \
    TCGv_i64 xth;                                           \
    TCGv_i64 xtl;                                           \
                                                            \
    if (indexed) {                                          \
        xt = xT(ctx->opcode);                               \
    } else {                                                \
        xt = DQxT(ctx->opcode);                             \
    }                                                       \
                                                            \
    if (xt < 32) {                                          \
        if (unlikely(!ctx->vsx_enabled)) {                  \
            gen_exception(ctx, POWERPC_EXCP_VSXU);          \
            return;                                         \
        }                                                   \
    } else {                                                \
        if (unlikely(!ctx->altivec_enabled)) {              \
            gen_exception(ctx, POWERPC_EXCP_VPU);           \
            return;                                         \
        }                                                   \
    }                                                       \
    xth = tcg_temp_new_i64(tcg_ctx);                               \
    xtl = tcg_temp_new_i64(tcg_ctx);                               \
    get_cpu_vsrh(tcg_ctx, xth, xt);                                  \
    get_cpu_vsrl(tcg_ctx, xtl, xt);                                  \
    gen_set_access_type(ctx, ACCESS_INT);                   \
    EA = tcg_temp_new(tcg_ctx);                                    \
    if (indexed) {                                          \
        gen_addr_reg_index(ctx, EA);                        \
    } else {                                                \
        gen_addr_imm_index(ctx, EA, 0x0F);                  \
    }                                                       \
    if (ctx->le_mode) {                                     \
        tcg_gen_qemu_##op(tcg_ctx, xtl, EA, ctx->mem_idx, MO_LEQ);   \
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);                         \
        tcg_gen_qemu_##op(tcg_ctx, xth, EA, ctx->mem_idx, MO_LEQ);   \
    } else {                                                \
        tcg_gen_qemu_##op(tcg_ctx, xth, EA, ctx->mem_idx, MO_BEQ);   \
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);                         \
        tcg_gen_qemu_##op(tcg_ctx, xtl, EA, ctx->mem_idx, MO_BEQ);   \
    }                                                       \
    tcg_temp_free(tcg_ctx, EA);                                      \
    tcg_temp_free_i64(tcg_ctx, xth);                                 \
    tcg_temp_free_i64(tcg_ctx, xtl);                                 \
}

VSX_VECTOR_STORE(stxv, st_i64, 0)
VSX_VECTOR_STORE(stxvx, st_i64, 1)

#ifdef TARGET_PPC64
#define VSX_VECTOR_LOAD_STORE_LENGTH(name)                         \
static void gen_##name(DisasContext *ctx)                          \
{                                                                  \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv EA;                                                       \
    TCGv_ptr xt;                                                   \
                                                                   \
    if (xT(ctx->opcode) < 32) {                                    \
        if (unlikely(!ctx->vsx_enabled)) {                         \
            gen_exception(ctx, POWERPC_EXCP_VSXU);                 \
            return;                                                \
        }                                                          \
    } else {                                                       \
        if (unlikely(!ctx->altivec_enabled)) {                     \
            gen_exception(ctx, POWERPC_EXCP_VPU);                  \
            return;                                                \
        }                                                          \
    }                                                              \
    EA = tcg_temp_new(tcg_ctx);                                           \
    xt = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));                             \
    gen_set_access_type(ctx, ACCESS_INT);                          \
    gen_addr_register(ctx, EA);                                    \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, EA, xt, cpu_gpr[rB(ctx->opcode)]);  \
    tcg_temp_free(tcg_ctx, EA);                                             \
    tcg_temp_free_ptr(tcg_ctx, xt);                                         \
}

VSX_VECTOR_LOAD_STORE_LENGTH(lxvl)
VSX_VECTOR_LOAD_STORE_LENGTH(lxvll)
VSX_VECTOR_LOAD_STORE_LENGTH(stxvl)
VSX_VECTOR_LOAD_STORE_LENGTH(stxvll)
#endif

#define VSX_LOAD_SCALAR_DS(name, operation)                       \
static void gen_##name(DisasContext *ctx)                         \
{                                                                 \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv EA;                                                      \
    TCGv_i64 xth;                                                 \
                                                                  \
    if (unlikely(!ctx->altivec_enabled)) {                        \
        gen_exception(ctx, POWERPC_EXCP_VPU);                     \
        return;                                                   \
    }                                                             \
    xth = tcg_temp_new_i64(tcg_ctx);                                     \
    gen_set_access_type(ctx, ACCESS_INT);                         \
    EA = tcg_temp_new(tcg_ctx);                                          \
    gen_addr_imm_index(ctx, EA, 0x03);                            \
    gen_qemu_##operation(ctx, xth, EA);                           \
    set_cpu_vsrh(tcg_ctx, rD(ctx->opcode) + 32, xth);                      \
    /* NOTE: cpu_vsrl is undefined */                             \
    tcg_temp_free(tcg_ctx, EA);                                            \
    tcg_temp_free_i64(tcg_ctx, xth);                                       \
}

VSX_LOAD_SCALAR_DS(lxsd, ld64_i64)
VSX_LOAD_SCALAR_DS(lxssp, ld32fs)

#define VSX_STORE_SCALAR(name, operation)                     \
static void gen_##name(DisasContext *ctx)                     \
{                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv EA;                                                  \
    TCGv_i64 t0;                                              \
    if (unlikely(!ctx->vsx_enabled)) {                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                \
        return;                                               \
    }                                                         \
    t0 = tcg_temp_new_i64(tcg_ctx);                                  \
    gen_set_access_type(ctx, ACCESS_INT);                     \
    EA = tcg_temp_new(tcg_ctx);                                      \
    gen_addr_reg_index(ctx, EA);                              \
    get_cpu_vsrh(tcg_ctx, t0, xS(ctx->opcode));                        \
    gen_qemu_##operation(ctx, t0, EA);                        \
    tcg_temp_free(tcg_ctx, EA);                                        \
    tcg_temp_free_i64(tcg_ctx, t0);                                    \
}

VSX_STORE_SCALAR(stxsdx, st64_i64)

VSX_STORE_SCALAR(stxsibx, st8_i64)
VSX_STORE_SCALAR(stxsihx, st16_i64)
VSX_STORE_SCALAR(stxsiwx, st32_i64)
VSX_STORE_SCALAR(stxsspx, st32fs)

static void gen_stxvd2x(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 t0;
    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    t0 = tcg_temp_new_i64(tcg_ctx);
    gen_set_access_type(ctx, ACCESS_INT);
    EA = tcg_temp_new(tcg_ctx);
    gen_addr_reg_index(ctx, EA);
    get_cpu_vsrh(tcg_ctx, t0, xS(ctx->opcode));
    gen_qemu_st64_i64(ctx, t0, EA);
    tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
    get_cpu_vsrl(tcg_ctx, t0, xS(ctx->opcode));
    gen_qemu_st64_i64(ctx, t0, EA);
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void gen_stxvw4x(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 xsh;
    TCGv_i64 xsl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xsh = tcg_temp_new_i64(tcg_ctx);
    xsl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xsh, xS(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xsl, xS(ctx->opcode));
    gen_set_access_type(ctx, ACCESS_INT);
    EA = tcg_temp_new(tcg_ctx);
    gen_addr_reg_index(ctx, EA);
    if (ctx->le_mode) {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);

        tcg_gen_shri_i64(tcg_ctx, t0, xsh, 32);
        tcg_gen_deposit_i64(tcg_ctx, t1, t0, xsh, 32, 32);
        tcg_gen_qemu_st_i64(tcg_ctx, t1, EA, ctx->mem_idx, MO_LEQ);
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
        tcg_gen_shri_i64(tcg_ctx, t0, xsl, 32);
        tcg_gen_deposit_i64(tcg_ctx, t1, t0, xsl, 32, 32);
        tcg_gen_qemu_st_i64(tcg_ctx, t1, EA, ctx->mem_idx, MO_LEQ);
        tcg_temp_free_i64(tcg_ctx, t0);
        tcg_temp_free_i64(tcg_ctx, t1);
    } else {
        tcg_gen_qemu_st_i64(tcg_ctx, xsh, EA, ctx->mem_idx, MO_BEQ);
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
        tcg_gen_qemu_st_i64(tcg_ctx, xsl, EA, ctx->mem_idx, MO_BEQ);
    }
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, xsh);
    tcg_temp_free_i64(tcg_ctx, xsl);
}

static void gen_stxvh8x(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 xsh;
    TCGv_i64 xsl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xsh = tcg_temp_new_i64(tcg_ctx);
    xsl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xsh, xS(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xsl, xS(ctx->opcode));
    gen_set_access_type(ctx, ACCESS_INT);
    EA = tcg_temp_new(tcg_ctx);
    gen_addr_reg_index(ctx, EA);
    if (ctx->le_mode) {
        TCGv_i64 outh = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 outl = tcg_temp_new_i64(tcg_ctx);

        gen_bswap16x8(tcg_ctx, outh, outl, xsh, xsl);
        tcg_gen_qemu_st_i64(tcg_ctx, outh, EA, ctx->mem_idx, MO_BEQ);
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
        tcg_gen_qemu_st_i64(tcg_ctx, outl, EA, ctx->mem_idx, MO_BEQ);
        tcg_temp_free_i64(tcg_ctx, outh);
        tcg_temp_free_i64(tcg_ctx, outl);
    } else {
        tcg_gen_qemu_st_i64(tcg_ctx, xsh, EA, ctx->mem_idx, MO_BEQ);
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
        tcg_gen_qemu_st_i64(tcg_ctx, xsl, EA, ctx->mem_idx, MO_BEQ);
    }
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, xsh);
    tcg_temp_free_i64(tcg_ctx, xsl);
}

static void gen_stxvb16x(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv EA;
    TCGv_i64 xsh;
    TCGv_i64 xsl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xsh = tcg_temp_new_i64(tcg_ctx);
    xsl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xsh, xS(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xsl, xS(ctx->opcode));
    gen_set_access_type(ctx, ACCESS_INT);
    EA = tcg_temp_new(tcg_ctx);
    gen_addr_reg_index(ctx, EA);
    tcg_gen_qemu_st_i64(tcg_ctx, xsh, EA, ctx->mem_idx, MO_BEQ);
    tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);
    tcg_gen_qemu_st_i64(tcg_ctx, xsl, EA, ctx->mem_idx, MO_BEQ);
    tcg_temp_free(tcg_ctx, EA);
    tcg_temp_free_i64(tcg_ctx, xsh);
    tcg_temp_free_i64(tcg_ctx, xsl);
}

#define VSX_STORE_SCALAR_DS(name, operation)                      \
static void gen_##name(DisasContext *ctx)                         \
{                                                                 \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv EA;                                                      \
    TCGv_i64 xth;                                                 \
                                                                  \
    if (unlikely(!ctx->altivec_enabled)) {                        \
        gen_exception(ctx, POWERPC_EXCP_VPU);                     \
        return;                                                   \
    }                                                             \
    xth = tcg_temp_new_i64(tcg_ctx);                                     \
    get_cpu_vsrh(tcg_ctx, xth, rD(ctx->opcode) + 32);                      \
    gen_set_access_type(ctx, ACCESS_INT);                         \
    EA = tcg_temp_new(tcg_ctx);                                          \
    gen_addr_imm_index(ctx, EA, 0x03);                            \
    gen_qemu_##operation(ctx, xth, EA);                           \
    /* NOTE: cpu_vsrl is undefined */                             \
    tcg_temp_free(tcg_ctx, EA);                                            \
    tcg_temp_free_i64(tcg_ctx, xth);                                       \
}

VSX_STORE_SCALAR_DS(stxsd, st64_i64)
VSX_STORE_SCALAR_DS(stxssp, st32fs)

static void gen_mfvsrwz(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (xS(ctx->opcode) < 32) {
        if (unlikely(!ctx->fpu_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_FPU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 xsh = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xsh, xS(ctx->opcode));
    tcg_gen_ext32u_i64(tcg_ctx, tmp, xsh);
    tcg_gen_trunc_i64_tl(tcg_ctx, cpu_gpr[rA(ctx->opcode)], tmp);
    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, xsh);
}

static void gen_mtvsrwa(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (xS(ctx->opcode) < 32) {
        if (unlikely(!ctx->fpu_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_FPU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 xsh = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_extu_tl_i64(tcg_ctx, tmp, cpu_gpr[rA(ctx->opcode)]);
    tcg_gen_ext32s_i64(tcg_ctx, xsh, tmp);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xsh);
    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, xsh);
}

static void gen_mtvsrwz(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (xS(ctx->opcode) < 32) {
        if (unlikely(!ctx->fpu_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_FPU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 xsh = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_extu_tl_i64(tcg_ctx, tmp, cpu_gpr[rA(ctx->opcode)]);
    tcg_gen_ext32u_i64(tcg_ctx, xsh, tmp);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xsh);
    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, xsh);
}

#if defined(TARGET_PPC64)
static void gen_mfvsrd(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0;
    if (xS(ctx->opcode) < 32) {
        if (unlikely(!ctx->fpu_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_FPU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }
    t0 = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, t0, xS(ctx->opcode));
    tcg_gen_mov_i64(tcg_ctx, cpu_gpr[rA(ctx->opcode)], t0);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void gen_mtvsrd(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0;
    if (xS(ctx->opcode) < 32) {
        if (unlikely(!ctx->fpu_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_FPU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }
    t0 = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_mov_i64(tcg_ctx, t0, cpu_gpr[rA(ctx->opcode)]);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), t0);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void gen_mfvsrld(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0;
    if (xS(ctx->opcode) < 32) {
        if (unlikely(!ctx->vsx_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VSXU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }
    t0 = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrl(tcg_ctx, t0, xS(ctx->opcode));
    tcg_gen_mov_i64(tcg_ctx, cpu_gpr[rA(ctx->opcode)], t0);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void gen_mtvsrdd(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0;
    if (xT(ctx->opcode) < 32) {
        if (unlikely(!ctx->vsx_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VSXU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }

    t0 = tcg_temp_new_i64(tcg_ctx);
    if (!rA(ctx->opcode)) {
        tcg_gen_movi_i64(tcg_ctx, t0, 0);
    } else {
        tcg_gen_mov_i64(tcg_ctx, t0, cpu_gpr[rA(ctx->opcode)]);
    }
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), t0);

    tcg_gen_mov_i64(tcg_ctx, t0, cpu_gpr[rB(ctx->opcode)]);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), t0);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void gen_mtvsrws(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0;
    if (xT(ctx->opcode) < 32) {
        if (unlikely(!ctx->vsx_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VSXU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }

    t0 = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_deposit_i64(tcg_ctx, t0, cpu_gpr[rA(ctx->opcode)],
                        cpu_gpr[rA(ctx->opcode)], 32, 32);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), t0);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), t0);
    tcg_temp_free_i64(tcg_ctx, t0);
}

#endif

static void gen_xxpermdi(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xh, xl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }

    xh = tcg_temp_new_i64(tcg_ctx);
    xl = tcg_temp_new_i64(tcg_ctx);

    if (unlikely((xT(ctx->opcode) == xA(ctx->opcode)) ||
                 (xT(ctx->opcode) == xB(ctx->opcode)))) {
        if ((DM(ctx->opcode) & 2) == 0) {
            get_cpu_vsrh(tcg_ctx, xh, xA(ctx->opcode));
        } else {
            get_cpu_vsrl(tcg_ctx, xh, xA(ctx->opcode));
        }
        if ((DM(ctx->opcode) & 1) == 0) {
            get_cpu_vsrh(tcg_ctx, xl, xB(ctx->opcode));
        } else {
            get_cpu_vsrl(tcg_ctx, xl, xB(ctx->opcode));
        }

        set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xh);
        set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xl);
    } else {
        if ((DM(ctx->opcode) & 2) == 0) {
            get_cpu_vsrh(tcg_ctx, xh, xA(ctx->opcode));
            set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xh);
        } else {
            get_cpu_vsrl(tcg_ctx, xh, xA(ctx->opcode));
            set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xh);
        }
        if ((DM(ctx->opcode) & 1) == 0) {
            get_cpu_vsrh(tcg_ctx, xl, xB(ctx->opcode));
            set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xl);
        } else {
            get_cpu_vsrl(tcg_ctx, xl, xB(ctx->opcode));
            set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xl);
        }
    }
    tcg_temp_free_i64(tcg_ctx, xh);
    tcg_temp_free_i64(tcg_ctx, xl);
}

#define OP_ABS 1
#define OP_NABS 2
#define OP_NEG 3
#define OP_CPSGN 4
#define SGN_MASK_DP  0x8000000000000000ull
#define SGN_MASK_SP 0x8000000080000000ull

#define VSX_SCALAR_MOVE(name, op, sgn_mask)                       \
static void glue(gen_, name)(DisasContext *ctx)                   \
    {                                                             \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
        TCGv_i64 xb, sgm;                                         \
        if (unlikely(!ctx->vsx_enabled)) {                        \
            gen_exception(ctx, POWERPC_EXCP_VSXU);                \
            return;                                               \
        }                                                         \
        xb = tcg_temp_new_i64(tcg_ctx);                                  \
        sgm = tcg_temp_new_i64(tcg_ctx);                                 \
        get_cpu_vsrh(tcg_ctx, xb, xB(ctx->opcode));                        \
        tcg_gen_movi_i64(tcg_ctx, sgm, sgn_mask);                          \
        switch (op) {                                             \
            case OP_ABS: {                                        \
                tcg_gen_andc_i64(tcg_ctx, xb, xb, sgm);                    \
                break;                                            \
            }                                                     \
            case OP_NABS: {                                       \
                tcg_gen_or_i64(tcg_ctx, xb, xb, sgm);                      \
                break;                                            \
            }                                                     \
            case OP_NEG: {                                        \
                tcg_gen_xor_i64(tcg_ctx, xb, xb, sgm);                     \
                break;                                            \
            }                                                     \
            case OP_CPSGN: {                                      \
                TCGv_i64 xa = tcg_temp_new_i64(tcg_ctx);                 \
                get_cpu_vsrh(tcg_ctx, xa, xA(ctx->opcode));                \
                tcg_gen_and_i64(tcg_ctx, xa, xa, sgm);                     \
                tcg_gen_andc_i64(tcg_ctx, xb, xb, sgm);                    \
                tcg_gen_or_i64(tcg_ctx, xb, xb, xa);                       \
                tcg_temp_free_i64(tcg_ctx, xa);                            \
                break;                                            \
            }                                                     \
        }                                                         \
        set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xb);                        \
        tcg_temp_free_i64(tcg_ctx, xb);                                    \
        tcg_temp_free_i64(tcg_ctx, sgm);                                   \
    }

VSX_SCALAR_MOVE(xsabsdp, OP_ABS, SGN_MASK_DP)
VSX_SCALAR_MOVE(xsnabsdp, OP_NABS, SGN_MASK_DP)
VSX_SCALAR_MOVE(xsnegdp, OP_NEG, SGN_MASK_DP)
VSX_SCALAR_MOVE(xscpsgndp, OP_CPSGN, SGN_MASK_DP)

#define VSX_SCALAR_MOVE_QP(name, op, sgn_mask)                    \
static void glue(gen_, name)(DisasContext *ctx)                   \
{                                                                 \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    int xa;                                                       \
    int xt = rD(ctx->opcode) + 32;                                \
    int xb = rB(ctx->opcode) + 32;                                \
    TCGv_i64 xah, xbh, xbl, sgm, tmp;                             \
                                                                  \
    if (unlikely(!ctx->vsx_enabled)) {                            \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                    \
        return;                                                   \
    }                                                             \
    xbh = tcg_temp_new_i64(tcg_ctx);                                     \
    xbl = tcg_temp_new_i64(tcg_ctx);                                     \
    sgm = tcg_temp_new_i64(tcg_ctx);                                     \
    tmp = tcg_temp_new_i64(tcg_ctx);                                     \
    get_cpu_vsrh(tcg_ctx, xbh, xb);                                        \
    get_cpu_vsrl(tcg_ctx, xbl, xb);                                        \
    tcg_gen_movi_i64(tcg_ctx, sgm, sgn_mask);                              \
    switch (op) {                                                 \
    case OP_ABS:                                                  \
        tcg_gen_andc_i64(tcg_ctx, xbh, xbh, sgm);                          \
        break;                                                    \
    case OP_NABS:                                                 \
        tcg_gen_or_i64(tcg_ctx, xbh, xbh, sgm);                            \
        break;                                                    \
    case OP_NEG:                                                  \
        tcg_gen_xor_i64(tcg_ctx, xbh, xbh, sgm);                           \
        break;                                                    \
    case OP_CPSGN:                                                \
        xah = tcg_temp_new_i64(tcg_ctx);                                 \
        xa = rA(ctx->opcode) + 32;                                \
        get_cpu_vsrh(tcg_ctx, tmp, xa);                                    \
        tcg_gen_and_i64(tcg_ctx, xah, tmp, sgm);                           \
        tcg_gen_andc_i64(tcg_ctx, xbh, xbh, sgm);                          \
        tcg_gen_or_i64(tcg_ctx, xbh, xbh, xah);                            \
        tcg_temp_free_i64(tcg_ctx, xah);                                   \
        break;                                                    \
    }                                                             \
    set_cpu_vsrh(tcg_ctx, xt, xbh);                                        \
    set_cpu_vsrl(tcg_ctx, xt, xbl);                                        \
    tcg_temp_free_i64(tcg_ctx, xbl);                                       \
    tcg_temp_free_i64(tcg_ctx, xbh);                                       \
    tcg_temp_free_i64(tcg_ctx, sgm);                                       \
    tcg_temp_free_i64(tcg_ctx, tmp);                                       \
}

VSX_SCALAR_MOVE_QP(xsabsqp, OP_ABS, SGN_MASK_DP)
VSX_SCALAR_MOVE_QP(xsnabsqp, OP_NABS, SGN_MASK_DP)
VSX_SCALAR_MOVE_QP(xsnegqp, OP_NEG, SGN_MASK_DP)
VSX_SCALAR_MOVE_QP(xscpsgnqp, OP_CPSGN, SGN_MASK_DP)

#define VSX_VECTOR_MOVE(name, op, sgn_mask)                      \
static void glue(gen_, name)(DisasContext *ctx)                  \
    {                                                            \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
        TCGv_i64 xbh, xbl, sgm;                                  \
        if (unlikely(!ctx->vsx_enabled)) {                       \
            gen_exception(ctx, POWERPC_EXCP_VSXU);               \
            return;                                              \
        }                                                        \
        xbh = tcg_temp_new_i64(tcg_ctx);                                \
        xbl = tcg_temp_new_i64(tcg_ctx);                                \
        sgm = tcg_temp_new_i64(tcg_ctx);                                \
        get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));                      \
        get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));                      \
        tcg_gen_movi_i64(tcg_ctx, sgm, sgn_mask);                         \
        switch (op) {                                            \
            case OP_ABS: {                                       \
                tcg_gen_andc_i64(tcg_ctx, xbh, xbh, sgm);                 \
                tcg_gen_andc_i64(tcg_ctx, xbl, xbl, sgm);                 \
                break;                                           \
            }                                                    \
            case OP_NABS: {                                      \
                tcg_gen_or_i64(tcg_ctx, xbh, xbh, sgm);                   \
                tcg_gen_or_i64(tcg_ctx, xbl, xbl, sgm);                   \
                break;                                           \
            }                                                    \
            case OP_NEG: {                                       \
                tcg_gen_xor_i64(tcg_ctx, xbh, xbh, sgm);                  \
                tcg_gen_xor_i64(tcg_ctx, xbl, xbl, sgm);                  \
                break;                                           \
            }                                                    \
            case OP_CPSGN: {                                     \
                TCGv_i64 xah = tcg_temp_new_i64(tcg_ctx);               \
                TCGv_i64 xal = tcg_temp_new_i64(tcg_ctx);               \
                get_cpu_vsrh(tcg_ctx, xah, xA(ctx->opcode));              \
                get_cpu_vsrl(tcg_ctx, xal, xA(ctx->opcode));              \
                tcg_gen_and_i64(tcg_ctx, xah, xah, sgm);                  \
                tcg_gen_and_i64(tcg_ctx, xal, xal, sgm);                  \
                tcg_gen_andc_i64(tcg_ctx, xbh, xbh, sgm);                 \
                tcg_gen_andc_i64(tcg_ctx, xbl, xbl, sgm);                 \
                tcg_gen_or_i64(tcg_ctx, xbh, xbh, xah);                   \
                tcg_gen_or_i64(tcg_ctx, xbl, xbl, xal);                   \
                tcg_temp_free_i64(tcg_ctx, xah);                          \
                tcg_temp_free_i64(tcg_ctx, xal);                          \
                break;                                           \
            }                                                    \
        }                                                        \
        set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xbh);                      \
        set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xbl);                      \
        tcg_temp_free_i64(tcg_ctx, xbh);                                  \
        tcg_temp_free_i64(tcg_ctx, xbl);                                  \
        tcg_temp_free_i64(tcg_ctx, sgm);                                  \
    }

VSX_VECTOR_MOVE(xvabsdp, OP_ABS, SGN_MASK_DP)
VSX_VECTOR_MOVE(xvnabsdp, OP_NABS, SGN_MASK_DP)
VSX_VECTOR_MOVE(xvnegdp, OP_NEG, SGN_MASK_DP)
VSX_VECTOR_MOVE(xvcpsgndp, OP_CPSGN, SGN_MASK_DP)
VSX_VECTOR_MOVE(xvabssp, OP_ABS, SGN_MASK_SP)
VSX_VECTOR_MOVE(xvnabssp, OP_NABS, SGN_MASK_SP)
VSX_VECTOR_MOVE(xvnegsp, OP_NEG, SGN_MASK_SP)
VSX_VECTOR_MOVE(xvcpsgnsp, OP_CPSGN, SGN_MASK_SP)

#define VSX_CMP(name, op1, op2, inval, type)                                  \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_i32 ignored;                                                         \
    TCGv_ptr xt, xa, xb;                                                      \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    xt = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));                                        \
    xa = gen_vsr_ptr(tcg_ctx, xA(ctx->opcode));                                        \
    xb = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));                                        \
    if ((ctx->opcode >> (31 - 21)) & 1) {                                     \
        gen_helper_##name(tcg_ctx, cpu_crf[6], tcg_ctx->cpu_env, xt, xa, xb);                   \
    } else {                                                                  \
        ignored = tcg_temp_new_i32(tcg_ctx);                                         \
        gen_helper_##name(tcg_ctx, ignored, tcg_ctx->cpu_env, xt, xa, xb);                      \
        tcg_temp_free_i32(tcg_ctx, ignored);                                           \
    }                                                                         \
    gen_helper_float_check_status(tcg_ctx, tcg_ctx->cpu_env);                                   \
    tcg_temp_free_ptr(tcg_ctx, xt);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xa);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xb);                                                    \
}

VSX_CMP(xvcmpeqdp, 0x0C, 0x0C, 0, PPC2_VSX)
VSX_CMP(xvcmpgedp, 0x0C, 0x0E, 0, PPC2_VSX)
VSX_CMP(xvcmpgtdp, 0x0C, 0x0D, 0, PPC2_VSX)
VSX_CMP(xvcmpnedp, 0x0C, 0x0F, 0, PPC2_ISA300)
VSX_CMP(xvcmpeqsp, 0x0C, 0x08, 0, PPC2_VSX)
VSX_CMP(xvcmpgesp, 0x0C, 0x0A, 0, PPC2_VSX)
VSX_CMP(xvcmpgtsp, 0x0C, 0x09, 0, PPC2_VSX)
VSX_CMP(xvcmpnesp, 0x0C, 0x0B, 0, PPC2_VSX)

static void gen_xscvqpdp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 opc;
    TCGv_ptr xt, xb;
    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    opc = tcg_const_i32(tcg_ctx, ctx->opcode);
    xt = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));
    xb = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));
    gen_helper_xscvqpdp(tcg_ctx, tcg_ctx->cpu_env, opc, xt, xb);
    tcg_temp_free_i32(tcg_ctx, opc);
    tcg_temp_free_ptr(tcg_ctx, xt);
    tcg_temp_free_ptr(tcg_ctx, xb);
}

#define GEN_VSX_HELPER_2(name, op1, op2, inval, type)                         \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_i32 opc;                                                             \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    opc = tcg_const_i32(tcg_ctx, ctx->opcode);                                         \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, opc);                                          \
    tcg_temp_free_i32(tcg_ctx, opc);                                                   \
}

#define GEN_VSX_HELPER_X3(name, op1, op2, inval, type)                        \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_ptr xt, xa, xb;                                                      \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    xt = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));                                        \
    xa = gen_vsr_ptr(tcg_ctx, xA(ctx->opcode));                                        \
    xb = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));                                        \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, xt, xa, xb);                                   \
    tcg_temp_free_ptr(tcg_ctx, xt);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xa);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xb);                                                    \
}

#define GEN_VSX_HELPER_X2(name, op1, op2, inval, type)                        \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_ptr xt, xb;                                                          \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    xt = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));                                        \
    xb = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));                                        \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, xt, xb);                                       \
    tcg_temp_free_ptr(tcg_ctx, xt);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xb);                                                    \
}

#define GEN_VSX_HELPER_X2_AB(name, op1, op2, inval, type)                     \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_i32 opc;                                                             \
    TCGv_ptr xa, xb;                                                          \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    opc = tcg_const_i32(tcg_ctx, ctx->opcode);                                         \
    xa = gen_vsr_ptr(tcg_ctx, xA(ctx->opcode));                                        \
    xb = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));                                        \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, opc, xa, xb);                                  \
    tcg_temp_free_i32(tcg_ctx, opc);                                                   \
    tcg_temp_free_ptr(tcg_ctx, xa);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xb);                                                    \
}

#define GEN_VSX_HELPER_X1(name, op1, op2, inval, type)                        \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_i32 opc;                                                             \
    TCGv_ptr xb;                                                              \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    opc = tcg_const_i32(tcg_ctx, ctx->opcode);                                         \
    xb = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));                                        \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, opc, xb);                                      \
    tcg_temp_free_i32(tcg_ctx, opc);                                                   \
    tcg_temp_free_ptr(tcg_ctx, xb);                                                    \
}

#define GEN_VSX_HELPER_R3(name, op1, op2, inval, type)                        \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_i32 opc;                                                             \
    TCGv_ptr xt, xa, xb;                                                      \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    opc = tcg_const_i32(tcg_ctx, ctx->opcode);                                         \
    xt = gen_vsr_ptr(tcg_ctx, rD(ctx->opcode) + 32);                                   \
    xa = gen_vsr_ptr(tcg_ctx, rA(ctx->opcode) + 32);                                   \
    xb = gen_vsr_ptr(tcg_ctx, rB(ctx->opcode) + 32);                                   \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, opc, xt, xa, xb);                              \
    tcg_temp_free_i32(tcg_ctx, opc);                                                   \
    tcg_temp_free_ptr(tcg_ctx, xt);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xa);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xb);                                                    \
}

#define GEN_VSX_HELPER_R2(name, op1, op2, inval, type)                        \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_i32 opc;                                                             \
    TCGv_ptr xt, xb;                                                          \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    opc = tcg_const_i32(tcg_ctx, ctx->opcode);                                         \
    xt = gen_vsr_ptr(tcg_ctx, rD(ctx->opcode) + 32);                                   \
    xb = gen_vsr_ptr(tcg_ctx, rB(ctx->opcode) + 32);                                   \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, opc, xt, xb);                                  \
    tcg_temp_free_i32(tcg_ctx, opc);                                                   \
    tcg_temp_free_ptr(tcg_ctx, xt);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xb);                                                    \
}

#define GEN_VSX_HELPER_R2_AB(name, op1, op2, inval, type)                     \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_i32 opc;                                                             \
    TCGv_ptr xa, xb;                                                          \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    opc = tcg_const_i32(tcg_ctx, ctx->opcode);                                         \
    xa = gen_vsr_ptr(tcg_ctx, rA(ctx->opcode) + 32);                                   \
    xb = gen_vsr_ptr(tcg_ctx, rB(ctx->opcode) + 32);                                   \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, opc, xa, xb);                                  \
    tcg_temp_free_i32(tcg_ctx, opc);                                                   \
    tcg_temp_free_ptr(tcg_ctx, xa);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xb);                                                    \
}

#define GEN_VSX_HELPER_XT_XB_ENV(name, op1, op2, inval, type) \
static void gen_##name(DisasContext *ctx)                     \
{                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_i64 t0;                                              \
    TCGv_i64 t1;                                              \
    if (unlikely(!ctx->vsx_enabled)) {                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                \
        return;                                               \
    }                                                         \
    t0 = tcg_temp_new_i64(tcg_ctx);                                  \
    t1 = tcg_temp_new_i64(tcg_ctx);                                  \
    get_cpu_vsrh(tcg_ctx, t0, xB(ctx->opcode));                        \
    gen_helper_##name(tcg_ctx, t1, tcg_ctx->cpu_env, t0);                       \
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), t1);                        \
    tcg_temp_free_i64(tcg_ctx, t0);                                    \
    tcg_temp_free_i64(tcg_ctx, t1);                                    \
}

GEN_VSX_HELPER_X3(xsadddp, 0x00, 0x04, 0, PPC2_VSX)
GEN_VSX_HELPER_R3(xsaddqp, 0x04, 0x00, 0, PPC2_ISA300)
GEN_VSX_HELPER_X3(xssubdp, 0x00, 0x05, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xsmuldp, 0x00, 0x06, 0, PPC2_VSX)
GEN_VSX_HELPER_R3(xsmulqp, 0x04, 0x01, 0, PPC2_ISA300)
GEN_VSX_HELPER_X3(xsdivdp, 0x00, 0x07, 0, PPC2_VSX)
GEN_VSX_HELPER_R3(xsdivqp, 0x04, 0x11, 0, PPC2_ISA300)
GEN_VSX_HELPER_X2(xsredp, 0x14, 0x05, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xssqrtdp, 0x16, 0x04, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xsrsqrtedp, 0x14, 0x04, 0, PPC2_VSX)
GEN_VSX_HELPER_X2_AB(xstdivdp, 0x14, 0x07, 0, PPC2_VSX)
GEN_VSX_HELPER_X1(xstsqrtdp, 0x14, 0x06, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xscmpeqdp, 0x0C, 0x00, 0, PPC2_ISA300)
GEN_VSX_HELPER_X3(xscmpgtdp, 0x0C, 0x01, 0, PPC2_ISA300)
GEN_VSX_HELPER_X3(xscmpgedp, 0x0C, 0x02, 0, PPC2_ISA300)
GEN_VSX_HELPER_X3(xscmpnedp, 0x0C, 0x03, 0, PPC2_ISA300)
GEN_VSX_HELPER_X2_AB(xscmpexpdp, 0x0C, 0x07, 0, PPC2_ISA300)
GEN_VSX_HELPER_R2_AB(xscmpexpqp, 0x04, 0x05, 0, PPC2_ISA300)
GEN_VSX_HELPER_X2_AB(xscmpodp, 0x0C, 0x05, 0, PPC2_VSX)
GEN_VSX_HELPER_X2_AB(xscmpudp, 0x0C, 0x04, 0, PPC2_VSX)
GEN_VSX_HELPER_R2_AB(xscmpoqp, 0x04, 0x04, 0, PPC2_VSX)
GEN_VSX_HELPER_R2_AB(xscmpuqp, 0x04, 0x14, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xsmaxdp, 0x00, 0x14, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xsmindp, 0x00, 0x15, 0, PPC2_VSX)
GEN_VSX_HELPER_R3(xsmaxcdp, 0x00, 0x10, 0, PPC2_ISA300)
GEN_VSX_HELPER_R3(xsmincdp, 0x00, 0x11, 0, PPC2_ISA300)
GEN_VSX_HELPER_R3(xsmaxjdp, 0x00, 0x12, 0, PPC2_ISA300)
GEN_VSX_HELPER_R3(xsminjdp, 0x00, 0x12, 0, PPC2_ISA300)
GEN_VSX_HELPER_X2(xscvdphp, 0x16, 0x15, 0x11, PPC2_ISA300)
GEN_VSX_HELPER_X2(xscvdpsp, 0x12, 0x10, 0, PPC2_VSX)
GEN_VSX_HELPER_R2(xscvdpqp, 0x04, 0x1A, 0x16, PPC2_ISA300)
GEN_VSX_HELPER_XT_XB_ENV(xscvdpspn, 0x16, 0x10, 0, PPC2_VSX207)
GEN_VSX_HELPER_R2(xscvqpsdz, 0x04, 0x1A, 0x19, PPC2_ISA300)
GEN_VSX_HELPER_R2(xscvqpswz, 0x04, 0x1A, 0x09, PPC2_ISA300)
GEN_VSX_HELPER_R2(xscvqpudz, 0x04, 0x1A, 0x11, PPC2_ISA300)
GEN_VSX_HELPER_R2(xscvqpuwz, 0x04, 0x1A, 0x01, PPC2_ISA300)
GEN_VSX_HELPER_X2(xscvhpdp, 0x16, 0x15, 0x10, PPC2_ISA300)
GEN_VSX_HELPER_R2(xscvsdqp, 0x04, 0x1A, 0x0A, PPC2_ISA300)
GEN_VSX_HELPER_X2(xscvspdp, 0x12, 0x14, 0, PPC2_VSX)
GEN_VSX_HELPER_XT_XB_ENV(xscvspdpn, 0x16, 0x14, 0, PPC2_VSX207)
GEN_VSX_HELPER_X2(xscvdpsxds, 0x10, 0x15, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xscvdpsxws, 0x10, 0x05, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xscvdpuxds, 0x10, 0x14, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xscvdpuxws, 0x10, 0x04, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xscvsxddp, 0x10, 0x17, 0, PPC2_VSX)
GEN_VSX_HELPER_R2(xscvudqp, 0x04, 0x1A, 0x02, PPC2_ISA300)
GEN_VSX_HELPER_X2(xscvuxddp, 0x10, 0x16, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xsrdpi, 0x12, 0x04, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xsrdpic, 0x16, 0x06, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xsrdpim, 0x12, 0x07, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xsrdpip, 0x12, 0x06, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xsrdpiz, 0x12, 0x05, 0, PPC2_VSX)
GEN_VSX_HELPER_XT_XB_ENV(xsrsp, 0x12, 0x11, 0, PPC2_VSX207)
GEN_VSX_HELPER_R2(xsrqpi, 0x05, 0x00, 0, PPC2_ISA300)
GEN_VSX_HELPER_R2(xsrqpxp, 0x05, 0x01, 0, PPC2_ISA300)
GEN_VSX_HELPER_R2(xssqrtqp, 0x04, 0x19, 0x1B, PPC2_ISA300)
GEN_VSX_HELPER_R3(xssubqp, 0x04, 0x10, 0, PPC2_ISA300)
GEN_VSX_HELPER_X3(xsaddsp, 0x00, 0x00, 0, PPC2_VSX207)
GEN_VSX_HELPER_X3(xssubsp, 0x00, 0x01, 0, PPC2_VSX207)
GEN_VSX_HELPER_X3(xsmulsp, 0x00, 0x02, 0, PPC2_VSX207)
GEN_VSX_HELPER_X3(xsdivsp, 0x00, 0x03, 0, PPC2_VSX207)
GEN_VSX_HELPER_X2(xsresp, 0x14, 0x01, 0, PPC2_VSX207)
GEN_VSX_HELPER_X2(xssqrtsp, 0x16, 0x00, 0, PPC2_VSX207)
GEN_VSX_HELPER_X2(xsrsqrtesp, 0x14, 0x00, 0, PPC2_VSX207)
GEN_VSX_HELPER_X2(xscvsxdsp, 0x10, 0x13, 0, PPC2_VSX207)
GEN_VSX_HELPER_X2(xscvuxdsp, 0x10, 0x12, 0, PPC2_VSX207)
GEN_VSX_HELPER_X1(xststdcsp, 0x14, 0x12, 0, PPC2_ISA300)
GEN_VSX_HELPER_2(xststdcdp, 0x14, 0x16, 0, PPC2_ISA300)
GEN_VSX_HELPER_2(xststdcqp, 0x04, 0x16, 0, PPC2_ISA300)

GEN_VSX_HELPER_X3(xvadddp, 0x00, 0x0C, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvsubdp, 0x00, 0x0D, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvmuldp, 0x00, 0x0E, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvdivdp, 0x00, 0x0F, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvredp, 0x14, 0x0D, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvsqrtdp, 0x16, 0x0C, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrsqrtedp, 0x14, 0x0C, 0, PPC2_VSX)
GEN_VSX_HELPER_X2_AB(xvtdivdp, 0x14, 0x0F, 0, PPC2_VSX)
GEN_VSX_HELPER_X1(xvtsqrtdp, 0x14, 0x0E, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvmaxdp, 0x00, 0x1C, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvmindp, 0x00, 0x1D, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvdpsp, 0x12, 0x18, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvdpsxds, 0x10, 0x1D, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvdpsxws, 0x10, 0x0D, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvdpuxds, 0x10, 0x1C, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvdpuxws, 0x10, 0x0C, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvsxddp, 0x10, 0x1F, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvuxddp, 0x10, 0x1E, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvsxwdp, 0x10, 0x0F, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvuxwdp, 0x10, 0x0E, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrdpi, 0x12, 0x0C, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrdpic, 0x16, 0x0E, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrdpim, 0x12, 0x0F, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrdpip, 0x12, 0x0E, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrdpiz, 0x12, 0x0D, 0, PPC2_VSX)

GEN_VSX_HELPER_X3(xvaddsp, 0x00, 0x08, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvsubsp, 0x00, 0x09, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvmulsp, 0x00, 0x0A, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvdivsp, 0x00, 0x0B, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvresp, 0x14, 0x09, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvsqrtsp, 0x16, 0x08, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrsqrtesp, 0x14, 0x08, 0, PPC2_VSX)
GEN_VSX_HELPER_X2_AB(xvtdivsp, 0x14, 0x0B, 0, PPC2_VSX)
GEN_VSX_HELPER_X1(xvtsqrtsp, 0x14, 0x0A, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvmaxsp, 0x00, 0x18, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xvminsp, 0x00, 0x19, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvspdp, 0x12, 0x1C, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvhpsp, 0x16, 0x1D, 0x18, PPC2_ISA300)
GEN_VSX_HELPER_X2(xvcvsphp, 0x16, 0x1D, 0x19, PPC2_ISA300)
GEN_VSX_HELPER_X2(xvcvspsxds, 0x10, 0x19, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvspsxws, 0x10, 0x09, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvspuxds, 0x10, 0x18, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvspuxws, 0x10, 0x08, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvsxdsp, 0x10, 0x1B, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvuxdsp, 0x10, 0x1A, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvsxwsp, 0x10, 0x0B, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvcvuxwsp, 0x10, 0x0A, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrspi, 0x12, 0x08, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrspic, 0x16, 0x0A, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrspim, 0x12, 0x0B, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrspip, 0x12, 0x0A, 0, PPC2_VSX)
GEN_VSX_HELPER_X2(xvrspiz, 0x12, 0x09, 0, PPC2_VSX)
GEN_VSX_HELPER_2(xvtstdcsp, 0x14, 0x1A, 0, PPC2_VSX)
GEN_VSX_HELPER_2(xvtstdcdp, 0x14, 0x1E, 0, PPC2_VSX)
GEN_VSX_HELPER_X3(xxperm, 0x08, 0x03, 0, PPC2_ISA300)
GEN_VSX_HELPER_X3(xxpermr, 0x08, 0x07, 0, PPC2_ISA300)

#define GEN_VSX_HELPER_VSX_MADD(name, op1, aop, mop, inval, type)             \
static void gen_##name(DisasContext *ctx)                                     \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_ptr xt, xa, b, c;                                                    \
    if (unlikely(!ctx->vsx_enabled)) {                                        \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                                \
        return;                                                               \
    }                                                                         \
    xt = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));                                        \
    xa = gen_vsr_ptr(tcg_ctx, xA(ctx->opcode));                                        \
    if (ctx->opcode & PPC_BIT32(25)) {                                        \
        /*                                                                    \
         * AxT + B                                                            \
         */                                                                   \
        b = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));                                     \
        c = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));                                     \
    } else {                                                                  \
        /*                                                                    \
         * AxB + T                                                            \
         */                                                                   \
        b = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));                                     \
        c = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));                                     \
    }                                                                         \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, xt, xa, b, c);                                 \
    tcg_temp_free_ptr(tcg_ctx, xt);                                                    \
    tcg_temp_free_ptr(tcg_ctx, xa);                                                    \
    tcg_temp_free_ptr(tcg_ctx, b);                                                     \
    tcg_temp_free_ptr(tcg_ctx, c);                                                     \
}

GEN_VSX_HELPER_VSX_MADD(xsmadddp, 0x04, 0x04, 0x05, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xsmsubdp, 0x04, 0x06, 0x07, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xsnmadddp, 0x04, 0x14, 0x15, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xsnmsubdp, 0x04, 0x16, 0x17, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xsmaddsp, 0x04, 0x00, 0x01, 0, PPC2_VSX207)
GEN_VSX_HELPER_VSX_MADD(xsmsubsp, 0x04, 0x02, 0x03, 0, PPC2_VSX207)
GEN_VSX_HELPER_VSX_MADD(xsnmaddsp, 0x04, 0x10, 0x11, 0, PPC2_VSX207)
GEN_VSX_HELPER_VSX_MADD(xsnmsubsp, 0x04, 0x12, 0x13, 0, PPC2_VSX207)
GEN_VSX_HELPER_VSX_MADD(xvmadddp, 0x04, 0x0C, 0x0D, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xvmsubdp, 0x04, 0x0E, 0x0F, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xvnmadddp, 0x04, 0x1C, 0x1D, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xvnmsubdp, 0x04, 0x1E, 0x1F, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xvmaddsp, 0x04, 0x08, 0x09, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xvmsubsp, 0x04, 0x0A, 0x0B, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xvnmaddsp, 0x04, 0x18, 0x19, 0, PPC2_VSX)
GEN_VSX_HELPER_VSX_MADD(xvnmsubsp, 0x04, 0x1A, 0x1B, 0, PPC2_VSX)

static void gen_xxbrd(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;
    TCGv_i64 xbl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));

    tcg_gen_bswap64_i64(tcg_ctx, xth, xbh);
    tcg_gen_bswap64_i64(tcg_ctx, xtl, xbl);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

static void gen_xxbrh(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;
    TCGv_i64 xbl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));

    gen_bswap16x8(tcg_ctx, xth, xtl, xbh, xbl);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

static void gen_xxbrq(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;
    TCGv_i64 xbl;
    TCGv_i64 t0;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));
    t0 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_bswap64_i64(tcg_ctx, t0, xbl);
    tcg_gen_bswap64_i64(tcg_ctx, xtl, xbh);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);
    tcg_gen_mov_i64(tcg_ctx, xth, t0);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

static void gen_xxbrw(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;
    TCGv_i64 xbl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));

    gen_bswap32x4(tcg_ctx, xth, xtl, xbh, xbl);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

#define VSX_LOGICAL(name, vece, tcg_op)                              \
static void glue(gen_, name)(DisasContext *ctx)                      \
    {                                                                \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
        if (unlikely(!ctx->vsx_enabled)) {                           \
            gen_exception(ctx, POWERPC_EXCP_VSXU);                   \
            return;                                                  \
        }                                                            \
        tcg_op(tcg_ctx, vece, vsr_full_offset(xT(ctx->opcode)),               \
               vsr_full_offset(xA(ctx->opcode)),                     \
               vsr_full_offset(xB(ctx->opcode)), 16, 16);            \
    }

VSX_LOGICAL(xxland, MO_64, tcg_gen_gvec_and)
VSX_LOGICAL(xxlandc, MO_64, tcg_gen_gvec_andc)
VSX_LOGICAL(xxlor, MO_64, tcg_gen_gvec_or)
VSX_LOGICAL(xxlxor, MO_64, tcg_gen_gvec_xor)
VSX_LOGICAL(xxlnor, MO_64, tcg_gen_gvec_nor)
VSX_LOGICAL(xxleqv, MO_64, tcg_gen_gvec_eqv)
VSX_LOGICAL(xxlnand, MO_64, tcg_gen_gvec_nand)
VSX_LOGICAL(xxlorc, MO_64, tcg_gen_gvec_orc)

#define VSX_XXMRG(name, high)                               \
static void glue(gen_, name)(DisasContext *ctx)             \
    {                                                       \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
        TCGv_i64 a0, a1, b0, b1, tmp;                       \
        if (unlikely(!ctx->vsx_enabled)) {                  \
            gen_exception(ctx, POWERPC_EXCP_VSXU);          \
            return;                                         \
        }                                                   \
        a0 = tcg_temp_new_i64(tcg_ctx);                            \
        a1 = tcg_temp_new_i64(tcg_ctx);                            \
        b0 = tcg_temp_new_i64(tcg_ctx);                            \
        b1 = tcg_temp_new_i64(tcg_ctx);                            \
        tmp = tcg_temp_new_i64(tcg_ctx);                           \
        if (high) {                                         \
            get_cpu_vsrh(tcg_ctx, a0, xA(ctx->opcode));              \
            get_cpu_vsrh(tcg_ctx, a1, xA(ctx->opcode));              \
            get_cpu_vsrh(tcg_ctx, b0, xB(ctx->opcode));              \
            get_cpu_vsrh(tcg_ctx, b1, xB(ctx->opcode));              \
        } else {                                            \
            get_cpu_vsrl(tcg_ctx, a0, xA(ctx->opcode));              \
            get_cpu_vsrl(tcg_ctx, a1, xA(ctx->opcode));              \
            get_cpu_vsrl(tcg_ctx, b0, xB(ctx->opcode));              \
            get_cpu_vsrl(tcg_ctx, b1, xB(ctx->opcode));              \
        }                                                   \
        tcg_gen_shri_i64(tcg_ctx, a0, a0, 32);                       \
        tcg_gen_shri_i64(tcg_ctx, b0, b0, 32);                       \
        tcg_gen_deposit_i64(tcg_ctx, tmp, b0, a0, 32, 32);           \
        set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), tmp);                 \
        tcg_gen_deposit_i64(tcg_ctx, tmp, b1, a1, 32, 32);           \
        set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), tmp);                 \
        tcg_temp_free_i64(tcg_ctx, a0);                              \
        tcg_temp_free_i64(tcg_ctx, a1);                              \
        tcg_temp_free_i64(tcg_ctx, b0);                              \
        tcg_temp_free_i64(tcg_ctx, b1);                              \
        tcg_temp_free_i64(tcg_ctx, tmp);                             \
    }

VSX_XXMRG(xxmrghw, 1)
VSX_XXMRG(xxmrglw, 0)

static void gen_xxsel(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int rt = xT(ctx->opcode);
    int ra = xA(ctx->opcode);
    int rb = xB(ctx->opcode);
    int rc = xC(ctx->opcode);

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    tcg_gen_gvec_bitsel(tcg_ctx, MO_64, vsr_full_offset(rt), vsr_full_offset(rc),
                        vsr_full_offset(rb), vsr_full_offset(ra), 16, 16);
}

static void gen_xxspltw(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int rt = xT(ctx->opcode);
    int rb = xB(ctx->opcode);
    int uim = UIM(ctx->opcode);
    int tofs, bofs;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }

    tofs = vsr_full_offset(rt);
    bofs = vsr_full_offset(rb);
    bofs += uim << MO_32;
#ifndef HOST_WORDS_BIG_ENDIAN
    bofs ^= 8 | 4;
#endif

    tcg_gen_gvec_dup_mem(tcg_ctx, MO_32, tofs, bofs, 16, 16);
}

#define pattern(x) (((x) & 0xff) * (~(uint64_t)0 / 0xff))

static void gen_xxspltib(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    uint8_t uim8 = IMM8(ctx->opcode);
    int rt = xT(ctx->opcode);

    if (rt < 32) {
        if (unlikely(!ctx->vsx_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VSXU);
            return;
        }
    } else {
        if (unlikely(!ctx->altivec_enabled)) {
            gen_exception(ctx, POWERPC_EXCP_VPU);
            return;
        }
    }
    tcg_gen_gvec_dup8i(tcg_ctx, vsr_full_offset(rt), 16, 16, uim8);
}

static void gen_xxsldwi(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth, xtl;
    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);

    switch (SHW(ctx->opcode)) {
        case 0: {
            get_cpu_vsrh(tcg_ctx, xth, xA(ctx->opcode));
            get_cpu_vsrl(tcg_ctx, xtl, xA(ctx->opcode));
            break;
        }
        case 1: {
            TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
            get_cpu_vsrh(tcg_ctx, xth, xA(ctx->opcode));
            tcg_gen_shli_i64(tcg_ctx, xth, xth, 32);
            get_cpu_vsrl(tcg_ctx, t0, xA(ctx->opcode));
            tcg_gen_shri_i64(tcg_ctx, t0, t0, 32);
            tcg_gen_or_i64(tcg_ctx, xth, xth, t0);
            get_cpu_vsrl(tcg_ctx, xtl, xA(ctx->opcode));
            tcg_gen_shli_i64(tcg_ctx, xtl, xtl, 32);
            get_cpu_vsrh(tcg_ctx, t0, xB(ctx->opcode));
            tcg_gen_shri_i64(tcg_ctx, t0, t0, 32);
            tcg_gen_or_i64(tcg_ctx, xtl, xtl, t0);
            tcg_temp_free_i64(tcg_ctx, t0);
            break;
        }
        case 2: {
            get_cpu_vsrl(tcg_ctx, xth, xA(ctx->opcode));
            get_cpu_vsrh(tcg_ctx, xtl, xB(ctx->opcode));
            break;
        }
        case 3: {
            TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
            get_cpu_vsrl(tcg_ctx, xth, xA(ctx->opcode));
            tcg_gen_shli_i64(tcg_ctx, xth, xth, 32);
            get_cpu_vsrh(tcg_ctx, t0, xB(ctx->opcode));
            tcg_gen_shri_i64(tcg_ctx, t0, t0, 32);
            tcg_gen_or_i64(tcg_ctx, xth, xth, t0);
            get_cpu_vsrh(tcg_ctx, xtl, xB(ctx->opcode));
            tcg_gen_shli_i64(tcg_ctx, xtl, xtl, 32);
            get_cpu_vsrl(tcg_ctx, t0, xB(ctx->opcode));
            tcg_gen_shri_i64(tcg_ctx, t0, t0, 32);
            tcg_gen_or_i64(tcg_ctx, xtl, xtl, t0);
            tcg_temp_free_i64(tcg_ctx, t0);
            break;
        }
    }

    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
}

#define VSX_EXTRACT_INSERT(name)                                \
static void gen_##name(DisasContext *ctx)                       \
{                                                               \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                   \
    TCGv_ptr xt, xb;                                            \
    TCGv_i32 t0;                                                \
    TCGv_i64 t1;                                                \
    uint8_t uimm = UIMM4(ctx->opcode);                          \
                                                                \
    if (unlikely(!ctx->vsx_enabled)) {                          \
        gen_exception(ctx, POWERPC_EXCP_VSXU);                  \
        return;                                                 \
    }                                                           \
    xt = gen_vsr_ptr(tcg_ctx, xT(ctx->opcode));                          \
    xb = gen_vsr_ptr(tcg_ctx, xB(ctx->opcode));                          \
    t0 = tcg_temp_new_i32(tcg_ctx);                                    \
    t1 = tcg_temp_new_i64(tcg_ctx);                                    \
    /*                                                          \
     * uimm > 15 out of bound and for                           \
     * uimm > 12 handle as per hardware in helper               \
     */                                                         \
    if (uimm > 15) {                                            \
        tcg_gen_movi_i64(tcg_ctx, t1, 0);                                \
        set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), t1);                      \
        set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), t1);                      \
        return;                                                 \
    }                                                           \
    tcg_gen_movi_i32(tcg_ctx, t0, uimm);                                 \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, xt, xb, t0);                     \
    tcg_temp_free_ptr(tcg_ctx, xb);                                      \
    tcg_temp_free_ptr(tcg_ctx, xt);                                      \
    tcg_temp_free_i32(tcg_ctx, t0);                                      \
    tcg_temp_free_i64(tcg_ctx, t1);                                      \
}

VSX_EXTRACT_INSERT(xxextractuw)
VSX_EXTRACT_INSERT(xxinsertw)

#ifdef TARGET_PPC64
static void gen_xsxexpdp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv rt = cpu_gpr[rD(ctx->opcode)];
    TCGv_i64 t0;
    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    t0 = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, t0, xB(ctx->opcode));
    tcg_gen_extract_i64(tcg_ctx, rt, t0, 52, 11);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static void gen_xsxexpqp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, rB(ctx->opcode) + 32);

    tcg_gen_extract_i64(tcg_ctx, xth, xbh, 48, 15);
    set_cpu_vsrh(tcg_ctx, rD(ctx->opcode) + 32, xth);
    tcg_gen_movi_i64(tcg_ctx, xtl, 0);
    set_cpu_vsrl(tcg_ctx, rD(ctx->opcode) + 32, xtl);

    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
}

static void gen_xsiexpdp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv ra = cpu_gpr[rA(ctx->opcode)];
    TCGv rb = cpu_gpr[rB(ctx->opcode)];
    TCGv_i64 t0;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    t0 = tcg_temp_new_i64(tcg_ctx);
    xth = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_andi_i64(tcg_ctx, xth, ra, 0x800FFFFFFFFFFFFF);
    tcg_gen_andi_i64(tcg_ctx, t0, rb, 0x7FF);
    tcg_gen_shli_i64(tcg_ctx, t0, t0, 52);
    tcg_gen_or_i64(tcg_ctx, xth, xth, t0);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    /* dword[1] is undefined */
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, xth);
}

static void gen_xsiexpqp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xah;
    TCGv_i64 xal;
    TCGv_i64 xbh;
    TCGv_i64 t0;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xah = tcg_temp_new_i64(tcg_ctx);
    xal = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xah, rA(ctx->opcode) + 32);
    get_cpu_vsrl(tcg_ctx, xal, rA(ctx->opcode) + 32);
    xbh = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, rB(ctx->opcode) + 32);
    t0 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, xth, xah, 0x8000FFFFFFFFFFFF);
    tcg_gen_andi_i64(tcg_ctx, t0, xbh, 0x7FFF);
    tcg_gen_shli_i64(tcg_ctx, t0, t0, 48);
    tcg_gen_or_i64(tcg_ctx, xth, xth, t0);
    set_cpu_vsrh(tcg_ctx, rD(ctx->opcode) + 32, xth);
    tcg_gen_mov_i64(tcg_ctx, xtl, xal);
    set_cpu_vsrl(tcg_ctx, rD(ctx->opcode) + 32, xtl);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xah);
    tcg_temp_free_i64(tcg_ctx, xal);
    tcg_temp_free_i64(tcg_ctx, xbh);
}

static void gen_xsxsigdp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv rt = cpu_gpr[rD(ctx->opcode)];
    TCGv_i64 t0, t1, zr, nan, exp;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    exp = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);
    zr = tcg_const_i64(tcg_ctx, 0);
    nan = tcg_const_i64(tcg_ctx, 2047);

    get_cpu_vsrh(tcg_ctx, t1, xB(ctx->opcode));
    tcg_gen_extract_i64(tcg_ctx, exp, t1, 52, 11);
    tcg_gen_movi_i64(tcg_ctx, t0, 0x0010000000000000);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, exp, zr, zr, t0);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, exp, nan, zr, t0);
    get_cpu_vsrh(tcg_ctx, t1, xB(ctx->opcode));
    tcg_gen_deposit_i64(tcg_ctx, rt, t0, t1, 0, 52);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, exp);
    tcg_temp_free_i64(tcg_ctx, zr);
    tcg_temp_free_i64(tcg_ctx, nan);
}

static void gen_xsxsigqp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0, zr, nan, exp;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;
    TCGv_i64 xbl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, rB(ctx->opcode) + 32);
    get_cpu_vsrl(tcg_ctx, xbl, rB(ctx->opcode) + 32);
    exp = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    zr = tcg_const_i64(tcg_ctx, 0);
    nan = tcg_const_i64(tcg_ctx, 32767);

    tcg_gen_extract_i64(tcg_ctx, exp, xbh, 48, 15);
    tcg_gen_movi_i64(tcg_ctx, t0, 0x0001000000000000);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, exp, zr, zr, t0);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, exp, nan, zr, t0);
    tcg_gen_deposit_i64(tcg_ctx, xth, t0, xbh, 0, 48);
    set_cpu_vsrh(tcg_ctx, rD(ctx->opcode) + 32, xth);
    tcg_gen_mov_i64(tcg_ctx, xtl, xbl);
    set_cpu_vsrl(tcg_ctx, rD(ctx->opcode) + 32, xtl);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, exp);
    tcg_temp_free_i64(tcg_ctx, zr);
    tcg_temp_free_i64(tcg_ctx, nan);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}
#endif

static void gen_xviexpsp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xah;
    TCGv_i64 xal;
    TCGv_i64 xbh;
    TCGv_i64 xbl;
    TCGv_i64 t0;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xah = tcg_temp_new_i64(tcg_ctx);
    xal = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xah, xA(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xal, xA(ctx->opcode));
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));
    t0 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, xth, xah, 0x807FFFFF807FFFFF);
    tcg_gen_andi_i64(tcg_ctx, t0, xbh, 0xFF000000FF);
    tcg_gen_shli_i64(tcg_ctx, t0, t0, 23);
    tcg_gen_or_i64(tcg_ctx, xth, xth, t0);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    tcg_gen_andi_i64(tcg_ctx, xtl, xal, 0x807FFFFF807FFFFF);
    tcg_gen_andi_i64(tcg_ctx, t0, xbl, 0xFF000000FF);
    tcg_gen_shli_i64(tcg_ctx, t0, t0, 23);
    tcg_gen_or_i64(tcg_ctx, xtl, xtl, t0);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xah);
    tcg_temp_free_i64(tcg_ctx, xal);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

static void gen_xviexpdp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xah;
    TCGv_i64 xal;
    TCGv_i64 xbh;
    TCGv_i64 xbl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xah = tcg_temp_new_i64(tcg_ctx);
    xal = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xah, xA(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xal, xA(ctx->opcode));
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));

    tcg_gen_deposit_i64(tcg_ctx, xth, xah, xbh, 52, 11);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);

    tcg_gen_deposit_i64(tcg_ctx, xtl, xal, xbl, 52, 11);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xah);
    tcg_temp_free_i64(tcg_ctx, xal);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

static void gen_xvxexpsp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;
    TCGv_i64 xbl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));

    tcg_gen_shri_i64(tcg_ctx, xth, xbh, 23);
    tcg_gen_andi_i64(tcg_ctx, xth, xth, 0xFF000000FF);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    tcg_gen_shri_i64(tcg_ctx, xtl, xbl, 23);
    tcg_gen_andi_i64(tcg_ctx, xtl, xtl, 0xFF000000FF);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

static void gen_xvxexpdp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;
    TCGv_i64 xbl;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));

    tcg_gen_extract_i64(tcg_ctx, xth, xbh, 52, 11);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);
    tcg_gen_extract_i64(tcg_ctx, xtl, xbl, 52, 11);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

GEN_VSX_HELPER_X2(xvxsigsp, 0x00, 0x04, 0, PPC2_ISA300)

static void gen_xvxsigdp(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 xth;
    TCGv_i64 xtl;
    TCGv_i64 xbh;
    TCGv_i64 xbl;
    TCGv_i64 t0, zr, nan, exp;

    if (unlikely(!ctx->vsx_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VSXU);
        return;
    }
    xth = tcg_temp_new_i64(tcg_ctx);
    xtl = tcg_temp_new_i64(tcg_ctx);
    xbh = tcg_temp_new_i64(tcg_ctx);
    xbl = tcg_temp_new_i64(tcg_ctx);
    get_cpu_vsrh(tcg_ctx, xbh, xB(ctx->opcode));
    get_cpu_vsrl(tcg_ctx, xbl, xB(ctx->opcode));
    exp = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    zr = tcg_const_i64(tcg_ctx, 0);
    nan = tcg_const_i64(tcg_ctx, 2047);

    tcg_gen_extract_i64(tcg_ctx, exp, xbh, 52, 11);
    tcg_gen_movi_i64(tcg_ctx, t0, 0x0010000000000000);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, exp, zr, zr, t0);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, exp, nan, zr, t0);
    tcg_gen_deposit_i64(tcg_ctx, xth, t0, xbh, 0, 52);
    set_cpu_vsrh(tcg_ctx, xT(ctx->opcode), xth);

    tcg_gen_extract_i64(tcg_ctx, exp, xbl, 52, 11);
    tcg_gen_movi_i64(tcg_ctx, t0, 0x0010000000000000);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, exp, zr, zr, t0);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t0, exp, nan, zr, t0);
    tcg_gen_deposit_i64(tcg_ctx, xtl, t0, xbl, 0, 52);
    set_cpu_vsrl(tcg_ctx, xT(ctx->opcode), xtl);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, exp);
    tcg_temp_free_i64(tcg_ctx, zr);
    tcg_temp_free_i64(tcg_ctx, nan);
    tcg_temp_free_i64(tcg_ctx, xth);
    tcg_temp_free_i64(tcg_ctx, xtl);
    tcg_temp_free_i64(tcg_ctx, xbh);
    tcg_temp_free_i64(tcg_ctx, xbl);
}

#undef GEN_XX2FORM
#undef GEN_XX3FORM
#undef GEN_XX2IFORM
#undef GEN_XX3_RC_FORM
#undef GEN_XX3FORM_DM
#undef VSX_LOGICAL
