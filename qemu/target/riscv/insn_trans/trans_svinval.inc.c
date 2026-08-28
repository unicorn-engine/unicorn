static bool trans_sinval_vma(DisasContext *ctx, arg_sfence_vma *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (!ctx->ext_svinval || !has_ext(ctx, RVS)) {
        return false;
    }

    gen_helper_tlb_flush(tcg_ctx, tcg_ctx->cpu_env);
    return true;
}

static bool trans_sfence_w_inval(DisasContext *ctx, arg_sfence_w_inval *a)
{
    if (!ctx->ext_svinval || !has_ext(ctx, RVS)) {
        return false;
    }

    return true;
}

static bool trans_sfence_inval_ir(DisasContext *ctx, arg_sfence_inval_ir *a)
{
    if (!ctx->ext_svinval || !has_ext(ctx, RVS)) {
        return false;
    }

    return true;
}

static bool trans_hinval_vvma(DisasContext *ctx, arg_hinval_vvma *a)
{
    if (!ctx->ext_svinval || !has_ext(ctx, RVH)) {
        return false;
    }

    return trans_hfence_bvma(ctx, a);
}

static bool trans_hinval_gvma(DisasContext *ctx, arg_hinval_gvma *a)
{
    if (!ctx->ext_svinval || !has_ext(ctx, RVH)) {
        return false;
    }

    return trans_hfence_gvma(ctx, a);
}
