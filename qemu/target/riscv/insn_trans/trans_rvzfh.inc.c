/*
 * RISC-V translation routines for the RV64Zfh Standard Extension.
 *
 * Copyright (c) 2020 Chih-Min Chao, chihmin.chao@sifive.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define RISCV_NANBOX16_MASK UINT64_C(0xffffffffffff0000)

#define REQUIRE_ZFH(ctx) do { \
    if (!ctx->ext_zfh) { \
        return false; \
    } \
} while (0)

#define REQUIRE_ZFH_OR_ZFHMIN(ctx) do { \
    if (!ctx->ext_zfh && !ctx->ext_zfhmin) { \
        return false; \
    } \
} while (0)

static void gen_nanbox_h(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 value)
{
    tcg_gen_ori_i64(tcg_ctx, ret, value, RISCV_NANBOX16_MASK);
}

static void gen_check_nanbox_h(TCGContext *tcg_ctx, TCGv_i64 ret,
                               TCGv_i64 value)
{
    TCGv_i64 boxed = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 mask = tcg_const_i64(tcg_ctx, RISCV_NANBOX16_MASK);
    TCGv_i64 qnan = tcg_const_i64(tcg_ctx, 0x7e00u);

    tcg_gen_andi_i64(tcg_ctx, boxed, value, RISCV_NANBOX16_MASK);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, ret, boxed, mask, value, qnan);
    tcg_gen_andi_i64(tcg_ctx, ret, ret, UINT16_MAX);

    tcg_temp_free_i64(tcg_ctx, qnan);
    tcg_temp_free_i64(tcg_ctx, mask);
    tcg_temp_free_i64(tcg_ctx, boxed);
}

static bool trans_flh(DisasContext *ctx, arg_flh *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    REQUIRE_FPU;
    REQUIRE_ZFH_OR_ZFHMIN(ctx);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, a->imm);

    tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], t0, ctx->mem_idx,
                        MO_TEUW);
    gen_nanbox_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_fpr[a->rd]);

    tcg_temp_free(tcg_ctx, t0);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsh(DisasContext *ctx, arg_fsh *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    REQUIRE_FPU;
    REQUIRE_ZFH_OR_ZFHMIN(ctx);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, a->imm);

    tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rs2], t0, ctx->mem_idx,
                        MO_TEUW);

    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fmadd_h(DisasContext *ctx, arg_fmadd_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fmadd_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                       tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2],
                       tcg_ctx->cpu_fpr[a->rs3]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fmsub_h(DisasContext *ctx, arg_fmsub_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fmsub_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                       tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2],
                       tcg_ctx->cpu_fpr[a->rs3]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fnmsub_h(DisasContext *ctx, arg_fnmsub_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fnmsub_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2],
                        tcg_ctx->cpu_fpr[a->rs3]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fnmadd_h(DisasContext *ctx, arg_fnmadd_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fnmadd_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2],
                        tcg_ctx->cpu_fpr[a->rs3]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fadd_h(DisasContext *ctx, arg_fadd_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fadd_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsub_h(DisasContext *ctx, arg_fsub_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fsub_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fmul_h(DisasContext *ctx, arg_fmul_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fmul_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fdiv_h(DisasContext *ctx, arg_fdiv_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fdiv_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsqrt_h(DisasContext *ctx, arg_fsqrt_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fsqrt_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                       tcg_ctx->cpu_fpr[a->rs1]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsgnj_h(DisasContext *ctx, arg_fsgnj_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 frs1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 frs2 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 sign = tcg_temp_new_i64(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_check_nanbox_h(tcg_ctx, frs1, tcg_ctx->cpu_fpr[a->rs1]);
    gen_check_nanbox_h(tcg_ctx, frs2, tcg_ctx->cpu_fpr[a->rs2]);
    tcg_gen_andi_i64(tcg_ctx, sign, frs2, 0x8000);
    tcg_gen_andi_i64(tcg_ctx, frs1, frs1, ~UINT64_C(0x8000));
    tcg_gen_or_i64(tcg_ctx, frs1, frs1, sign);
    gen_nanbox_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], frs1);

    tcg_temp_free_i64(tcg_ctx, sign);
    tcg_temp_free_i64(tcg_ctx, frs2);
    tcg_temp_free_i64(tcg_ctx, frs1);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsgnjn_h(DisasContext *ctx, arg_fsgnjn_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 frs1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 frs2 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 sign = tcg_temp_new_i64(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_check_nanbox_h(tcg_ctx, frs1, tcg_ctx->cpu_fpr[a->rs1]);
    gen_check_nanbox_h(tcg_ctx, frs2, tcg_ctx->cpu_fpr[a->rs2]);
    tcg_gen_andi_i64(tcg_ctx, sign, frs2, 0x8000);
    tcg_gen_xori_i64(tcg_ctx, sign, sign, 0x8000);
    tcg_gen_andi_i64(tcg_ctx, frs1, frs1, ~UINT64_C(0x8000));
    tcg_gen_or_i64(tcg_ctx, frs1, frs1, sign);
    gen_nanbox_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], frs1);

    tcg_temp_free_i64(tcg_ctx, sign);
    tcg_temp_free_i64(tcg_ctx, frs2);
    tcg_temp_free_i64(tcg_ctx, frs1);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsgnjx_h(DisasContext *ctx, arg_fsgnjx_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 frs1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 frs2 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 sign = tcg_temp_new_i64(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_check_nanbox_h(tcg_ctx, frs1, tcg_ctx->cpu_fpr[a->rs1]);
    gen_check_nanbox_h(tcg_ctx, frs2, tcg_ctx->cpu_fpr[a->rs2]);
    tcg_gen_xor_i64(tcg_ctx, sign, frs1, frs2);
    tcg_gen_andi_i64(tcg_ctx, sign, sign, 0x8000);
    tcg_gen_andi_i64(tcg_ctx, frs1, frs1, ~UINT64_C(0x8000));
    tcg_gen_or_i64(tcg_ctx, frs1, frs1, sign);
    gen_nanbox_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], frs1);

    tcg_temp_free_i64(tcg_ctx, sign);
    tcg_temp_free_i64(tcg_ctx, frs2);
    tcg_temp_free_i64(tcg_ctx, frs1);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fmin_h(DisasContext *ctx, arg_fmin_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_helper_fmin_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fmax_h(DisasContext *ctx, arg_fmax_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_helper_fmax_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fcvt_s_h(DisasContext *ctx, arg_fcvt_s_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH_OR_ZFHMIN(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_s_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fcvt_d_h(DisasContext *ctx, arg_fcvt_d_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH_OR_ZFHMIN(ctx);
    REQUIRE_EXT(ctx, RVD);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_d_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fcvt_h_s(DisasContext *ctx, arg_fcvt_h_s *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH_OR_ZFHMIN(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_h_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fcvt_h_d(DisasContext *ctx, arg_fcvt_h_d *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    REQUIRE_FPU;
    REQUIRE_ZFH_OR_ZFHMIN(ctx);
    REQUIRE_EXT(ctx, RVD);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_h_d(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_feq_h(DisasContext *ctx, arg_feq_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_helper_feq_h(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                     tcg_ctx->cpu_fpr[a->rs2]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_flt_h(DisasContext *ctx, arg_flt_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_helper_flt_h(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                     tcg_ctx->cpu_fpr[a->rs2]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fle_h(DisasContext *ctx, arg_fle_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_helper_fle_h(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                     tcg_ctx->cpu_fpr[a->rs2]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fclass_h(DisasContext *ctx, arg_fclass_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_helper_fclass_h(tcg_ctx, t0, tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_w_h(DisasContext *ctx, arg_fcvt_w_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_w_h(tcg_ctx, t0, tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_wu_h(DisasContext *ctx, arg_fcvt_wu_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_wu_h(tcg_ctx, t0, tcg_ctx->cpu_env,
                         tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_h_w(DisasContext *ctx, arg_fcvt_h_w *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_h_w(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                        t0);
    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_h_wu(DisasContext *ctx, arg_fcvt_h_wu *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_h_wu(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                         t0);
    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fmv_x_h(DisasContext *ctx, arg_fmv_x_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH_OR_ZFHMIN(ctx);
#if defined(TARGET_RISCV64)
    tcg_gen_ext16s_tl(tcg_ctx, t0, tcg_ctx->cpu_fpr[a->rs1]);
#else
    tcg_gen_extrl_i64_i32(tcg_ctx, t0, tcg_ctx->cpu_fpr[a->rs1]);
    tcg_gen_ext16s_tl(tcg_ctx, t0, t0);
#endif
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fmv_h_x(DisasContext *ctx, arg_fmv_h_x *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    REQUIRE_FPU;
    REQUIRE_ZFH_OR_ZFHMIN(ctx);
#if defined(TARGET_RISCV64)
    tcg_gen_ext16u_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], t0);
#else
    tcg_gen_extu_i32_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], t0);
    tcg_gen_andi_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd],
                     tcg_ctx->cpu_fpr[a->rd], UINT16_MAX);
#endif
    gen_nanbox_h(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_fpr[a->rd]);
    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

#ifdef TARGET_RISCV64
static bool trans_fcvt_l_h(DisasContext *ctx, arg_fcvt_l_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_l_h(tcg_ctx, t0, tcg_ctx->cpu_env,
                        tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_lu_h(DisasContext *ctx, arg_fcvt_lu_h *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_lu_h(tcg_ctx, t0, tcg_ctx->cpu_env,
                         tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_h_l(DisasContext *ctx, arg_fcvt_h_l *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_h_l(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                        t0);
    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_h_lu(DisasContext *ctx, arg_fcvt_h_lu *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    REQUIRE_FPU;
    REQUIRE_ZFH(ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_h_lu(tcg_ctx, tcg_ctx->cpu_fpr[a->rd],
                         tcg_ctx->cpu_env, t0);
    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}
#endif
