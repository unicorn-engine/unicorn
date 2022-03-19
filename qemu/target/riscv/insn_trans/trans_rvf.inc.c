/*
 * RISC-V translation routines for the RV64F Standard Extension.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2018 Peer Adelt, peer.adelt@hni.uni-paderborn.de
 *                    Bastian Koppelmann, kbastian@mail.uni-paderborn.de
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

#define REQUIRE_FPU do {\
    if (ctx->mstatus_fs == 0) \
        return false;                       \
} while (0)

static bool trans_flw(DisasContext *ctx, arg_flw *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, a->imm);

    tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], t0, ctx->mem_idx, MO_TEUL);
    /* RISC-V requires NaN-boxing of narrower width floating point values */
    tcg_gen_ori_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_fpr[a->rd], 0xffffffff00000000ULL);

    tcg_temp_free(tcg_ctx, t0);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsw(DisasContext *ctx, arg_fsw *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, a->imm);

    tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rs2], t0, ctx->mem_idx, MO_TEUL);

    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fmadd_s(DisasContext *ctx, arg_fmadd_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_set_rm(ctx, a->rm);
    gen_helper_fmadd_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                       tcg_ctx->cpu_fpr[a->rs2], tcg_ctx->cpu_fpr[a->rs3]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fmsub_s(DisasContext *ctx, arg_fmsub_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_set_rm(ctx, a->rm);
    gen_helper_fmsub_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                       tcg_ctx->cpu_fpr[a->rs2], tcg_ctx->cpu_fpr[a->rs3]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fnmsub_s(DisasContext *ctx, arg_fnmsub_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_set_rm(ctx, a->rm);
    gen_helper_fnmsub_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                        tcg_ctx->cpu_fpr[a->rs2], tcg_ctx->cpu_fpr[a->rs3]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fnmadd_s(DisasContext *ctx, arg_fnmadd_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_set_rm(ctx, a->rm);
    gen_helper_fnmadd_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                        tcg_ctx->cpu_fpr[a->rs2], tcg_ctx->cpu_fpr[a->rs3]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fadd_s(DisasContext *ctx, arg_fadd_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    gen_set_rm(ctx, a->rm);
    gen_helper_fadd_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsub_s(DisasContext *ctx, arg_fsub_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    gen_set_rm(ctx, a->rm);
    gen_helper_fsub_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fmul_s(DisasContext *ctx, arg_fmul_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    gen_set_rm(ctx, a->rm);
    gen_helper_fmul_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fdiv_s(DisasContext *ctx, arg_fdiv_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    gen_set_rm(ctx, a->rm);
    gen_helper_fdiv_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env,
                      tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsqrt_s(DisasContext *ctx, arg_fsqrt_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    gen_set_rm(ctx, a->rm);
    gen_helper_fsqrt_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsgnj_s(DisasContext *ctx, arg_fsgnj_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (a->rs1 == a->rs2) { /* FMOV */
        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_fpr[a->rs1]);
    } else { /* FSGNJ */
        tcg_gen_deposit_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_fpr[a->rs2], tcg_ctx->cpu_fpr[a->rs1],
                            0, 31);
    }
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsgnjn_s(DisasContext *ctx, arg_fsgnjn_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (a->rs1 == a->rs2) { /* FNEG */
        tcg_gen_xori_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_fpr[a->rs1], INT32_MIN);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_not_i64(tcg_ctx, t0, tcg_ctx->cpu_fpr[a->rs2]);
        tcg_gen_deposit_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], t0, tcg_ctx->cpu_fpr[a->rs1], 0, 31);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fsgnjx_s(DisasContext *ctx, arg_fsgnjx_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (a->rs1 == a->rs2) { /* FABS */
        tcg_gen_andi_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_fpr[a->rs1], ~INT32_MIN);
    } else {
        TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
        tcg_gen_andi_i64(tcg_ctx, t0, tcg_ctx->cpu_fpr[a->rs2], INT32_MIN);
        tcg_gen_xor_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_fpr[a->rs1], t0);
        tcg_temp_free_i64(tcg_ctx, t0);
    }
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fmin_s(DisasContext *ctx, arg_fmin_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    gen_helper_fmin_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                      tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fmax_s(DisasContext *ctx, arg_fmax_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    gen_helper_fmax_s(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1],
                      tcg_ctx->cpu_fpr[a->rs2]);
    mark_fs_dirty(ctx);
    return true;
}

static bool trans_fcvt_w_s(DisasContext *ctx, arg_fcvt_w_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_w_s(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);

    return true;
}

static bool trans_fcvt_wu_s(DisasContext *ctx, arg_fcvt_wu_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_wu_s(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);

    return true;
}

static bool trans_fmv_x_w(DisasContext *ctx, arg_fmv_x_w *a)
{
    /* NOTE: This was FMV.X.S in an earlier version of the ISA spec! */
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);

#if defined(TARGET_RISCV64)
    tcg_gen_ext32s_tl(tcg_ctx, t0, tcg_ctx->cpu_fpr[a->rs1]);
#else
    tcg_gen_extrl_i64_i32(tcg_ctx, t0, tcg_ctx->cpu_fpr[a->rs1]);
#endif

    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);

    return true;
}

static bool trans_feq_s(DisasContext *ctx, arg_feq_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_helper_feq_s(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_flt_s(DisasContext *ctx, arg_flt_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_helper_flt_s(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fle_s(DisasContext *ctx, arg_fle_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_helper_fle_s(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1], tcg_ctx->cpu_fpr[a->rs2]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fclass_s(DisasContext *ctx, arg_fclass_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);

    gen_helper_fclass_s(tcg_ctx, t0, tcg_ctx->cpu_fpr[a->rs1]);

    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);

    return true;
}

static bool trans_fcvt_s_w(DisasContext *ctx, arg_fcvt_s_w *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_s_w(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, t0);

    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);

    return true;
}

static bool trans_fcvt_s_wu(DisasContext *ctx, arg_fcvt_s_wu *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_s_wu(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, t0);

    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);

    return true;
}

static bool trans_fmv_w_x(DisasContext *ctx, arg_fmv_w_x *a)
{
    /* NOTE: This was FMV.S.X in an earlier version of the ISA spec! */
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

#if defined(TARGET_RISCV64)
    tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], t0);
#else
    tcg_gen_extu_i32_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], t0);
#endif

    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);

    return true;
}

#ifdef TARGET_RISCV64
static bool trans_fcvt_l_s(DisasContext *ctx, arg_fcvt_l_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_l_s(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_lu_s(DisasContext *ctx, arg_fcvt_lu_s *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_lu_s(tcg_ctx, t0, tcg_ctx->cpu_env, tcg_ctx->cpu_fpr[a->rs1]);
    gen_set_gpr(tcg_ctx, a->rd, t0);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_s_l(DisasContext *ctx, arg_fcvt_s_l *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_s_l(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, t0);

    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool trans_fcvt_s_lu(DisasContext *ctx, arg_fcvt_s_lu *a)
{
    REQUIRE_FPU;
    REQUIRE_EXT(ctx, RVF);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);

    gen_set_rm(ctx, a->rm);
    gen_helper_fcvt_s_lu(tcg_ctx, tcg_ctx->cpu_fpr[a->rd], tcg_ctx->cpu_env, t0);

    mark_fs_dirty(ctx);
    tcg_temp_free(tcg_ctx, t0);
    return true;
}
#endif
