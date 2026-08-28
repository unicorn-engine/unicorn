/*
 * RISC-V translation routines for the XVentanaCondOps extension.
 *
 * Copyright (c) 2021-2022 VRULL GmbH.
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

static bool gen_vt_condmask(DisasContext *ctx, arg_r *a, TCGCond cond)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv dest;
    TCGv source1;
    TCGv source2;
    TCGv zero;

    if (!ctx->ext_xventanacondops) {
        return false;
    }
    if (a->rd == 0) {
        return true;
    }

    dest = tcg_temp_new(tcg_ctx);
    source1 = tcg_temp_new(tcg_ctx);
    source2 = tcg_temp_new(tcg_ctx);
    zero = tcg_const_tl(tcg_ctx, 0);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);
    tcg_gen_movcond_tl(tcg_ctx, cond, dest, source2, zero, source1, zero);
    gen_set_gpr(tcg_ctx, a->rd, dest);

    tcg_temp_free(tcg_ctx, dest);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    tcg_temp_free(tcg_ctx, zero);
    return true;
}

static bool trans_vt_maskc(DisasContext *ctx, arg_vt_maskc *a)
{
    return gen_vt_condmask(ctx, a, TCG_COND_NE);
}

static bool trans_vt_maskcn(DisasContext *ctx, arg_vt_maskcn *a)
{
    return gen_vt_condmask(ctx, a, TCG_COND_EQ);
}
