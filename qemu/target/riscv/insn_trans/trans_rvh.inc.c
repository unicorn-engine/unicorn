/*
 * RISC-V translation routines for the RVXI Base Integer Instruction Set.
 *
 * Copyright (c) 2020 Western Digital
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

static bool trans_hfence_gvma(DisasContext *ctx, arg_sfence_vma *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    REQUIRE_EXT(ctx, RVH);
    gen_helper_hyp_tlb_flush(tcg_ctx, tcg_ctx->cpu_env);
    return true;
}

static bool trans_hfence_vvma(DisasContext *ctx, arg_sfence_vma *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    REQUIRE_EXT(ctx, RVH);
    gen_helper_hyp_tlb_flush(tcg_ctx, tcg_ctx->cpu_env);
    return true;
}
