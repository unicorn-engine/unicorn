/*
 * RISC-V translation routines for the RV64A Standard Extension.
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

static inline bool gen_lr(DisasContext *ctx, arg_atomic *a, MemOp mop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv src1 = tcg_temp_new(tcg_ctx);
    /* Put addr in load_res, data in load_val.  */
    gen_get_gpr(tcg_ctx, src1, a->rs1);
    if (a->rl) {
        tcg_gen_mb(tcg_ctx, TCG_MO_ALL | TCG_BAR_STRL);
    }
    tcg_gen_qemu_ld_tl(tcg_ctx, tcg_ctx->load_val, src1, ctx->mem_idx, mop);
    if (a->aq) {
        tcg_gen_mb(tcg_ctx, TCG_MO_ALL | TCG_BAR_LDAQ);
    }
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->load_res, src1);
    gen_set_gpr(tcg_ctx, a->rd, tcg_ctx->load_val);

    tcg_temp_free(tcg_ctx, src1);
    return true;
}

static inline bool gen_sc(DisasContext *ctx, arg_atomic *a, MemOp mop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv src1 = tcg_temp_new(tcg_ctx);
    TCGv src2 = tcg_temp_new(tcg_ctx);
    TCGv dat = tcg_temp_new(tcg_ctx);
    TCGLabel *l1 = gen_new_label(tcg_ctx);
    TCGLabel *l2 = gen_new_label(tcg_ctx);

    gen_get_gpr(tcg_ctx, src1, a->rs1);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_NE, tcg_ctx->load_res, src1, l1);

    gen_get_gpr(tcg_ctx, src2, a->rs2);
    /*
     * Note that the TCG atomic primitives are SC,
     * so we can ignore AQ/RL along this path.
     */
    tcg_gen_atomic_cmpxchg_tl(tcg_ctx, src1, tcg_ctx->load_res, tcg_ctx->load_val, src2,
                              ctx->mem_idx, mop);
    tcg_gen_setcond_tl(tcg_ctx, TCG_COND_NE, dat, src1, tcg_ctx->load_val);
    gen_set_gpr(tcg_ctx, a->rd, dat);
    tcg_gen_br(tcg_ctx, l2);

    gen_set_label(tcg_ctx, l1);
    /*
     * Address comparison failure.  However, we still need to
     * provide the memory barrier implied by AQ/RL.
     */
    tcg_gen_mb(tcg_ctx, TCG_MO_ALL + a->aq * TCG_BAR_LDAQ + a->rl * TCG_BAR_STRL);
    tcg_gen_movi_tl(tcg_ctx, dat, 1);
    gen_set_gpr(tcg_ctx, a->rd, dat);

    gen_set_label(tcg_ctx, l2);
    /*
     * Clear the load reservation, since an SC must fail if there is
     * an SC to any address, in between an LR and SC pair.
     */
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->load_res, -1);

    tcg_temp_free(tcg_ctx, dat);
    tcg_temp_free(tcg_ctx, src1);
    tcg_temp_free(tcg_ctx, src2);
    return true;
}

static bool gen_amo(DisasContext *ctx, arg_atomic *a,
                    void(*func)(TCGContext *, TCGv, TCGv, TCGv, TCGArg, MemOp),
                    MemOp mop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv src1 = tcg_temp_new(tcg_ctx);
    TCGv src2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, src1, a->rs1);
    gen_get_gpr(tcg_ctx, src2, a->rs2);

    (*func)(tcg_ctx, src2, src1, src2, ctx->mem_idx, mop);

    gen_set_gpr(tcg_ctx, a->rd, src2);
    tcg_temp_free(tcg_ctx, src1);
    tcg_temp_free(tcg_ctx, src2);
    return true;
}

static bool trans_lr_w(DisasContext *ctx, arg_lr_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_lr(ctx, a, (MO_ALIGN | MO_TESL));
}

static bool trans_sc_w(DisasContext *ctx, arg_sc_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_sc(ctx, a, (MO_ALIGN | MO_TESL));
}

static bool trans_amoswap_w(DisasContext *ctx, arg_amoswap_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_xchg_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoadd_w(DisasContext *ctx, arg_amoadd_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_add_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoxor_w(DisasContext *ctx, arg_amoxor_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_xor_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoand_w(DisasContext *ctx, arg_amoand_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_and_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoor_w(DisasContext *ctx, arg_amoor_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_or_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomin_w(DisasContext *ctx, arg_amomin_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smin_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomax_w(DisasContext *ctx, arg_amomax_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smax_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amominu_w(DisasContext *ctx, arg_amominu_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umin_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomaxu_w(DisasContext *ctx, arg_amomaxu_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umax_tl, (MO_ALIGN | MO_TESL));
}

#ifdef TARGET_RISCV64

static bool trans_lr_d(DisasContext *ctx, arg_lr_d *a)
{
    return gen_lr(ctx, a, MO_ALIGN | MO_TEQ);
}

static bool trans_sc_d(DisasContext *ctx, arg_sc_d *a)
{
    return gen_sc(ctx, a, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoswap_d(DisasContext *ctx, arg_amoswap_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_xchg_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoadd_d(DisasContext *ctx, arg_amoadd_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_add_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoxor_d(DisasContext *ctx, arg_amoxor_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_xor_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoand_d(DisasContext *ctx, arg_amoand_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_and_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoor_d(DisasContext *ctx, arg_amoor_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_or_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amomin_d(DisasContext *ctx, arg_amomin_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smin_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amomax_d(DisasContext *ctx, arg_amomax_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smax_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amominu_d(DisasContext *ctx, arg_amominu_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umin_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amomaxu_d(DisasContext *ctx, arg_amomaxu_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umax_tl, (MO_ALIGN | MO_TEQ));
}
#endif
