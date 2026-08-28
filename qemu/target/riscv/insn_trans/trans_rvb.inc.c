/*
 * RISC-V translation routines for bit manipulation extensions.
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

#define REQUIRE_ZBA(ctx) do { \
    if (!(ctx)->ext_zba) {    \
        return false;         \
    }                         \
} while (0)

#define REQUIRE_ZBB(ctx) do { \
    if (!(ctx)->ext_zbb) {    \
        return false;         \
    }                         \
} while (0)

#define REQUIRE_ZBC(ctx) do { \
    if (!(ctx)->ext_zbc) {    \
        return false;         \
    }                         \
} while (0)

#define REQUIRE_ZBC_OR_ZBKC(ctx) do {             \
    if (!(ctx)->ext_zbc && !(ctx)->ext_zbkc) {    \
        return false;                             \
    }                                             \
} while (0)

#define REQUIRE_ZBKB(ctx) do { \
    if (!(ctx)->ext_zbkb) {    \
        return false;          \
    }                          \
} while (0)

#define REQUIRE_ZBKX(ctx) do { \
    if (!(ctx)->ext_zbkx) {    \
        return false;          \
    }                          \
} while (0)

#define REQUIRE_ZBS(ctx) do { \
    if (!(ctx)->ext_zbs) {    \
        return false;         \
    }                         \
} while (0)

static bool gen_zbb_unary(DisasContext *ctx, arg_decode_insn3213 *a,
                          void (*func)(TCGContext *, TCGv, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source;

    if (a->rd == 0) {
        return true;
    }

    source = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, source, a->rs1);
    func(tcg_ctx, source, source);
    gen_set_gpr(tcg_ctx, a->rd, source);
    tcg_temp_free(tcg_ctx, source);
    return true;
}

static void gen_clz(TCGContext *tcg_ctx, TCGv ret, TCGv arg1)
{
    tcg_gen_clzi_tl(tcg_ctx, ret, arg1, TARGET_LONG_BITS);
}

static bool trans_clz(DisasContext *ctx, arg_clz *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, gen_clz);
}

static void gen_ctz(TCGContext *tcg_ctx, TCGv ret, TCGv arg1)
{
    tcg_gen_ctzi_tl(tcg_ctx, ret, arg1, TARGET_LONG_BITS);
}

static bool trans_ctz(DisasContext *ctx, arg_ctz *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, gen_ctz);
}

static bool trans_cpop(DisasContext *ctx, arg_cpop *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, tcg_gen_ctpop_tl);
}

static bool trans_andn(DisasContext *ctx, arg_andn *a)
{
    REQUIRE_ZBB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, tcg_gen_andc_tl);
}

static bool trans_orn(DisasContext *ctx, arg_orn *a)
{
    REQUIRE_ZBB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, tcg_gen_orc_tl);
}

static bool trans_xnor(DisasContext *ctx, arg_xnor *a)
{
    REQUIRE_ZBB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, tcg_gen_eqv_tl);
}

static bool trans_min(DisasContext *ctx, arg_min *a)
{
    REQUIRE_ZBB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, tcg_gen_smin_tl);
}

static bool trans_max(DisasContext *ctx, arg_max *a)
{
    REQUIRE_ZBB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, tcg_gen_smax_tl);
}

static bool trans_minu(DisasContext *ctx, arg_minu *a)
{
    REQUIRE_ZBB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, tcg_gen_umin_tl);
}

static bool trans_maxu(DisasContext *ctx, arg_maxu *a)
{
    REQUIRE_ZBB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, tcg_gen_umax_tl);
}

static bool trans_sext_b(DisasContext *ctx, arg_sext_b *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, tcg_gen_ext8s_tl);
}

static bool trans_sext_h(DisasContext *ctx, arg_sext_h *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, tcg_gen_ext16s_tl);
}

static bool trans_rol(DisasContext *ctx, arg_rol *a)
{
    REQUIRE_ZBB(ctx);
    return gen_shift(ctx, a, tcg_gen_rotl_tl);
}

static bool trans_ror(DisasContext *ctx, arg_ror *a)
{
    REQUIRE_ZBB(ctx);
    return gen_shift(ctx, a, tcg_gen_rotr_tl);
}

static bool trans_rori(DisasContext *ctx, arg_rori *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source;

    REQUIRE_ZBB(ctx);

    if (a->shamt >= TARGET_LONG_BITS) {
        return false;
    }

    if (a->rd == 0) {
        return true;
    }

    source = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, source, a->rs1);
    tcg_gen_rotri_tl(tcg_ctx, source, source, a->shamt);
    gen_set_gpr(tcg_ctx, a->rd, source);
    tcg_temp_free(tcg_ctx, source);
    return true;
}

static void gen_rev8_32(TCGContext *tcg_ctx, TCGv ret, TCGv arg1)
{
    tcg_gen_bswap32_tl(tcg_ctx, ret, arg1);
}

#ifndef TARGET_RISCV64
static bool trans_rev8_32(DisasContext *ctx, arg_rev8_32 *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, gen_rev8_32);
}

static bool trans_zext_h_32(DisasContext *ctx, arg_zext_h_32 *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, tcg_gen_ext16u_tl);
}
#endif

static void gen_orc_b(TCGContext *tcg_ctx, TCGv ret, TCGv arg1)
{
    TCGv tmp = tcg_temp_new(tcg_ctx);
#ifdef TARGET_RISCV64
    TCGv low7 = tcg_const_tl(tcg_ctx, 0x7f7f7f7f7f7f7f7full);
#else
    TCGv low7 = tcg_const_tl(tcg_ctx, 0x7f7f7f7f);
#endif

    tcg_gen_and_tl(tcg_ctx, tmp, arg1, low7);
    tcg_gen_add_tl(tcg_ctx, tmp, tmp, low7);
    tcg_gen_or_tl(tcg_ctx, tmp, tmp, arg1);
    tcg_gen_andc_tl(tcg_ctx, tmp, tmp, low7);
    tcg_gen_shri_tl(tcg_ctx, tmp, tmp, 7);
    tcg_gen_muli_tl(tcg_ctx, ret, tmp, 0xff);

    tcg_temp_free(tcg_ctx, tmp);
    tcg_temp_free(tcg_ctx, low7);
}

static bool trans_orc_b(DisasContext *ctx, arg_orc_b *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, gen_orc_b);
}

#ifdef TARGET_RISCV64
static void gen_rev8_64(TCGContext *tcg_ctx, TCGv ret, TCGv arg1)
{
    tcg_gen_bswap64_tl(tcg_ctx, ret, arg1);
}

static bool trans_rev8_64(DisasContext *ctx, arg_rev8_64 *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, gen_rev8_64);
}

static bool trans_zext_h_64(DisasContext *ctx, arg_zext_h_64 *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, tcg_gen_ext16u_tl);
}

static void gen_clzw(TCGContext *tcg_ctx, TCGv ret, TCGv arg1)
{
    TCGv tmp = tcg_temp_new(tcg_ctx);

    tcg_gen_shli_tl(tcg_ctx, tmp, arg1, 32);
    tcg_gen_clzi_tl(tcg_ctx, ret, tmp, 32);
    tcg_temp_free(tcg_ctx, tmp);
}

static bool trans_clzw(DisasContext *ctx, arg_clzw *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, gen_clzw);
}

static void gen_ctzw(TCGContext *tcg_ctx, TCGv ret, TCGv arg1)
{
    TCGv tmp = tcg_temp_new(tcg_ctx);

    tcg_gen_ext32u_tl(tcg_ctx, tmp, arg1);
    tcg_gen_ctzi_tl(tcg_ctx, ret, tmp, 32);
    tcg_temp_free(tcg_ctx, tmp);
}

static bool trans_ctzw(DisasContext *ctx, arg_ctzw *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, gen_ctzw);
}

static void gen_cpopw(TCGContext *tcg_ctx, TCGv ret, TCGv arg1)
{
    tcg_gen_ext32u_tl(tcg_ctx, ret, arg1);
    tcg_gen_ctpop_tl(tcg_ctx, ret, ret);
}

static bool trans_cpopw(DisasContext *ctx, arg_cpopw *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_unary(ctx, a, gen_cpopw);
}

static bool gen_zbb_word_shift(DisasContext *ctx, arg_r *a,
                               void (*func)(TCGContext *, TCGv_i32,
                                            TCGv_i32, TCGv_i32))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1 = tcg_temp_new(tcg_ctx);
    TCGv source2 = tcg_temp_new(tcg_ctx);
    TCGv_i32 word1 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 word2 = tcg_temp_new_i32(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);
    tcg_gen_trunc_tl_i32(tcg_ctx, word1, source1);
    tcg_gen_trunc_tl_i32(tcg_ctx, word2, source2);
    tcg_gen_andi_i32(tcg_ctx, word2, word2, 31);
    func(tcg_ctx, word1, word1, word2);
    tcg_gen_ext_i32_tl(tcg_ctx, source1, word1);
    gen_set_gpr(tcg_ctx, a->rd, source1);

    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    tcg_temp_free_i32(tcg_ctx, word1);
    tcg_temp_free_i32(tcg_ctx, word2);
    return true;
}

static bool trans_rolw(DisasContext *ctx, arg_rolw *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_word_shift(ctx, a, tcg_gen_rotl_i32);
}

static bool trans_rorw(DisasContext *ctx, arg_rorw *a)
{
    REQUIRE_ZBB(ctx);
    return gen_zbb_word_shift(ctx, a, tcg_gen_rotr_i32);
}

static bool trans_roriw(DisasContext *ctx, arg_roriw *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source;
    TCGv_i32 word;

    REQUIRE_ZBB(ctx);

    if (a->rd == 0) {
        return true;
    }

    source = tcg_temp_new(tcg_ctx);
    word = tcg_temp_new_i32(tcg_ctx);
    gen_get_gpr(tcg_ctx, source, a->rs1);
    tcg_gen_trunc_tl_i32(tcg_ctx, word, source);
    tcg_gen_rotri_i32(tcg_ctx, word, word, a->shamt);
    tcg_gen_ext_i32_tl(tcg_ctx, source, word);
    gen_set_gpr(tcg_ctx, a->rd, source);

    tcg_temp_free(tcg_ctx, source);
    tcg_temp_free_i32(tcg_ctx, word);
    return true;
}
#endif

#define GEN_SHADD(SHAMT)                                             \
static void gen_sh##SHAMT##add(TCGContext *tcg_ctx, TCGv ret,        \
                               TCGv arg1, TCGv arg2)                 \
{                                                                    \
    TCGv tmp = tcg_temp_new(tcg_ctx);                                \
                                                                     \
    tcg_gen_shli_tl(tcg_ctx, tmp, arg1, SHAMT);                      \
    tcg_gen_add_tl(tcg_ctx, ret, tmp, arg2);                         \
    tcg_temp_free(tcg_ctx, tmp);                                     \
}

GEN_SHADD(1)
GEN_SHADD(2)
GEN_SHADD(3)

#define GEN_TRANS_SHADD(SHAMT)                                      \
static bool trans_sh##SHAMT##add(DisasContext *ctx,                 \
                                 arg_sh##SHAMT##add *a)             \
{                                                                   \
    REQUIRE_ZBA(ctx);                                               \
    return gen_arith(ctx->uc->tcg_ctx, a, gen_sh##SHAMT##add);      \
}

GEN_TRANS_SHADD(1)
GEN_TRANS_SHADD(2)
GEN_TRANS_SHADD(3)

#ifdef TARGET_RISCV64
#define GEN_SHADD_UW(SHAMT)                                          \
static void gen_sh##SHAMT##add_uw(TCGContext *tcg_ctx, TCGv ret,     \
                                  TCGv arg1, TCGv arg2)              \
{                                                                    \
    TCGv tmp = tcg_temp_new(tcg_ctx);                                \
                                                                     \
    tcg_gen_ext32u_tl(tcg_ctx, tmp, arg1);                           \
    tcg_gen_shli_tl(tcg_ctx, tmp, tmp, SHAMT);                       \
    tcg_gen_add_tl(tcg_ctx, ret, tmp, arg2);                         \
    tcg_temp_free(tcg_ctx, tmp);                                     \
}

GEN_SHADD_UW(1)
GEN_SHADD_UW(2)
GEN_SHADD_UW(3)

#define GEN_TRANS_SHADD_UW(SHAMT)                                   \
static bool trans_sh##SHAMT##add_uw(DisasContext *ctx,              \
                                    arg_sh##SHAMT##add_uw *a)       \
{                                                                   \
    REQUIRE_ZBA(ctx);                                               \
    return gen_arith(ctx->uc->tcg_ctx, a, gen_sh##SHAMT##add_uw);   \
}

GEN_TRANS_SHADD_UW(1)
GEN_TRANS_SHADD_UW(2)
GEN_TRANS_SHADD_UW(3)

static void gen_add_uw(TCGContext *tcg_ctx, TCGv ret, TCGv arg1,
                       TCGv arg2)
{
    TCGv tmp = tcg_temp_new(tcg_ctx);

    tcg_gen_ext32u_tl(tcg_ctx, tmp, arg1);
    tcg_gen_add_tl(tcg_ctx, ret, tmp, arg2);
    tcg_temp_free(tcg_ctx, tmp);
}

static bool trans_add_uw(DisasContext *ctx, arg_add_uw *a)
{
    REQUIRE_ZBA(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_add_uw);
}

static bool trans_slli_uw(DisasContext *ctx, arg_slli_uw *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source;

    REQUIRE_ZBA(ctx);

    if (a->shamt >= TARGET_LONG_BITS) {
        return false;
    }

    if (a->rd == 0) {
        return true;
    }

    source = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, source, a->rs1);
    tcg_gen_ext32u_tl(tcg_ctx, source, source);
    tcg_gen_shli_tl(tcg_ctx, source, source, a->shamt);
    gen_set_gpr(tcg_ctx, a->rd, source);
    tcg_temp_free(tcg_ctx, source);
    return true;
}
#endif

static bool trans_clmul(DisasContext *ctx, arg_clmul *a)
{
    REQUIRE_ZBC_OR_ZBKC(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_clmul);
}

static void gen_clmulh(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv arg2)
{
    gen_helper_clmulr(tcg_ctx, ret, arg1, arg2);
    tcg_gen_shri_tl(tcg_ctx, ret, ret, 1);
}

static bool trans_clmulh(DisasContext *ctx, arg_clmulh *a)
{
    REQUIRE_ZBC_OR_ZBKC(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_clmulh);
}

static bool trans_clmulr(DisasContext *ctx, arg_clmulr *a)
{
    REQUIRE_ZBC(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_clmulr);
}

static bool trans_brev8(DisasContext *ctx, arg_brev8 *a)
{
    REQUIRE_ZBKB(ctx);
    return gen_zbb_unary(ctx, a, gen_helper_brev8);
}

static void gen_pack(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv arg2)
{
    tcg_gen_deposit_tl(tcg_ctx, ret, arg1, arg2,
                       TARGET_LONG_BITS / 2, TARGET_LONG_BITS / 2);
}

static bool trans_pack(DisasContext *ctx, arg_pack *a)
{
    REQUIRE_ZBKB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_pack);
}

static void gen_packh(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv arg2)
{
    TCGv tmp = tcg_temp_new(tcg_ctx);

    tcg_gen_ext8u_tl(tcg_ctx, tmp, arg2);
    tcg_gen_deposit_tl(tcg_ctx, ret, arg1, tmp, 8, TARGET_LONG_BITS - 8);
    tcg_temp_free(tcg_ctx, tmp);
}

static bool trans_packh(DisasContext *ctx, arg_packh *a)
{
    REQUIRE_ZBKB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_packh);
}

#ifdef TARGET_RISCV64
static void gen_packw(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv arg2)
{
    TCGv tmp = tcg_temp_new(tcg_ctx);

    tcg_gen_ext16s_tl(tcg_ctx, tmp, arg2);
    tcg_gen_deposit_tl(tcg_ctx, ret, arg1, tmp, 16, TARGET_LONG_BITS - 16);
    tcg_temp_free(tcg_ctx, tmp);
}

static bool trans_packw(DisasContext *ctx, arg_packw *a)
{
    REQUIRE_ZBKB(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_packw);
}
#endif

#ifndef TARGET_RISCV64
static bool trans_unzip(DisasContext *ctx, arg_unzip *a)
{
    REQUIRE_ZBKB(ctx);
    return gen_zbb_unary(ctx, a, gen_helper_unzip);
}

static bool trans_zip(DisasContext *ctx, arg_zip *a)
{
    REQUIRE_ZBKB(ctx);
    return gen_zbb_unary(ctx, a, gen_helper_zip);
}
#endif

static bool trans_xperm4(DisasContext *ctx, arg_xperm4 *a)
{
    REQUIRE_ZBKX(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_xperm4);
}

static bool trans_xperm8(DisasContext *ctx, arg_xperm8 *a)
{
    REQUIRE_ZBKX(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_xperm8);
}

static void gen_sbop_mask(TCGContext *tcg_ctx, TCGv ret, TCGv shamt)
{
    tcg_gen_movi_tl(tcg_ctx, ret, 1);
    tcg_gen_shl_tl(tcg_ctx, ret, ret, shamt);
}

static void gen_bset(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv shamt)
{
    TCGv mask = tcg_temp_new(tcg_ctx);

    gen_sbop_mask(tcg_ctx, mask, shamt);
    tcg_gen_or_tl(tcg_ctx, ret, arg1, mask);
    tcg_temp_free(tcg_ctx, mask);
}

static void gen_bclr(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv shamt)
{
    TCGv mask = tcg_temp_new(tcg_ctx);

    gen_sbop_mask(tcg_ctx, mask, shamt);
    tcg_gen_andc_tl(tcg_ctx, ret, arg1, mask);
    tcg_temp_free(tcg_ctx, mask);
}

static void gen_binv(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv shamt)
{
    TCGv mask = tcg_temp_new(tcg_ctx);

    gen_sbop_mask(tcg_ctx, mask, shamt);
    tcg_gen_xor_tl(tcg_ctx, ret, arg1, mask);
    tcg_temp_free(tcg_ctx, mask);
}

static void gen_bext(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv shamt)
{
    tcg_gen_shr_tl(tcg_ctx, ret, arg1, shamt);
    tcg_gen_andi_tl(tcg_ctx, ret, ret, 1);
}

static bool gen_zbs_imm(DisasContext *ctx, arg_shift *a,
                        void (*func)(TCGContext *, TCGv, TCGv, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source;
    TCGv shamt;

    REQUIRE_ZBS(ctx);

    if (a->shamt >= TARGET_LONG_BITS) {
        return false;
    }

    if (a->rd == 0) {
        return true;
    }

    source = tcg_temp_new(tcg_ctx);
    shamt = tcg_const_tl(tcg_ctx, a->shamt);
    gen_get_gpr(tcg_ctx, source, a->rs1);
    func(tcg_ctx, source, source, shamt);
    gen_set_gpr(tcg_ctx, a->rd, source);
    tcg_temp_free(tcg_ctx, source);
    tcg_temp_free(tcg_ctx, shamt);
    return true;
}

static bool trans_bset(DisasContext *ctx, arg_bset *a)
{
    REQUIRE_ZBS(ctx);
    return gen_shift(ctx, a, gen_bset);
}

static bool trans_bseti(DisasContext *ctx, arg_bseti *a)
{
    return gen_zbs_imm(ctx, a, gen_bset);
}

static bool trans_bclr(DisasContext *ctx, arg_bclr *a)
{
    REQUIRE_ZBS(ctx);
    return gen_shift(ctx, a, gen_bclr);
}

static bool trans_bclri(DisasContext *ctx, arg_bclri *a)
{
    return gen_zbs_imm(ctx, a, gen_bclr);
}

static bool trans_binv(DisasContext *ctx, arg_binv *a)
{
    REQUIRE_ZBS(ctx);
    return gen_shift(ctx, a, gen_binv);
}

static bool trans_binvi(DisasContext *ctx, arg_binvi *a)
{
    return gen_zbs_imm(ctx, a, gen_binv);
}

static bool trans_bext(DisasContext *ctx, arg_bext *a)
{
    REQUIRE_ZBS(ctx);
    return gen_shift(ctx, a, gen_bext);
}

static bool trans_bexti(DisasContext *ctx, arg_bexti *a)
{
    return gen_zbs_imm(ctx, a, gen_bext);
}

#undef REQUIRE_ZBA
#undef REQUIRE_ZBB
#undef REQUIRE_ZBC
#undef REQUIRE_ZBC_OR_ZBKC
#undef REQUIRE_ZBKB
#undef REQUIRE_ZBKX
#undef REQUIRE_ZBS
