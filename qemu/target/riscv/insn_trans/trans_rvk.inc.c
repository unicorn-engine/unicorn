/*
 * RISC-V translation routines for scalar cryptography extensions.
 *
 * Copyright (c) 2021 Ruibo Lu, luruibo2000@163.com
 * Copyright (c) 2021 Zewen Ye, lustrew@foxmail.com
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

#define REQUIRE_ZKNH(ctx) do { \
    if (!(ctx)->ext_zknh) {    \
        return false;          \
    }                          \
} while (0)

#define REQUIRE_ZKND(ctx) do { \
    if (!(ctx)->ext_zknd) {    \
        return false;          \
    }                          \
} while (0)

#define REQUIRE_ZKNE(ctx) do { \
    if (!(ctx)->ext_zkne) {    \
        return false;          \
    }                          \
} while (0)

#define REQUIRE_ZKND_OR_ZKNE(ctx) do {                 \
    if (!(ctx)->ext_zknd && !(ctx)->ext_zkne) {         \
        return false;                                  \
    }                                                  \
} while (0)

#define REQUIRE_ZKSED(ctx) do { \
    if (!(ctx)->ext_zksed) {    \
        return false;           \
    }                           \
} while (0)

#define REQUIRE_ZKSH(ctx) do { \
    if (!(ctx)->ext_zksh) {    \
        return false;          \
    }                          \
} while (0)

static void gen_shri_i32(TCGContext *tcg_ctx, TCGv_i32 ret, TCGv_i32 arg,
                         unsigned shift)
{
    tcg_gen_shri_i32(tcg_ctx, ret, arg, shift);
}

static void gen_shri_i64(TCGContext *tcg_ctx, TCGv_i64 ret, TCGv_i64 arg,
                         unsigned shift)
{
    tcg_gen_shri_i64(tcg_ctx, ret, arg, shift);
}

static bool gen_aes32_sm4(DisasContext *ctx, arg_k_aes *a,
                          void (*func)(TCGContext *, TCGv, TCGv, TCGv,
                                       TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv dest = tcg_temp_new(tcg_ctx);
    TCGv source1 = tcg_temp_new(tcg_ctx);
    TCGv source2 = tcg_temp_new(tcg_ctx);
    TCGv shamt = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);
    tcg_gen_movi_tl(tcg_ctx, shamt, a->shamt);
    func(tcg_ctx, dest, source1, source2, shamt);
    gen_set_gpr(tcg_ctx, a->rd, dest);

    tcg_temp_free(tcg_ctx, dest);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    tcg_temp_free(tcg_ctx, shamt);
    return true;
}

#ifndef TARGET_RISCV64
static bool trans_aes32esmi(DisasContext *ctx, arg_aes32esmi *a)
{
    REQUIRE_ZKNE(ctx);
    return gen_aes32_sm4(ctx, a, gen_helper_aes32esmi);
}

static bool trans_aes32esi(DisasContext *ctx, arg_aes32esi *a)
{
    REQUIRE_ZKNE(ctx);
    return gen_aes32_sm4(ctx, a, gen_helper_aes32esi);
}

static bool trans_aes32dsmi(DisasContext *ctx, arg_aes32dsmi *a)
{
    REQUIRE_ZKND(ctx);
    return gen_aes32_sm4(ctx, a, gen_helper_aes32dsmi);
}

static bool trans_aes32dsi(DisasContext *ctx, arg_aes32dsi *a)
{
    REQUIRE_ZKND(ctx);
    return gen_aes32_sm4(ctx, a, gen_helper_aes32dsi);
}
#else
static bool trans_aes64es(DisasContext *ctx, arg_aes64es *a)
{
    REQUIRE_ZKNE(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_aes64es);
}

static bool trans_aes64esm(DisasContext *ctx, arg_aes64esm *a)
{
    REQUIRE_ZKNE(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_aes64esm);
}

static bool trans_aes64ds(DisasContext *ctx, arg_aes64ds *a)
{
    REQUIRE_ZKND(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_aes64ds);
}

static bool trans_aes64dsm(DisasContext *ctx, arg_aes64dsm *a)
{
    REQUIRE_ZKND(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_aes64dsm);
}

static bool trans_aes64ks2(DisasContext *ctx, arg_aes64ks2 *a)
{
    REQUIRE_ZKND_OR_ZKNE(ctx);
    return gen_arith(ctx->uc->tcg_ctx, a, gen_helper_aes64ks2);
}

static bool trans_aes64ks1i(DisasContext *ctx, arg_aes64ks1i *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv dest;
    TCGv source;
    TCGv round;

    REQUIRE_ZKND_OR_ZKNE(ctx);
    if (a->imm > 0xa) {
        return false;
    }

    dest = tcg_temp_new(tcg_ctx);
    source = tcg_temp_new(tcg_ctx);
    round = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source, a->rs1);
    tcg_gen_movi_tl(tcg_ctx, round, a->imm);
    gen_helper_aes64ks1i(tcg_ctx, dest, source, round);
    gen_set_gpr(tcg_ctx, a->rd, dest);

    tcg_temp_free(tcg_ctx, dest);
    tcg_temp_free(tcg_ctx, source);
    tcg_temp_free(tcg_ctx, round);
    return true;
}

static bool trans_aes64im(DisasContext *ctx, arg_aes64im *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv dest = tcg_temp_new(tcg_ctx);
    TCGv source = tcg_temp_new(tcg_ctx);

    REQUIRE_ZKND(ctx);
    gen_get_gpr(tcg_ctx, source, a->rs1);
    gen_helper_aes64im(tcg_ctx, dest, source);
    gen_set_gpr(tcg_ctx, a->rd, dest);

    tcg_temp_free(tcg_ctx, dest);
    tcg_temp_free(tcg_ctx, source);
    return true;
}
#endif

static bool gen_sha256(DisasContext *ctx, arg_decode_insn3213 *a,
                       void (*func)(TCGContext *, TCGv_i32, TCGv_i32,
                                    unsigned),
                       unsigned num1, unsigned num2, unsigned num3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source = tcg_temp_new(tcg_ctx);
    TCGv_i32 word = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 tmp1 = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 tmp2 = tcg_temp_new_i32(tcg_ctx);

    gen_get_gpr(tcg_ctx, source, a->rs1);
    tcg_gen_trunc_tl_i32(tcg_ctx, word, source);
    tcg_gen_rotri_i32(tcg_ctx, tmp1, word, num1);
    tcg_gen_rotri_i32(tcg_ctx, tmp2, word, num2);
    tcg_gen_xor_i32(tcg_ctx, tmp1, tmp1, tmp2);
    func(tcg_ctx, tmp2, word, num3);
    tcg_gen_xor_i32(tcg_ctx, tmp1, tmp1, tmp2);
    tcg_gen_ext_i32_tl(tcg_ctx, source, tmp1);
    gen_set_gpr(tcg_ctx, a->rd, source);

    tcg_temp_free(tcg_ctx, source);
    tcg_temp_free_i32(tcg_ctx, word);
    tcg_temp_free_i32(tcg_ctx, tmp1);
    tcg_temp_free_i32(tcg_ctx, tmp2);
    return true;
}

static bool trans_sha256sig0(DisasContext *ctx, arg_sha256sig0 *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha256(ctx, a, gen_shri_i32, 7, 18, 3);
}

static bool trans_sha256sig1(DisasContext *ctx, arg_sha256sig1 *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha256(ctx, a, gen_shri_i32, 17, 19, 10);
}

static bool trans_sha256sum0(DisasContext *ctx, arg_sha256sum0 *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha256(ctx, a, tcg_gen_rotri_i32, 2, 13, 22);
}

static bool trans_sha256sum1(DisasContext *ctx, arg_sha256sum1 *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha256(ctx, a, tcg_gen_rotri_i32, 6, 11, 25);
}

#ifndef TARGET_RISCV64
static bool gen_sha512_rv32(DisasContext *ctx, arg_r *a,
                            void (*func1)(TCGContext *, TCGv_i64,
                                          TCGv_i64, unsigned),
                            void (*func2)(TCGContext *, TCGv_i64,
                                          TCGv_i64, unsigned),
                            unsigned num1, unsigned num2, unsigned num3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1 = tcg_temp_new(tcg_ctx);
    TCGv source2 = tcg_temp_new(tcg_ctx);
    TCGv_i64 dword = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp2 = tcg_temp_new_i64(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);
    tcg_gen_concat_tl_i64(tcg_ctx, dword, source1, source2);
    func1(tcg_ctx, tmp1, dword, num1);
    func2(tcg_ctx, tmp2, dword, num2);
    tcg_gen_xor_i64(tcg_ctx, tmp1, tmp1, tmp2);
    tcg_gen_rotri_i64(tcg_ctx, tmp2, dword, num3);
    tcg_gen_xor_i64(tcg_ctx, tmp1, tmp1, tmp2);
    tcg_gen_trunc_i64_tl(tcg_ctx, source1, tmp1);
    gen_set_gpr(tcg_ctx, a->rd, source1);

    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    tcg_temp_free_i64(tcg_ctx, dword);
    tcg_temp_free_i64(tcg_ctx, tmp1);
    tcg_temp_free_i64(tcg_ctx, tmp2);
    return true;
}

static bool trans_sha512sum0r(DisasContext *ctx, arg_sha512sum0r *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512_rv32(ctx, a, tcg_gen_rotli_i64,
                           tcg_gen_rotli_i64, 25, 30, 28);
}

static bool trans_sha512sum1r(DisasContext *ctx, arg_sha512sum1r *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512_rv32(ctx, a, tcg_gen_rotli_i64,
                           tcg_gen_rotri_i64, 23, 14, 18);
}

static bool trans_sha512sig0l(DisasContext *ctx, arg_sha512sig0l *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512_rv32(ctx, a, tcg_gen_rotri_i64,
                           tcg_gen_rotri_i64, 1, 7, 8);
}

static bool trans_sha512sig1l(DisasContext *ctx, arg_sha512sig1l *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512_rv32(ctx, a, tcg_gen_rotli_i64,
                           tcg_gen_rotri_i64, 3, 6, 19);
}

static bool gen_sha512h_rv32(DisasContext *ctx, arg_r *a,
                             void (*func)(TCGContext *, TCGv_i64,
                                          TCGv_i64, unsigned),
                             unsigned num1, unsigned num2, unsigned num3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1 = tcg_temp_new(tcg_ctx);
    TCGv source2 = tcg_temp_new(tcg_ctx);
    TCGv_i64 dword = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp2 = tcg_temp_new_i64(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);
    tcg_gen_concat_tl_i64(tcg_ctx, dword, source1, source2);
    func(tcg_ctx, tmp1, dword, num1);
    tcg_gen_ext32u_i64(tcg_ctx, tmp2, dword);
    tcg_gen_shri_i64(tcg_ctx, tmp2, tmp2, num2);
    tcg_gen_xor_i64(tcg_ctx, tmp1, tmp1, tmp2);
    tcg_gen_rotri_i64(tcg_ctx, tmp2, dword, num3);
    tcg_gen_xor_i64(tcg_ctx, tmp1, tmp1, tmp2);
    tcg_gen_trunc_i64_tl(tcg_ctx, source1, tmp1);
    gen_set_gpr(tcg_ctx, a->rd, source1);

    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    tcg_temp_free_i64(tcg_ctx, dword);
    tcg_temp_free_i64(tcg_ctx, tmp1);
    tcg_temp_free_i64(tcg_ctx, tmp2);
    return true;
}

static bool trans_sha512sig0h(DisasContext *ctx, arg_sha512sig0h *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512h_rv32(ctx, a, tcg_gen_rotri_i64, 1, 7, 8);
}

static bool trans_sha512sig1h(DisasContext *ctx, arg_sha512sig1h *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512h_rv32(ctx, a, tcg_gen_rotli_i64, 3, 6, 19);
}
#else
static bool gen_sha512_rv64(DisasContext *ctx, arg_decode_insn3213 *a,
                            void (*func)(TCGContext *, TCGv_i64,
                                         TCGv_i64, unsigned),
                            unsigned num1, unsigned num2, unsigned num3)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source = tcg_temp_new(tcg_ctx);
    TCGv_i64 dword = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp2 = tcg_temp_new_i64(tcg_ctx);

    gen_get_gpr(tcg_ctx, source, a->rs1);
    tcg_gen_extu_tl_i64(tcg_ctx, dword, source);
    tcg_gen_rotri_i64(tcg_ctx, tmp1, dword, num1);
    tcg_gen_rotri_i64(tcg_ctx, tmp2, dword, num2);
    tcg_gen_xor_i64(tcg_ctx, tmp1, tmp1, tmp2);
    func(tcg_ctx, tmp2, dword, num3);
    tcg_gen_xor_i64(tcg_ctx, tmp1, tmp1, tmp2);
    tcg_gen_trunc_i64_tl(tcg_ctx, source, tmp1);
    gen_set_gpr(tcg_ctx, a->rd, source);

    tcg_temp_free(tcg_ctx, source);
    tcg_temp_free_i64(tcg_ctx, dword);
    tcg_temp_free_i64(tcg_ctx, tmp1);
    tcg_temp_free_i64(tcg_ctx, tmp2);
    return true;
}

static bool trans_sha512sig0(DisasContext *ctx, arg_sha512sig0 *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512_rv64(ctx, a, gen_shri_i64, 1, 8, 7);
}

static bool trans_sha512sig1(DisasContext *ctx, arg_sha512sig1 *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512_rv64(ctx, a, gen_shri_i64, 19, 61, 6);
}

static bool trans_sha512sum0(DisasContext *ctx, arg_sha512sum0 *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512_rv64(ctx, a, tcg_gen_rotri_i64, 28, 34, 39);
}

static bool trans_sha512sum1(DisasContext *ctx, arg_sha512sum1 *a)
{
    REQUIRE_ZKNH(ctx);
    return gen_sha512_rv64(ctx, a, tcg_gen_rotri_i64, 14, 18, 41);
}
#endif

static bool gen_sm3(DisasContext *ctx, arg_decode_insn3213 *a,
                    unsigned num1, unsigned num2)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source = tcg_temp_new(tcg_ctx);
    TCGv_i32 word = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 tmp = tcg_temp_new_i32(tcg_ctx);

    gen_get_gpr(tcg_ctx, source, a->rs1);
    tcg_gen_trunc_tl_i32(tcg_ctx, word, source);
    tcg_gen_rotli_i32(tcg_ctx, tmp, word, num1);
    tcg_gen_xor_i32(tcg_ctx, tmp, word, tmp);
    tcg_gen_rotli_i32(tcg_ctx, word, word, num2);
    tcg_gen_xor_i32(tcg_ctx, tmp, tmp, word);
    tcg_gen_ext_i32_tl(tcg_ctx, source, tmp);
    gen_set_gpr(tcg_ctx, a->rd, source);

    tcg_temp_free(tcg_ctx, source);
    tcg_temp_free_i32(tcg_ctx, word);
    tcg_temp_free_i32(tcg_ctx, tmp);
    return true;
}

static bool trans_sm3p0(DisasContext *ctx, arg_sm3p0 *a)
{
    REQUIRE_ZKSH(ctx);
    return gen_sm3(ctx, a, 9, 17);
}

static bool trans_sm3p1(DisasContext *ctx, arg_sm3p1 *a)
{
    REQUIRE_ZKSH(ctx);
    return gen_sm3(ctx, a, 15, 23);
}

static bool trans_sm4ed(DisasContext *ctx, arg_sm4ed *a)
{
    REQUIRE_ZKSED(ctx);
    return gen_aes32_sm4(ctx, a, gen_helper_sm4ed);
}

static bool trans_sm4ks(DisasContext *ctx, arg_sm4ks *a)
{
    REQUIRE_ZKSED(ctx);
    return gen_aes32_sm4(ctx, a, gen_helper_sm4ks);
}

#undef REQUIRE_ZKND
#undef REQUIRE_ZKNE
#undef REQUIRE_ZKNH
#undef REQUIRE_ZKND_OR_ZKNE
#undef REQUIRE_ZKSED
#undef REQUIRE_ZKSH
