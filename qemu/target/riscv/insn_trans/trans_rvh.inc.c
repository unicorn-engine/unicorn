/*
 * RISC-V translation routines for the Hypervisor Extension.
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

typedef struct {
    int rd;
    int rs1;
} arg_rvh_load;

typedef struct {
    int rs1;
    int rs2;
} arg_rvh_store;

static bool rvh_check_access(DisasContext *ctx)
{
    if (ctx->hlsx) {
        return true;
    }

    if (ctx->virt_enabled) {
        gen_exception_virtual_instruction(ctx);
    } else {
        gen_exception_illegal(ctx);
    }
    return false;
}

static bool do_hlv(DisasContext *ctx, arg_rvh_load *a, MemOp mop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv dest;
    TCGv addr;
    int mem_idx;

    if (!rvh_check_access(ctx)) {
        return true;
    }

    dest = tcg_temp_new(tcg_ctx);
    addr = tcg_temp_new(tcg_ctx);
    mem_idx = ctx->mem_idx | TB_FLAGS_PRIV_HYP_ACCESS_MASK;

    gen_get_gpr(tcg_ctx, addr, a->rs1);
    tcg_gen_qemu_ld_tl(tcg_ctx, dest, addr, mem_idx, mop);
    gen_set_gpr(tcg_ctx, a->rd, dest);

    tcg_temp_free(tcg_ctx, addr);
    tcg_temp_free(tcg_ctx, dest);
    return true;
}

static bool trans_hlv_b(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlv(ctx, a, MO_SB);
}

static bool trans_hlv_bu(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlv(ctx, a, MO_UB);
}

static bool trans_hlv_h(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlv(ctx, a, MO_TESW);
}

static bool trans_hlv_hu(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlv(ctx, a, MO_TEUW);
}

static bool trans_hlv_w(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlv(ctx, a, MO_TESL);
}

static bool do_hsv(DisasContext *ctx, arg_rvh_store *a, MemOp mop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv data;
    TCGv addr;
    int mem_idx;

    if (!rvh_check_access(ctx)) {
        return true;
    }

    addr = tcg_temp_new(tcg_ctx);
    data = tcg_temp_new(tcg_ctx);
    mem_idx = ctx->mem_idx | TB_FLAGS_PRIV_HYP_ACCESS_MASK;

    gen_get_gpr(tcg_ctx, addr, a->rs1);
    gen_get_gpr(tcg_ctx, data, a->rs2);
    tcg_gen_qemu_st_tl(tcg_ctx, data, addr, mem_idx, mop);

    tcg_temp_free(tcg_ctx, data);
    tcg_temp_free(tcg_ctx, addr);
    return true;
}

static bool trans_hsv_b(DisasContext *ctx, arg_rvh_store *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hsv(ctx, a, MO_SB);
}

static bool trans_hsv_h(DisasContext *ctx, arg_rvh_store *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hsv(ctx, a, MO_TESW);
}

static bool trans_hsv_w(DisasContext *ctx, arg_rvh_store *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hsv(ctx, a, MO_TESL);
}

#ifdef TARGET_RISCV64
static bool trans_hlv_wu(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlv(ctx, a, MO_TEUL);
}

static bool trans_hlv_d(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlv(ctx, a, MO_TEUQ);
}

static bool trans_hsv_d(DisasContext *ctx, arg_rvh_store *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hsv(ctx, a, MO_TEUQ);
}
#endif

static bool do_hlvx(DisasContext *ctx, arg_rvh_load *a,
                    void (*func)(TCGContext *, TCGv, TCGv_env, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv dest;
    TCGv addr;

    if (!rvh_check_access(ctx)) {
        return true;
    }

    dest = tcg_temp_new(tcg_ctx);
    addr = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, addr, a->rs1);
    func(tcg_ctx, dest, tcg_ctx->cpu_env, addr);
    gen_set_gpr(tcg_ctx, a->rd, dest);

    tcg_temp_free(tcg_ctx, addr);
    tcg_temp_free(tcg_ctx, dest);
    return true;
}

static bool trans_hlvx_hu(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlvx(ctx, a, gen_helper_hyp_hlvx_hu);
}

static bool trans_hlvx_wu(DisasContext *ctx, arg_rvh_load *a)
{
    REQUIRE_EXT(ctx, RVH);
    return do_hlvx(ctx, a, gen_helper_hyp_hlvx_wu);
}

static bool decode_rvh(DisasContext *ctx, uint32_t insn)
{
    uint32_t funct7;
    uint32_t rs2;
    uint32_t rs1;
    uint32_t rd;
    arg_rvh_load load;
    arg_rvh_store store;

    if ((insn & 0x707f) != 0x4073) {
        return false;
    }

    funct7 = extract32(insn, 25, 7);
    rs2 = extract32(insn, 20, 5);
    rs1 = extract32(insn, 15, 5);
    rd = extract32(insn, 7, 5);
    load.rd = rd;
    load.rs1 = rs1;
    store.rs1 = rs1;
    store.rs2 = rs2;

    switch (funct7) {
    case 0x30:
        if (rs2 == 0) {
            return trans_hlv_b(ctx, &load);
        } else if (rs2 == 1) {
            return trans_hlv_bu(ctx, &load);
        }
        break;
    case 0x31:
        if (rd == 0) {
            return trans_hsv_b(ctx, &store);
        }
        break;
    case 0x32:
        if (rs2 == 0) {
            return trans_hlv_h(ctx, &load);
        } else if (rs2 == 1) {
            return trans_hlv_hu(ctx, &load);
        } else if (rs2 == 3) {
            return trans_hlvx_hu(ctx, &load);
        }
        break;
    case 0x33:
        if (rd == 0) {
            return trans_hsv_h(ctx, &store);
        }
        break;
    case 0x34:
        if (rs2 == 0) {
            return trans_hlv_w(ctx, &load);
        } else if (rs2 == 3) {
            return trans_hlvx_wu(ctx, &load);
        }
#ifdef TARGET_RISCV64
        else if (rs2 == 1) {
            return trans_hlv_wu(ctx, &load);
        }
#endif
        break;
    case 0x35:
        if (rd == 0) {
            return trans_hsv_w(ctx, &store);
        }
        break;
#ifdef TARGET_RISCV64
    case 0x36:
        if (rs2 == 0) {
            return trans_hlv_d(ctx, &load);
        }
        break;
    case 0x37:
        if (rd == 0) {
            return trans_hsv_d(ctx, &store);
        }
        break;
#endif
    }

    return false;
}
