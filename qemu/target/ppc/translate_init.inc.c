/*
 *  PowerPC CPU initialization for qemu.
 *
 *  Copyright (c) 2003-2007 Jocelyn Mayer
 *  Copyright 2011 Freescale Semiconductor, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "sysemu/cpus.h"
#include "sysemu/tcg.h"
#include "cpu-models.h"
#include "mmu-hash32.h"
#include "mmu-hash64.h"
#include "hw/ppc/ppc.h"
#include "mmu-book3s-v3.h"
#include "qemu/cutils.h"
#include "fpu/softfloat.h"
#include "disas/dis-asm.h"

/*
 * Generic callbacks:
 * do nothing but store/retrieve spr value
 */
static void spr_load_dump_spr(TCGContext *tcg_ctx, int sprn)
{
#ifdef PPC_DUMP_SPR_ACCESSES
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, sprn);
    gen_helper_load_dump_spr(tcg_ctx, tcg_ctx->cpu_env, t0);
    tcg_temp_free_i32(tcg_ctx, t0);
#endif
}

static void spr_read_generic(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_load_spr(tcg_ctx, cpu_gpr[gprn], sprn);
    spr_load_dump_spr(tcg_ctx, sprn);
}

static void spr_store_dump_spr(int sprn)
{
#ifdef PPC_DUMP_SPR_ACCESSES
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, sprn);
    gen_helper_store_dump_spr(tcg_ctx, tcg_ctx->cpu_env, t0);
    tcg_temp_free_i32(tcg_ctx, t0);
#endif
}

static void spr_write_generic(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_store_spr(tcg_ctx, sprn, cpu_gpr[gprn]);
    spr_store_dump_spr(sprn);
}

static void spr_write_generic32(DisasContext *ctx, int sprn, int gprn)
{
#ifdef TARGET_PPC64
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_ext32u_tl(tcg_ctx, t0, cpu_gpr[gprn]);
    gen_store_spr(tcg_ctx, sprn, t0);
    tcg_temp_free(tcg_ctx, t0);
    spr_store_dump_spr(sprn);
#else
    spr_write_generic(ctx, sprn, gprn);
#endif
}

static void spr_write_clear(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv t1 = tcg_temp_new(tcg_ctx);
    gen_load_spr(tcg_ctx, t0, sprn);
    tcg_gen_neg_tl(tcg_ctx, t1, cpu_gpr[gprn]);
    tcg_gen_and_tl(tcg_ctx, t0, t0, t1);
    gen_store_spr(tcg_ctx, sprn, t0);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
}

static void spr_access_nop(DisasContext *ctx, int sprn, int gprn)
{
}

/* SPR common to all PowerPC */
/* XER */
static void spr_read_xer(DisasContext *ctx, int gprn, int sprn)
{
    gen_read_xer(ctx, cpu_gpr[gprn]);
}

static void spr_write_xer(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_write_xer(tcg_ctx, cpu_gpr[gprn]);
}

/* LR */
static void spr_read_lr(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, cpu_gpr[gprn], cpu_lr);
}

static void spr_write_lr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, cpu_lr, cpu_gpr[gprn]);
}

/* CFAR */
#if defined(TARGET_PPC64)
static void spr_read_cfar(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, cpu_gpr[gprn], cpu_cfar);
}

static void spr_write_cfar(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, cpu_cfar, cpu_gpr[gprn]);
}
#endif

/* CTR */
static void spr_read_ctr(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, cpu_gpr[gprn], cpu_ctr);
}

static void spr_write_ctr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, cpu_ctr, cpu_gpr[gprn]);
}

/* User read access to SPR */
/* USPRx */
/* UMMCRx */
/* UPMCx */
/* USIA */
/* UDECR */
static void spr_read_ureg(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_load_spr(tcg_ctx, cpu_gpr[gprn], sprn + 0x10);
}

#if defined(TARGET_PPC64)
static void spr_write_ureg(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_store_spr(tcg_ctx, sprn + 0x10, cpu_gpr[gprn]);
}
#endif

/* SPR common to all non-embedded PowerPC */
/* DECR */
static void spr_read_decr(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_helper_load_decr(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_stop_exception(ctx);
    }
}

static void spr_write_decr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_helper_store_decr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_stop_exception(ctx);
    }
}

/* SPR common to all non-embedded PowerPC, except 601 */
/* Time base */
static void spr_read_tbl(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_helper_load_tbl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
        gen_stop_exception(ctx);
    }
}

static void spr_read_tbu(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_helper_load_tbu(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
        gen_stop_exception(ctx);
    }
}

#if 0
// ATTRIBUTE_UNUSED
static void spr_read_atbl(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_load_atbl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
}

// ATTRIBUTE_UNUSED
static void spr_read_atbu(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_load_atbu(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
}
#endif

static void spr_write_tbl(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_helper_store_tbl(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
        gen_stop_exception(ctx);
    }
}

static void spr_write_tbu(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_helper_store_tbu(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
        gen_stop_exception(ctx);
    }
}

#if 0
// ATTRIBUTE_UNUSED
static void spr_write_atbl(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_atbl(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

// ATTRIBUTE_UNUSED
static void spr_write_atbu(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_atbu(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}
#endif

#if defined(TARGET_PPC64)
// ATTRIBUTE_UNUSED
static void spr_read_purr(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_load_purr(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
}

static void spr_write_purr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_purr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

/* HDECR */
static void spr_read_hdecr(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_helper_load_hdecr(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
        gen_stop_exception(ctx);
    }
}

static void spr_write_hdecr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_helper_store_hdecr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
    if (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
        gen_stop_exception(ctx);
    }
}

static void spr_read_vtb(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_load_vtb(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
}

static void spr_write_vtb(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_vtb(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_write_tbu40(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_tbu40(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

#endif

/* IBAT0U...IBAT0U */
/* IBAT0L...IBAT7L */
static void spr_read_ibat(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_ld_tl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env,
                  offsetof(CPUPPCState,
                           IBAT[sprn & 1][(sprn - SPR_IBAT0U) / 2]));
}

static void spr_read_ibat_h(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_ld_tl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env,
                  offsetof(CPUPPCState,
                           IBAT[sprn & 1][((sprn - SPR_IBAT4U) / 2) + 4]));
}

static void spr_write_ibatu(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, (sprn - SPR_IBAT0U) / 2);
    gen_helper_store_ibatu(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_ibatu_h(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, ((sprn - SPR_IBAT4U) / 2) + 4);
    gen_helper_store_ibatu(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_ibatl(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, (sprn - SPR_IBAT0L) / 2);
    gen_helper_store_ibatl(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_ibatl_h(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, ((sprn - SPR_IBAT4L) / 2) + 4);
    gen_helper_store_ibatl(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

/* DBAT0U...DBAT7U */
/* DBAT0L...DBAT7L */
static void spr_read_dbat(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_ld_tl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env,
                  offsetof(CPUPPCState,
                           DBAT[sprn & 1][(sprn - SPR_DBAT0U) / 2]));
}

static void spr_read_dbat_h(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_ld_tl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env,
                  offsetof(CPUPPCState,
                           DBAT[sprn & 1][((sprn - SPR_DBAT4U) / 2) + 4]));
}

static void spr_write_dbatu(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, (sprn - SPR_DBAT0U) / 2);
    gen_helper_store_dbatu(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_dbatu_h(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, ((sprn - SPR_DBAT4U) / 2) + 4);
    gen_helper_store_dbatu(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_dbatl(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, (sprn - SPR_DBAT0L) / 2);
    gen_helper_store_dbatl(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_dbatl_h(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, ((sprn - SPR_DBAT4L) / 2) + 4);
    gen_helper_store_dbatl(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

/* SDR1 */
static void spr_write_sdr1(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_sdr1(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

#if defined(TARGET_PPC64)
/* 64 bits PowerPC specific SPRs */
/* PIDR */
static void spr_write_pidr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_pidr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_write_lpidr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_lpidr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_read_hior(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_ld_tl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env, offsetof(CPUPPCState, excp_prefix));
}

static void spr_write_hior(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_tl(tcg_ctx, t0, cpu_gpr[gprn], 0x3FFFFF00000ULL);
    tcg_gen_st_tl(tcg_ctx, t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, excp_prefix));
    tcg_temp_free(tcg_ctx, t0);
}
static void spr_write_ptcr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_ptcr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_write_pcr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_pcr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

/* DPDES */
static void spr_read_dpdes(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_load_dpdes(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
}

static void spr_write_dpdes(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_dpdes(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}
#endif

/* PowerPC 601 specific registers */
/* RTC */
static void spr_read_601_rtcl(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_load_601_rtcl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
}

static void spr_read_601_rtcu(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_load_601_rtcu(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
}

static void spr_write_601_rtcu(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_601_rtcu(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_write_601_rtcl(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_601_rtcl(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_write_hid0_601(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_hid0_601(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
    /* Must stop the translation as endianness may have changed */
    gen_stop_exception(ctx);
}

/* Unified bats */
static void spr_read_601_ubat(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_ld_tl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env,
                  offsetof(CPUPPCState,
                           IBAT[sprn & 1][(sprn - SPR_IBAT0U) / 2]));
}

static void spr_write_601_ubatu(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, (sprn - SPR_IBAT0U) / 2);
    gen_helper_store_601_batl(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_601_ubatl(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, (sprn - SPR_IBAT0U) / 2);
    gen_helper_store_601_batu(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

/* PowerPC 40x specific registers */
static void spr_read_40x_pit(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
#ifdef UNICORN_ARCH_POSTFIX
    glue(gen_helper_load_40x_pit, UNICORN_ARCH_POSTFIX)(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
#else
    gen_helper_load_40x_pit(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env);
#endif
}

static void spr_write_40x_pit(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
#ifdef UNICORN_ARCH_POSTFIX
    glue(gen_helper_store_40x_pit, UNICORN_ARCH_POSTFIX)(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
#else
    gen_helper_store_40x_pit(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
#endif
}

static void spr_write_40x_dbcr0(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_store_spr(tcg_ctx, sprn, cpu_gpr[gprn]);
#ifdef UNICORN_ARCH_POSTFIX
    glue(gen_helper_store_40x_dbcr0, UNICORN_ARCH_POSTFIX)(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
#else
    gen_helper_store_40x_dbcr0(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
#endif
    /* We must stop translation as we may have rebooted */
    gen_stop_exception(ctx);
}

static void spr_write_40x_sler(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
#ifdef UNICORN_ARCH_POSTFIX
    glue(gen_helper_store_40x_sler, UNICORN_ARCH_POSTFIX)(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
#else
    gen_helper_store_40x_sler(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
#endif
}

static void spr_write_booke_tcr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_booke_tcr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_write_booke_tsr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_store_booke_tsr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

/* PowerPC 403 specific registers */
/* PBL1 / PBU1 / PBL2 / PBU2 */
static void spr_read_403_pbr(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_ld_tl(tcg_ctx, cpu_gpr[gprn], tcg_ctx->cpu_env,
                  offsetof(CPUPPCState, pb[sprn - SPR_403_PBL1]));
}

static void spr_write_403_pbr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, sprn - SPR_403_PBL1);
    gen_helper_store_403_pbr(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_pir(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_tl(tcg_ctx, t0, cpu_gpr[gprn], 0xF);
    gen_store_spr(tcg_ctx, SPR_PIR, t0);
    tcg_temp_free(tcg_ctx, t0);
}

/* SPE specific registers */
static void spr_read_spefscr(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_ld_i32(tcg_ctx, t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, spe_fscr));
    tcg_gen_extu_i32_tl(tcg_ctx, cpu_gpr[gprn], t0);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_spefscr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_trunc_tl_i32(tcg_ctx, t0, cpu_gpr[gprn]);
    tcg_gen_st_i32(tcg_ctx, t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, spe_fscr));
    tcg_temp_free_i32(tcg_ctx, t0);
}

/* Callback used to write the exception vector base */
static void spr_write_excp_prefix(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_ld_tl(tcg_ctx, t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, ivpr_mask));
    tcg_gen_and_tl(tcg_ctx, t0, t0, cpu_gpr[gprn]);
    tcg_gen_st_tl(tcg_ctx, t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, excp_prefix));
    gen_store_spr(tcg_ctx, sprn, t0);
    tcg_temp_free(tcg_ctx, t0);
}

static void spr_write_excp_vector(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int sprn_offs;

    if (sprn >= SPR_BOOKE_IVOR0 && sprn <= SPR_BOOKE_IVOR15) {
        sprn_offs = sprn - SPR_BOOKE_IVOR0;
    } else if (sprn >= SPR_BOOKE_IVOR32 && sprn <= SPR_BOOKE_IVOR37) {
        sprn_offs = sprn - SPR_BOOKE_IVOR32 + 32;
    } else if (sprn >= SPR_BOOKE_IVOR38 && sprn <= SPR_BOOKE_IVOR42) {
        sprn_offs = sprn - SPR_BOOKE_IVOR38 + 38;
    } else {
        printf("Trying to write an unknown exception vector %d %03x\n",
               sprn, sprn);
        gen_inval_exception(ctx, POWERPC_EXCP_PRIV_REG);
        return;
    }

    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_ld_tl(tcg_ctx, t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, ivor_mask));
    tcg_gen_and_tl(tcg_ctx, t0, t0, cpu_gpr[gprn]);
    tcg_gen_st_tl(tcg_ctx, t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, excp_vectors[sprn_offs]));
    gen_store_spr(tcg_ctx, sprn, t0);
    tcg_temp_free(tcg_ctx, t0);
}

static inline void vscr_init(CPUPPCState *env, uint32_t val)
{
    /* Altivec always uses round-to-nearest */
    set_float_rounding_mode(float_round_nearest_even, &env->vec_status);
    helper_mtvscr(env, val);
}

#define spr_register_kvm(env, num, name, uea_read, uea_write,                  \
                         oea_read, oea_write, one_reg_id, initial_value)       \
    _spr_register(env, num, name, uea_read, uea_write,                         \
                  oea_read, oea_write, oea_read, oea_write, initial_value)
#define spr_register_kvm_hv(env, num, name, uea_read, uea_write,               \
                            oea_read, oea_write, hea_read, hea_write,          \
                            one_reg_id, initial_value)                         \
    _spr_register(env, num, name, uea_read, uea_write,                         \
                  oea_read, oea_write, hea_read, hea_write, initial_value)

#define spr_register(env, num, name, uea_read, uea_write,                      \
                     oea_read, oea_write, initial_value)                       \
    spr_register_kvm(env, num, name, uea_read, uea_write,                      \
                     oea_read, oea_write, 0, initial_value)

#define spr_register_hv(env, num, name, uea_read, uea_write,                   \
                        oea_read, oea_write, hea_read, hea_write,              \
                        initial_value)                                         \
    spr_register_kvm_hv(env, num, name, uea_read, uea_write,                   \
                        oea_read, oea_write, hea_read, hea_write,              \
                        0, initial_value)

static inline void _spr_register(CPUPPCState *env, int num,
                                 const char *name,
                                 void (*uea_read)(DisasContext *ctx,
                                                  int gprn, int sprn),
                                 void (*uea_write)(DisasContext *ctx,
                                                   int sprn, int gprn),
                                 void (*oea_read)(DisasContext *ctx,
                                                  int gprn, int sprn),
                                 void (*oea_write)(DisasContext *ctx,
                                                   int sprn, int gprn),
                                 void (*hea_read)(DisasContext *opaque,
                                                  int gprn, int sprn),
                                 void (*hea_write)(DisasContext *opaque,
                                                   int sprn, int gprn),
#if defined(CONFIG_KVM)
                                 uint64_t one_reg_id,
#endif
                                 target_ulong initial_value)
{
    ppc_spr_t *spr;

    spr = &env->spr_cb[num];
    if (spr->name != NULL || env->spr[num] != 0x00000000 ||
        spr->oea_read != NULL || spr->oea_write != NULL ||
        spr->uea_read != NULL || spr->uea_write != NULL) {
        printf("Error: Trying to register SPR %d (%03x) twice !\n", num, num);
        exit(1);
    }
#if defined(PPC_DEBUG_SPR)
    printf("*** register spr %d (%03x) %s val " TARGET_FMT_lx "\n", num, num,
           name, initial_value);
#endif
    spr->name = name;
    spr->uea_read = uea_read;
    spr->uea_write = uea_write;
    spr->oea_read = oea_read;
    spr->oea_write = oea_write;
    spr->hea_read = hea_read;
    spr->hea_write = hea_write;
#if defined(CONFIG_KVM)
    spr->one_reg_id = one_reg_id,
#endif
    env->spr[num] = spr->default_value = initial_value;
}

/* Generic PowerPC SPRs */
static void gen_spr_generic(CPUPPCState *env)
{
    /* Integer processing */
    spr_register(env, SPR_XER, "XER",
                 &spr_read_xer, &spr_write_xer,
                 &spr_read_xer, &spr_write_xer,
                 0x00000000);
    /* Branch contol */
    spr_register(env, SPR_LR, "LR",
                 &spr_read_lr, &spr_write_lr,
                 &spr_read_lr, &spr_write_lr,
                 0x00000000);
    spr_register(env, SPR_CTR, "CTR",
                 &spr_read_ctr, &spr_write_ctr,
                 &spr_read_ctr, &spr_write_ctr,
                 0x00000000);
    /* Interrupt processing */
    spr_register(env, SPR_SRR0, "SRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SRR1, "SRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Processor control */
    spr_register(env, SPR_SPRG0, "SPRG0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG1, "SPRG1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG2, "SPRG2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG3, "SPRG3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR common to all non-embedded PowerPC, including 601 */
static void gen_spr_ne_601(CPUPPCState *env)
{
    /* Exception processing */
    spr_register_kvm(env, SPR_DSISR, "DSISR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DSISR, 0x00000000);
    spr_register_kvm(env, SPR_DAR, "DAR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DAR, 0x00000000);
    /* Timer */
    spr_register(env, SPR_DECR, "DECR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_decr, &spr_write_decr,
                 0x00000000);
}

/* Storage Description Register 1 */
static void gen_spr_sdr1(CPUPPCState *env)
{
    if (env->has_hv_mode) {
        /*
         * SDR1 is a hypervisor resource on CPUs which have a
         * hypervisor mode
         */
        spr_register_hv(env, SPR_SDR1, "SDR1",
                        SPR_NOACCESS, SPR_NOACCESS,
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_generic, &spr_write_sdr1,
                        0x00000000);
    } else {
        spr_register(env, SPR_SDR1, "SDR1",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_sdr1,
                     0x00000000);
    }
}

/* BATs 0-3 */
static void gen_low_BATs(CPUPPCState *env)
{
    spr_register(env, SPR_IBAT0U, "IBAT0U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat, &spr_write_ibatu,
                 0x00000000);
    spr_register(env, SPR_IBAT0L, "IBAT0L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat, &spr_write_ibatl,
                 0x00000000);
    spr_register(env, SPR_IBAT1U, "IBAT1U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat, &spr_write_ibatu,
                 0x00000000);
    spr_register(env, SPR_IBAT1L, "IBAT1L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat, &spr_write_ibatl,
                 0x00000000);
    spr_register(env, SPR_IBAT2U, "IBAT2U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat, &spr_write_ibatu,
                 0x00000000);
    spr_register(env, SPR_IBAT2L, "IBAT2L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat, &spr_write_ibatl,
                 0x00000000);
    spr_register(env, SPR_IBAT3U, "IBAT3U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat, &spr_write_ibatu,
                 0x00000000);
    spr_register(env, SPR_IBAT3L, "IBAT3L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat, &spr_write_ibatl,
                 0x00000000);
    spr_register(env, SPR_DBAT0U, "DBAT0U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat, &spr_write_dbatu,
                 0x00000000);
    spr_register(env, SPR_DBAT0L, "DBAT0L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat, &spr_write_dbatl,
                 0x00000000);
    spr_register(env, SPR_DBAT1U, "DBAT1U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat, &spr_write_dbatu,
                 0x00000000);
    spr_register(env, SPR_DBAT1L, "DBAT1L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat, &spr_write_dbatl,
                 0x00000000);
    spr_register(env, SPR_DBAT2U, "DBAT2U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat, &spr_write_dbatu,
                 0x00000000);
    spr_register(env, SPR_DBAT2L, "DBAT2L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat, &spr_write_dbatl,
                 0x00000000);
    spr_register(env, SPR_DBAT3U, "DBAT3U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat, &spr_write_dbatu,
                 0x00000000);
    spr_register(env, SPR_DBAT3L, "DBAT3L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat, &spr_write_dbatl,
                 0x00000000);
    env->nb_BATs += 4;
}

/* BATs 4-7 */
static void gen_high_BATs(CPUPPCState *env)
{
    spr_register(env, SPR_IBAT4U, "IBAT4U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat_h, &spr_write_ibatu_h,
                 0x00000000);
    spr_register(env, SPR_IBAT4L, "IBAT4L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat_h, &spr_write_ibatl_h,
                 0x00000000);
    spr_register(env, SPR_IBAT5U, "IBAT5U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat_h, &spr_write_ibatu_h,
                 0x00000000);
    spr_register(env, SPR_IBAT5L, "IBAT5L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat_h, &spr_write_ibatl_h,
                 0x00000000);
    spr_register(env, SPR_IBAT6U, "IBAT6U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat_h, &spr_write_ibatu_h,
                 0x00000000);
    spr_register(env, SPR_IBAT6L, "IBAT6L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat_h, &spr_write_ibatl_h,
                 0x00000000);
    spr_register(env, SPR_IBAT7U, "IBAT7U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat_h, &spr_write_ibatu_h,
                 0x00000000);
    spr_register(env, SPR_IBAT7L, "IBAT7L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_ibat_h, &spr_write_ibatl_h,
                 0x00000000);
    spr_register(env, SPR_DBAT4U, "DBAT4U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat_h, &spr_write_dbatu_h,
                 0x00000000);
    spr_register(env, SPR_DBAT4L, "DBAT4L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat_h, &spr_write_dbatl_h,
                 0x00000000);
    spr_register(env, SPR_DBAT5U, "DBAT5U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat_h, &spr_write_dbatu_h,
                 0x00000000);
    spr_register(env, SPR_DBAT5L, "DBAT5L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat_h, &spr_write_dbatl_h,
                 0x00000000);
    spr_register(env, SPR_DBAT6U, "DBAT6U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat_h, &spr_write_dbatu_h,
                 0x00000000);
    spr_register(env, SPR_DBAT6L, "DBAT6L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat_h, &spr_write_dbatl_h,
                 0x00000000);
    spr_register(env, SPR_DBAT7U, "DBAT7U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat_h, &spr_write_dbatu_h,
                 0x00000000);
    spr_register(env, SPR_DBAT7L, "DBAT7L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_dbat_h, &spr_write_dbatl_h,
                 0x00000000);
    env->nb_BATs += 4;
}

/* Generic PowerPC time base */
static void gen_tbl(CPUPPCState *env)
{
    spr_register(env, SPR_VTBL,  "TBL",
                 &spr_read_tbl, SPR_NOACCESS,
                 &spr_read_tbl, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_TBL,   "TBL",
                 &spr_read_tbl, SPR_NOACCESS,
                 &spr_read_tbl, &spr_write_tbl,
                 0x00000000);
    spr_register(env, SPR_VTBU,  "TBU",
                 &spr_read_tbu, SPR_NOACCESS,
                 &spr_read_tbu, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_TBU,   "TBU",
                 &spr_read_tbu, SPR_NOACCESS,
                 &spr_read_tbu, &spr_write_tbu,
                 0x00000000);
}

/* Softare table search registers */
static void gen_6xx_7xx_soft_tlb(CPUPPCState *env, int nb_tlbs, int nb_ways)
{
    env->nb_tlb = nb_tlbs;
    env->nb_ways = nb_ways;
    env->id_tlbs = 1;
    env->tlb_type = TLB_6XX;
    spr_register(env, SPR_DMISS, "DMISS",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_DCMP, "DCMP",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_HASH1, "HASH1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_HASH2, "HASH2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_IMISS, "IMISS",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_ICMP, "ICMP",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_RPA, "RPA",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR common to MPC755 and G2 */
static void gen_spr_G2_755(CPUPPCState *env)
{
    /* SGPRs */
    spr_register(env, SPR_SPRG4, "SPRG4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG5, "SPRG5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG6, "SPRG6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG7, "SPRG7",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR common to all 7xx PowerPC implementations */
static void gen_spr_7xx(CPUPPCState *env)
{
    /* Breakpoints */
    /* XXX : not implemented */
    spr_register_kvm(env, SPR_DABR, "DABR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DABR, 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_IABR, "IABR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Cache management */
    /* XXX : not implemented */
    spr_register(env, SPR_ICTC, "ICTC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Performance monitors */
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_MMCR0, "MMCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_MMCR1, "MMCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC1, "PMC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC2, "PMC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC3, "PMC3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC4, "PMC4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_SIAR, "SIAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UMMCR0, "UMMCR0",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UMMCR1, "UMMCR1",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC1, "UPMC1",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC2, "UPMC2",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC3, "UPMC3",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC4, "UPMC4",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_USIAR, "USIAR",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* External access control */
    /* XXX : not implemented */
    spr_register(env, SPR_EAR, "EAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

#ifdef TARGET_PPC64
static void spr_write_amr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv t1 = tcg_temp_new(tcg_ctx);
    TCGv t2 = tcg_temp_new(tcg_ctx);

    /*
     * Note, the HV=1 PR=0 case is handled earlier by simply using
     * spr_write_generic for HV mode in the SPR table
     */

    /* Build insertion mask into t1 based on context */
    if (ctx->pr) {
        gen_load_spr(tcg_ctx, t1, SPR_UAMOR);
    } else {
        gen_load_spr(tcg_ctx, t1, SPR_AMOR);
    }

    /* Mask new bits into t2 */
    tcg_gen_and_tl(tcg_ctx, t2, t1, cpu_gpr[gprn]);

    /* Load AMR and clear new bits in t0 */
    gen_load_spr(tcg_ctx, t0, SPR_AMR);
    tcg_gen_andc_tl(tcg_ctx, t0, t0, t1);

    /* Or'in new bits and write it out */
    tcg_gen_or_tl(tcg_ctx, t0, t0, t2);
    gen_store_spr(tcg_ctx, SPR_AMR, t0);
    spr_store_dump_spr(SPR_AMR);

    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t2);
}

static void spr_write_uamor(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv t1 = tcg_temp_new(tcg_ctx);
    TCGv t2 = tcg_temp_new(tcg_ctx);

    /*
     * Note, the HV=1 case is handled earlier by simply using
     * spr_write_generic for HV mode in the SPR table
     */

    /* Build insertion mask into t1 based on context */
    gen_load_spr(tcg_ctx, t1, SPR_AMOR);

    /* Mask new bits into t2 */
    tcg_gen_and_tl(tcg_ctx, t2, t1, cpu_gpr[gprn]);

    /* Load AMR and clear new bits in t0 */
    gen_load_spr(tcg_ctx, t0, SPR_UAMOR);
    tcg_gen_andc_tl(tcg_ctx, t0, t0, t1);

    /* Or'in new bits and write it out */
    tcg_gen_or_tl(tcg_ctx, t0, t0, t2);
    gen_store_spr(tcg_ctx, SPR_UAMOR, t0);
    spr_store_dump_spr(SPR_UAMOR);

    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t2);
}

static void spr_write_iamr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv t1 = tcg_temp_new(tcg_ctx);
    TCGv t2 = tcg_temp_new(tcg_ctx);

    /*
     * Note, the HV=1 case is handled earlier by simply using
     * spr_write_generic for HV mode in the SPR table
     */

    /* Build insertion mask into t1 based on context */
    gen_load_spr(tcg_ctx, t1, SPR_AMOR);

    /* Mask new bits into t2 */
    tcg_gen_and_tl(tcg_ctx, t2, t1, cpu_gpr[gprn]);

    /* Load AMR and clear new bits in t0 */
    gen_load_spr(tcg_ctx, t0, SPR_IAMR);
    tcg_gen_andc_tl(tcg_ctx, t0, t0, t1);

    /* Or'in new bits and write it out */
    tcg_gen_or_tl(tcg_ctx, t0, t0, t2);
    gen_store_spr(tcg_ctx, SPR_IAMR, t0);
    spr_store_dump_spr(SPR_IAMR);

    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t2);
}

static void gen_spr_amr(CPUPPCState *env)
{
    /*
     * Virtual Page Class Key protection
     *
     * The AMR is accessible either via SPR 13 or SPR 29.  13 is
     * userspace accessible, 29 is privileged.  So we only need to set
     * the kvm ONE_REG id on one of them, we use 29
     */
    spr_register(env, SPR_UAMR, "UAMR",
                 &spr_read_generic, &spr_write_amr,
                 &spr_read_generic, &spr_write_amr,
                 0);
    spr_register_kvm_hv(env, SPR_AMR, "AMR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_amr,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_AMR, 0);
    spr_register_kvm_hv(env, SPR_UAMOR, "UAMOR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_uamor,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_UAMOR, 0);
    spr_register_hv(env, SPR_AMOR, "AMOR",
                    SPR_NOACCESS, SPR_NOACCESS,
                    SPR_NOACCESS, SPR_NOACCESS,
                    &spr_read_generic, &spr_write_generic,
                    0);
}

static void gen_spr_iamr(CPUPPCState *env)
{
    spr_register_kvm_hv(env, SPR_IAMR, "IAMR",
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_generic, &spr_write_iamr,
                        &spr_read_generic, &spr_write_generic,
                        KVM_REG_PPC_IAMR, 0);
}
#endif /* TARGET_PPC64 */

static void spr_read_thrm(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_fixup_thrm(tcg_ctx, tcg_ctx->cpu_env);
    gen_load_spr(tcg_ctx, cpu_gpr[gprn], sprn);
    spr_load_dump_spr(tcg_ctx, sprn);
}

static void gen_spr_thrm(CPUPPCState *env)
{
    /* Thermal management */
    /* XXX : not implemented */
    spr_register(env, SPR_THRM1, "THRM1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_thrm, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_THRM2, "THRM2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_thrm, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_THRM3, "THRM3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_thrm, &spr_write_generic,
                 0x00000000);
}

/* SPR specific to PowerPC 604 implementation */
static void gen_spr_604(CPUPPCState *env)
{
    /* Processor identification */
    spr_register(env, SPR_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pir,
                 0x00000000);
    /* Breakpoints */
    /* XXX : not implemented */
    spr_register(env, SPR_IABR, "IABR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register_kvm(env, SPR_DABR, "DABR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DABR, 0x00000000);
    /* Performance counters */
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_MMCR0, "MMCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC1, "PMC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC2, "PMC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_SIAR, "SIAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_SDA, "SDA",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* External access control */
    /* XXX : not implemented */
    spr_register(env, SPR_EAR, "EAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR specific to PowerPC 603 implementation */
static void gen_spr_603(CPUPPCState *env)
{
    /* External access control */
    /* XXX : not implemented */
    spr_register(env, SPR_EAR, "EAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Breakpoints */
    /* XXX : not implemented */
    spr_register(env, SPR_IABR, "IABR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);

}

/* SPR specific to PowerPC G2 implementation */
static void gen_spr_G2(CPUPPCState *env)
{
    /* Memory base address */
    /* MBAR */
    /* XXX : not implemented */
    spr_register(env, SPR_MBAR, "MBAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Exception processing */
    spr_register(env, SPR_BOOKE_CSRR0, "CSRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_CSRR1, "CSRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Breakpoints */
    /* XXX : not implemented */
    spr_register(env, SPR_DABR, "DABR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_DABR2, "DABR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_IABR, "IABR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_IABR2, "IABR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_IBCR, "IBCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_DBCR, "DBCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR specific to PowerPC 602 implementation */
static void gen_spr_602(CPUPPCState *env)
{
    /* ESA registers */
    /* XXX : not implemented */
    spr_register(env, SPR_SER, "SER",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_SEBR, "SEBR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_ESASRR, "ESASRR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Floating point status */
    /* XXX : not implemented */
    spr_register(env, SPR_SP, "SP",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_LT, "LT",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Watchdog timer */
    /* XXX : not implemented */
    spr_register(env, SPR_TCR, "TCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Interrupt base */
    spr_register(env, SPR_IBR, "IBR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_IABR, "IABR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR specific to PowerPC 601 implementation */
static void gen_spr_601(CPUPPCState *env)
{
    /* Multiplication/division register */
    /* MQ */
    spr_register(env, SPR_MQ, "MQ",
                 &spr_read_generic, &spr_write_generic,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* RTC registers */
    spr_register(env, SPR_601_RTCU, "RTCU",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, &spr_write_601_rtcu,
                 0x00000000);
    spr_register(env, SPR_601_VRTCU, "RTCU",
                 &spr_read_601_rtcu, SPR_NOACCESS,
                 &spr_read_601_rtcu, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_601_RTCL, "RTCL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, &spr_write_601_rtcl,
                 0x00000000);
    spr_register(env, SPR_601_VRTCL, "RTCL",
                 &spr_read_601_rtcl, SPR_NOACCESS,
                 &spr_read_601_rtcl, SPR_NOACCESS,
                 0x00000000);
    /* Timer */
    spr_register(env, SPR_601_UDECR, "UDECR",
                 &spr_read_decr, SPR_NOACCESS,
                 &spr_read_decr, SPR_NOACCESS,
                 0x00000000);
    /* External access control */
    /* XXX : not implemented */
    spr_register(env, SPR_EAR, "EAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    spr_register(env, SPR_IBAT0U, "IBAT0U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_601_ubat, &spr_write_601_ubatu,
                 0x00000000);
    spr_register(env, SPR_IBAT0L, "IBAT0L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_601_ubat, &spr_write_601_ubatl,
                 0x00000000);
    spr_register(env, SPR_IBAT1U, "IBAT1U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_601_ubat, &spr_write_601_ubatu,
                 0x00000000);
    spr_register(env, SPR_IBAT1L, "IBAT1L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_601_ubat, &spr_write_601_ubatl,
                 0x00000000);
    spr_register(env, SPR_IBAT2U, "IBAT2U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_601_ubat, &spr_write_601_ubatu,
                 0x00000000);
    spr_register(env, SPR_IBAT2L, "IBAT2L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_601_ubat, &spr_write_601_ubatl,
                 0x00000000);
    spr_register(env, SPR_IBAT3U, "IBAT3U",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_601_ubat, &spr_write_601_ubatu,
                 0x00000000);
    spr_register(env, SPR_IBAT3L, "IBAT3L",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_601_ubat, &spr_write_601_ubatl,
                 0x00000000);
    env->nb_BATs = 4;
}

static void gen_spr_74xx(CPUPPCState *env)
{
    /* Processor identification */
    spr_register(env, SPR_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pir,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_74XX_MMCR2, "MMCR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_74XX_UMMCR2, "UMMCR2",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX: not implemented */
    spr_register(env, SPR_BAMR, "BAMR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MSSCR0, "MSSCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Altivec */
    spr_register(env, SPR_VRSAVE, "VRSAVE",
                 &spr_read_generic, &spr_write_generic,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_L2CR, "L2CR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, spr_access_nop,
                 0x00000000);
    /* Not strictly an SPR */
    vscr_init(env, 0x00010000);
}

static void gen_l3_ctrl(CPUPPCState *env)
{
    /* L3CR */
    /* XXX : not implemented */
    spr_register(env, SPR_L3CR, "L3CR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* L3ITCR0 */
    /* XXX : not implemented */
    spr_register(env, SPR_L3ITCR0, "L3ITCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* L3PM */
    /* XXX : not implemented */
    spr_register(env, SPR_L3PM, "L3PM",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_74xx_soft_tlb(CPUPPCState *env, int nb_tlbs, int nb_ways)
{
    env->nb_tlb = nb_tlbs;
    env->nb_ways = nb_ways;
    env->id_tlbs = 1;
    env->tlb_type = TLB_6XX;
    /* XXX : not implemented */
    spr_register(env, SPR_PTEHI, "PTEHI",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_PTELO, "PTELO",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_TLBMISS, "TLBMISS",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void spr_write_e500_l1csr0(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    tcg_gen_andi_tl(tcg_ctx, t0, cpu_gpr[gprn], L1CSR0_DCE | L1CSR0_CPE);
    gen_store_spr(tcg_ctx, sprn, t0);
    tcg_temp_free(tcg_ctx, t0);
}

static void spr_write_e500_l1csr1(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    tcg_gen_andi_tl(tcg_ctx, t0, cpu_gpr[gprn], L1CSR1_ICE | L1CSR1_CPE);
    gen_store_spr(tcg_ctx, sprn, t0);
    tcg_temp_free(tcg_ctx, t0);
}

static void spr_write_booke206_mmucsr0(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_booke206_tlbflush(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_write_booke_pid(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx, sprn);
    gen_helper_booke_setpid(tcg_ctx, tcg_ctx->cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void spr_write_eplc(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_booke_set_eplc(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void spr_write_epsc(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    gen_helper_booke_set_epsc(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void gen_spr_usprg3(CPUPPCState *env)
{
    spr_register(env, SPR_USPRG3, "USPRG3",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
}

static void gen_spr_usprgh(CPUPPCState *env)
{
    spr_register(env, SPR_USPRG4, "USPRG4",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_USPRG5, "USPRG5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_USPRG6, "USPRG6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_USPRG7, "USPRG7",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
}

/* PowerPC BookE SPR */
static void gen_spr_BookE(CPUPPCState *env, uint64_t ivor_mask)
{
    const char *ivor_names[64] = {
        "IVOR0",  "IVOR1",  "IVOR2",  "IVOR3",
        "IVOR4",  "IVOR5",  "IVOR6",  "IVOR7",
        "IVOR8",  "IVOR9",  "IVOR10", "IVOR11",
        "IVOR12", "IVOR13", "IVOR14", "IVOR15",
        "IVOR16", "IVOR17", "IVOR18", "IVOR19",
        "IVOR20", "IVOR21", "IVOR22", "IVOR23",
        "IVOR24", "IVOR25", "IVOR26", "IVOR27",
        "IVOR28", "IVOR29", "IVOR30", "IVOR31",
        "IVOR32", "IVOR33", "IVOR34", "IVOR35",
        "IVOR36", "IVOR37", "IVOR38", "IVOR39",
        "IVOR40", "IVOR41", "IVOR42", "IVOR43",
        "IVOR44", "IVOR45", "IVOR46", "IVOR47",
        "IVOR48", "IVOR49", "IVOR50", "IVOR51",
        "IVOR52", "IVOR53", "IVOR54", "IVOR55",
        "IVOR56", "IVOR57", "IVOR58", "IVOR59",
        "IVOR60", "IVOR61", "IVOR62", "IVOR63",
    };
#define SPR_BOOKE_IVORxx (-1)
    int ivor_sprn[64] = {
        SPR_BOOKE_IVOR0,  SPR_BOOKE_IVOR1,  SPR_BOOKE_IVOR2,  SPR_BOOKE_IVOR3,
        SPR_BOOKE_IVOR4,  SPR_BOOKE_IVOR5,  SPR_BOOKE_IVOR6,  SPR_BOOKE_IVOR7,
        SPR_BOOKE_IVOR8,  SPR_BOOKE_IVOR9,  SPR_BOOKE_IVOR10, SPR_BOOKE_IVOR11,
        SPR_BOOKE_IVOR12, SPR_BOOKE_IVOR13, SPR_BOOKE_IVOR14, SPR_BOOKE_IVOR15,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVOR32, SPR_BOOKE_IVOR33, SPR_BOOKE_IVOR34, SPR_BOOKE_IVOR35,
        SPR_BOOKE_IVOR36, SPR_BOOKE_IVOR37, SPR_BOOKE_IVOR38, SPR_BOOKE_IVOR39,
        SPR_BOOKE_IVOR40, SPR_BOOKE_IVOR41, SPR_BOOKE_IVOR42, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
        SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx, SPR_BOOKE_IVORxx,
    };
    int i;

    /* Interrupt processing */
    spr_register(env, SPR_BOOKE_CSRR0, "CSRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_CSRR1, "CSRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Debug */
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC1, "IAC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC2, "IAC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DAC1, "DAC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DAC2, "DAC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DBCR0, "DBCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_40x_dbcr0,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DBCR1, "DBCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DBCR2, "DBCR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_DSRR0, "DSRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_DSRR1, "DSRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DBSR, "DBSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_clear,
                 0x00000000);
    spr_register(env, SPR_BOOKE_DEAR, "DEAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_ESR, "ESR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_IVPR, "IVPR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_excp_prefix,
                 0x00000000);
    /* Exception vectors */
    for (i = 0; i < 64; i++) {
        if (ivor_mask & (1ULL << i)) {
            if (ivor_sprn[i] == SPR_BOOKE_IVORxx) {
                fprintf(stderr, "ERROR: IVOR %d SPR is not defined\n", i);
                exit(1);
            }
            spr_register(env, ivor_sprn[i], ivor_names[i],
                         SPR_NOACCESS, SPR_NOACCESS,
                         &spr_read_generic, &spr_write_excp_vector,
                         0x00000000);
        }
    }
    spr_register(env, SPR_BOOKE_PID, "PID",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_booke_pid,
                 0x00000000);
    spr_register(env, SPR_BOOKE_TCR, "TCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_booke_tcr,
                 0x00000000);
    spr_register(env, SPR_BOOKE_TSR, "TSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_booke_tsr,
                 0x00000000);
    /* Timer */
    spr_register(env, SPR_DECR, "DECR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_decr, &spr_write_decr,
                 0x00000000);
    spr_register(env, SPR_BOOKE_DECAR, "DECAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, &spr_write_generic,
                 0x00000000);
    /* SPRGs */
    spr_register(env, SPR_USPRG0, "USPRG0",
                 &spr_read_generic, &spr_write_generic,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG4, "SPRG4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG5, "SPRG5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG6, "SPRG6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG7, "SPRG7",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_SPRG8, "SPRG8",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_SPRG9, "SPRG9",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static inline uint32_t gen_tlbncfg(uint32_t assoc, uint32_t minsize,
                                   uint32_t maxsize, uint32_t flags,
                                   uint32_t nentries)
{
    return (assoc << TLBnCFG_ASSOC_SHIFT) |
           (minsize << TLBnCFG_MINSIZE_SHIFT) |
           (maxsize << TLBnCFG_MAXSIZE_SHIFT) |
           flags | nentries;
}

/* BookE 2.06 storage control registers */
static void gen_spr_BookE206(CPUPPCState *env, uint32_t mas_mask,
                             uint32_t *tlbncfg, uint32_t mmucfg)
{
    const char *mas_names[8] = {
        "MAS0", "MAS1", "MAS2", "MAS3", "MAS4", "MAS5", "MAS6", "MAS7",
    };
    int mas_sprn[8] = {
        SPR_BOOKE_MAS0, SPR_BOOKE_MAS1, SPR_BOOKE_MAS2, SPR_BOOKE_MAS3,
        SPR_BOOKE_MAS4, SPR_BOOKE_MAS5, SPR_BOOKE_MAS6, SPR_BOOKE_MAS7,
    };
    int i;

    /* TLB assist registers */
    /* XXX : not implemented */
    for (i = 0; i < 8; i++) {
        void (*uea_write)(DisasContext *ctx, int sprn, int gprn) =
            &spr_write_generic32;
        if (i == 2 && (mas_mask & (1 << i)) && (env->insns_flags & PPC_64B)) {
            uea_write = &spr_write_generic;
        }
        if (mas_mask & (1 << i)) {
            spr_register(env, mas_sprn[i], mas_names[i],
                         SPR_NOACCESS, SPR_NOACCESS,
                         &spr_read_generic, uea_write,
                         0x00000000);
        }
    }
    if (env->nb_pids > 1) {
        /* XXX : not implemented */
        spr_register(env, SPR_BOOKE_PID1, "PID1",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_booke_pid,
                     0x00000000);
    }
    if (env->nb_pids > 2) {
        /* XXX : not implemented */
        spr_register(env, SPR_BOOKE_PID2, "PID2",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_booke_pid,
                     0x00000000);
    }

    spr_register(env, SPR_BOOKE_EPLC, "EPLC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_eplc,
                 0x00000000);
    spr_register(env, SPR_BOOKE_EPSC, "EPSC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_epsc,
                 0x00000000);

    /* XXX : not implemented */
    spr_register(env, SPR_MMUCFG, "MMUCFG",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 mmucfg);
    switch (env->nb_ways) {
    case 4:
        spr_register(env, SPR_BOOKE_TLB3CFG, "TLB3CFG",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, SPR_NOACCESS,
                     tlbncfg[3]);
        /* Fallthru */
    case 3:
        spr_register(env, SPR_BOOKE_TLB2CFG, "TLB2CFG",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, SPR_NOACCESS,
                     tlbncfg[2]);
        /* Fallthru */
    case 2:
        spr_register(env, SPR_BOOKE_TLB1CFG, "TLB1CFG",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, SPR_NOACCESS,
                     tlbncfg[1]);
        /* Fallthru */
    case 1:
        spr_register(env, SPR_BOOKE_TLB0CFG, "TLB0CFG",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, SPR_NOACCESS,
                     tlbncfg[0]);
        /* Fallthru */
    case 0:
    default:
        break;
    }

    gen_spr_usprgh(env);
}

/* SPR specific to PowerPC 440 implementation */
static void gen_spr_440(CPUPPCState *env)
{
    /* Cache control */
    /* XXX : not implemented */
    spr_register(env, SPR_440_DNV0, "DNV0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DNV1, "DNV1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DNV2, "DNV2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DNV3, "DNV3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DTV0, "DTV0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DTV1, "DTV1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DTV2, "DTV2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DTV3, "DTV3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DVLIM, "DVLIM",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_INV0, "INV0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_INV1, "INV1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_INV2, "INV2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_INV3, "INV3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_ITV0, "ITV0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_ITV1, "ITV1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_ITV2, "ITV2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_ITV3, "ITV3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_IVLIM, "IVLIM",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Cache debug */
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DCDBTRH, "DCDBTRH",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DCDBTRL, "DCDBTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_ICDBDR, "ICDBDR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_ICDBTRH, "ICDBTRH",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_ICDBTRL, "ICDBTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_DBDR, "DBDR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Processor control */
    spr_register(env, SPR_4xx_CCR0, "CCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_440_RSTCFG, "RSTCFG",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* Storage control */
    spr_register(env, SPR_440_MMUCR, "MMUCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR shared between PowerPC 40x implementations */
static void gen_spr_40x(CPUPPCState *env)
{
    /* Cache */
    /* not emulated, as QEMU do not emulate caches */
    spr_register(env, SPR_40x_DCCR, "DCCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* not emulated, as QEMU do not emulate caches */
    spr_register(env, SPR_40x_ICCR, "ICCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* not emulated, as QEMU do not emulate caches */
    spr_register(env, SPR_BOOKE_ICDBDR, "ICDBDR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* Exception */
    spr_register(env, SPR_40x_DEAR, "DEAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_40x_ESR, "ESR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_40x_EVPR, "EVPR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_excp_prefix,
                 0x00000000);
    spr_register(env, SPR_40x_SRR2, "SRR2",
                 &spr_read_generic, &spr_write_generic,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_40x_SRR3, "SRR3",
                 &spr_read_generic, &spr_write_generic,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Timers */
    spr_register(env, SPR_40x_PIT, "PIT",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_40x_pit, &spr_write_40x_pit,
                 0x00000000);
    spr_register(env, SPR_40x_TCR, "TCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_booke_tcr,
                 0x00000000);
    spr_register(env, SPR_40x_TSR, "TSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_booke_tsr,
                 0x00000000);
}

/* SPR specific to PowerPC 405 implementation */
static void gen_spr_405(CPUPPCState *env)
{
    /* MMU */
    spr_register(env, SPR_40x_PID, "PID",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_4xx_CCR0, "CCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00700000);
    /* Debug interface */
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DBCR0, "DBCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_40x_dbcr0,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_405_DBCR1, "DBCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DBSR, "DBSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_clear,
                 /* Last reset was system reset */
                 0x00000300);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DAC1, "DAC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_40x_DAC2, "DAC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_405_DVC1, "DVC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_405_DVC2, "DVC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_IAC1, "IAC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_40x_IAC2, "IAC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_405_IAC3, "IAC3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_405_IAC4, "IAC4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Storage control */
    /* XXX: TODO: not implemented */
    spr_register(env, SPR_405_SLER, "SLER",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_40x_sler,
                 0x00000000);
    spr_register(env, SPR_40x_ZPR, "ZPR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_405_SU0R, "SU0R",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* SPRG */
    spr_register(env, SPR_USPRG0, "USPRG0",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG4, "SPRG4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG5, "SPRG5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG6, "SPRG6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_SPRG7, "SPRG7",
                 SPR_NOACCESS, SPR_NOACCESS,
                 spr_read_generic, &spr_write_generic,
                 0x00000000);
    gen_spr_usprgh(env);
}

/* SPR shared between PowerPC 401 & 403 implementations */
static void gen_spr_401_403(CPUPPCState *env)
{
    /* Time base */
    spr_register(env, SPR_403_VTBL,  "TBL",
                 &spr_read_tbl, SPR_NOACCESS,
                 &spr_read_tbl, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_403_TBL,   "TBL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, &spr_write_tbl,
                 0x00000000);
    spr_register(env, SPR_403_VTBU,  "TBU",
                 &spr_read_tbu, SPR_NOACCESS,
                 &spr_read_tbu, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_403_TBU,   "TBU",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, &spr_write_tbu,
                 0x00000000);
    /* Debug */
    /* not emulated, as QEMU do not emulate caches */
    spr_register(env, SPR_403_CDBCR, "CDBCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR specific to PowerPC 401 implementation */
static void gen_spr_401(CPUPPCState *env)
{
    /* Debug interface */
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DBCR0, "DBCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_40x_dbcr0,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DBSR, "DBSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_clear,
                 /* Last reset was system reset */
                 0x00000300);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DAC1, "DAC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_IAC1, "IAC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Storage control */
    /* XXX: TODO: not implemented */
    spr_register(env, SPR_405_SLER, "SLER",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_40x_sler,
                 0x00000000);
    /* not emulated, as QEMU never does speculative access */
    spr_register(env, SPR_40x_SGR, "SGR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0xFFFFFFFF);
    /* not emulated, as QEMU do not emulate caches */
    spr_register(env, SPR_40x_DCWR, "DCWR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_401x2(CPUPPCState *env)
{
    gen_spr_401(env);
    spr_register(env, SPR_40x_PID, "PID",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_40x_ZPR, "ZPR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR specific to PowerPC 403 implementation */
static void gen_spr_403(CPUPPCState *env)
{
    /* Debug interface */
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DBCR0, "DBCR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_40x_dbcr0,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DBSR, "DBSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_clear,
                 /* Last reset was system reset */
                 0x00000300);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DAC1, "DAC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_DAC2, "DAC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_IAC1, "IAC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_40x_IAC2, "IAC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_403_real(CPUPPCState *env)
{
    spr_register(env, SPR_403_PBL1,  "PBL1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_403_pbr, &spr_write_403_pbr,
                 0x00000000);
    spr_register(env, SPR_403_PBU1,  "PBU1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_403_pbr, &spr_write_403_pbr,
                 0x00000000);
    spr_register(env, SPR_403_PBL2,  "PBL2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_403_pbr, &spr_write_403_pbr,
                 0x00000000);
    spr_register(env, SPR_403_PBU2,  "PBU2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_403_pbr, &spr_write_403_pbr,
                 0x00000000);
}

static void gen_spr_403_mmu(CPUPPCState *env)
{
    /* MMU */
    spr_register(env, SPR_40x_PID, "PID",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_40x_ZPR, "ZPR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

/* SPR specific to PowerPC compression coprocessor extension */
static void gen_spr_compress(CPUPPCState *env)
{
    /* XXX : not implemented */
    spr_register(env, SPR_401_SKR, "SKR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

#if defined(TODO_USER_ONLY)
static void gen_spr_5xx_8xx(CPUPPCState *env)
{
    /* Exception processing */
    spr_register_kvm(env, SPR_DSISR, "DSISR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DSISR, 0x00000000);
    spr_register_kvm(env, SPR_DAR, "DAR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DAR, 0x00000000);
    /* Timer */
    spr_register(env, SPR_DECR, "DECR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_decr, &spr_write_decr,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_EIE, "EIE",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_EID, "EID",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_NRI, "NRI",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_CMPA, "CMPA",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_CMPB, "CMPB",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_CMPC, "CMPC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_CMPD, "CMPD",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_ECR, "ECR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_DER, "DER",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_COUNTA, "COUNTA",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_COUNTB, "COUNTB",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_CMPE, "CMPE",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_CMPF, "CMPF",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_CMPG, "CMPG",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_CMPH, "CMPH",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_LCTRL1, "LCTRL1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_LCTRL2, "LCTRL2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_BAR, "BAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_DPDR, "DPDR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_IMMR, "IMMR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_5xx(CPUPPCState *env)
{
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_GRA, "MI_GRA",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_GRA, "L2U_GRA",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RPCU_BBCMCR, "L2U_BBCMCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_MCR, "L2U_MCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_RBA0, "MI_RBA0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_RBA1, "MI_RBA1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_RBA2, "MI_RBA2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_RBA3, "MI_RBA3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_RBA0, "L2U_RBA0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_RBA1, "L2U_RBA1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_RBA2, "L2U_RBA2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_RBA3, "L2U_RBA3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_RA0, "MI_RA0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_RA1, "MI_RA1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_RA2, "MI_RA2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_MI_RA3, "MI_RA3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_RA0, "L2U_RA0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_RA1, "L2U_RA1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_RA2, "L2U_RA2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_L2U_RA3, "L2U_RA3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_RCPU_FPECR, "FPECR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_8xx(CPUPPCState *env)
{
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_IC_CST, "IC_CST",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_IC_ADR, "IC_ADR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_IC_DAT, "IC_DAT",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_DC_CST, "DC_CST",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_DC_ADR, "DC_ADR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_DC_DAT, "DC_DAT",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MI_CTR, "MI_CTR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MI_AP, "MI_AP",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MI_EPN, "MI_EPN",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MI_TWC, "MI_TWC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MI_RPN, "MI_RPN",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MI_DBCAM, "MI_DBCAM",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MI_DBRAM0, "MI_DBRAM0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MI_DBRAM1, "MI_DBRAM1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_CTR, "MD_CTR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_CASID, "MD_CASID",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_AP, "MD_AP",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_EPN, "MD_EPN",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_TWB, "MD_TWB",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_TWC, "MD_TWC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_RPN, "MD_RPN",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_TW, "MD_TW",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_DBCAM, "MD_DBCAM",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_DBRAM0, "MD_DBRAM0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MPC_MD_DBRAM1, "MD_DBRAM1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}
#endif

/*
 * AMR     => SPR 29 (Power 2.04)
 * CTRL    => SPR 136 (Power 2.04)
 * CTRL    => SPR 152 (Power 2.04)
 * SCOMC   => SPR 276 (64 bits ?)
 * SCOMD   => SPR 277 (64 bits ?)
 * TBU40   => SPR 286 (Power 2.04 hypv)
 * HSPRG0  => SPR 304 (Power 2.04 hypv)
 * HSPRG1  => SPR 305 (Power 2.04 hypv)
 * HDSISR  => SPR 306 (Power 2.04 hypv)
 * HDAR    => SPR 307 (Power 2.04 hypv)
 * PURR    => SPR 309 (Power 2.04 hypv)
 * HDEC    => SPR 310 (Power 2.04 hypv)
 * HIOR    => SPR 311 (hypv)
 * RMOR    => SPR 312 (970)
 * HRMOR   => SPR 313 (Power 2.04 hypv)
 * HSRR0   => SPR 314 (Power 2.04 hypv)
 * HSRR1   => SPR 315 (Power 2.04 hypv)
 * LPIDR   => SPR 317 (970)
 * EPR     => SPR 702 (Power 2.04 emb)
 * perf    => 768-783 (Power 2.04)
 * perf    => 784-799 (Power 2.04)
 * PPR     => SPR 896 (Power 2.04)
 * DABRX   => 1015    (Power 2.04 hypv)
 * FPECR   => SPR 1022 (?)
 * ... and more (thermal management, performance counters, ...)
 */

/*****************************************************************************/
/* Exception vectors models                                                  */
static void init_excp_4xx_real(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_CRITICAL] = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_PIT]      = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_FIT]      = 0x00001010;
    env->excp_vectors[POWERPC_EXCP_WDT]      = 0x00001020;
    env->excp_vectors[POWERPC_EXCP_DEBUG]    = 0x00002000;
    env->ivor_mask = 0x0000FFF0UL;
    env->ivpr_mask = 0xFFFF0000UL;
    /* Hardware reset vector */
    env->hreset_vector = 0xFFFFFFFCUL;
}

static void init_excp_4xx_softmmu(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_CRITICAL] = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_PIT]      = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_FIT]      = 0x00001010;
    env->excp_vectors[POWERPC_EXCP_WDT]      = 0x00001020;
    env->excp_vectors[POWERPC_EXCP_DTLB]     = 0x00001100;
    env->excp_vectors[POWERPC_EXCP_ITLB]     = 0x00001200;
    env->excp_vectors[POWERPC_EXCP_DEBUG]    = 0x00002000;
    env->ivor_mask = 0x0000FFF0UL;
    env->ivpr_mask = 0xFFFF0000UL;
    /* Hardware reset vector */
    env->hreset_vector = 0xFFFFFFFCUL;
}

#if defined(TODO_USER_ONLY)
static void init_excp_MPC5xx(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_FPA]      = 0x00000E00;
    env->excp_vectors[POWERPC_EXCP_EMUL]     = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_DABR]     = 0x00001C00;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001C00;
    env->excp_vectors[POWERPC_EXCP_MEXTBR]   = 0x00001E00;
    env->excp_vectors[POWERPC_EXCP_NMEXTBR]  = 0x00001F00;
    env->ivor_mask = 0x0000FFF0UL;
    env->ivpr_mask = 0xFFFF0000UL;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_MPC8xx(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_FPA]      = 0x00000E00;
    env->excp_vectors[POWERPC_EXCP_EMUL]     = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_ITLB]     = 0x00001100;
    env->excp_vectors[POWERPC_EXCP_DTLB]     = 0x00001200;
    env->excp_vectors[POWERPC_EXCP_ITLBE]    = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_DTLBE]    = 0x00001400;
    env->excp_vectors[POWERPC_EXCP_DABR]     = 0x00001C00;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001C00;
    env->excp_vectors[POWERPC_EXCP_MEXTBR]   = 0x00001E00;
    env->excp_vectors[POWERPC_EXCP_NMEXTBR]  = 0x00001F00;
    env->ivor_mask = 0x0000FFF0UL;
    env->ivpr_mask = 0xFFFF0000UL;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}
#endif

static void init_excp_G2(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_CRITICAL] = 0x00000A00;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_IFTLB]    = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_DLTLB]    = 0x00001100;
    env->excp_vectors[POWERPC_EXCP_DSTLB]    = 0x00001200;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_e200(CPUPPCState *env, target_ulong ivpr_mask)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000FFC;
    env->excp_vectors[POWERPC_EXCP_CRITICAL] = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_APU]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_FIT]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_WDT]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_DTLB]     = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_ITLB]     = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_DEBUG]    = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_SPEU]     = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_EFPDI]    = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_EFPRI]    = 0x00000000;
    env->ivor_mask = 0x0000FFF7UL;
    env->ivpr_mask = ivpr_mask;
    /* Hardware reset vector */
    env->hreset_vector = 0xFFFFFFFCUL;
}

static void init_excp_BookE(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_CRITICAL] = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_APU]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_FIT]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_WDT]      = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_DTLB]     = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_ITLB]     = 0x00000000;
    env->excp_vectors[POWERPC_EXCP_DEBUG]    = 0x00000000;
    env->ivor_mask = 0x0000FFF0UL;
    env->ivpr_mask = 0xFFFF0000UL;
    /* Hardware reset vector */
    env->hreset_vector = 0xFFFFFFFCUL;
}

static void init_excp_601(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_IO]       = 0x00000A00;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_RUNM]     = 0x00002000;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_602(CPUPPCState *env)
{
    /* XXX: exception prefix has a special behavior on 602 */
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_IFTLB]    = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_DLTLB]    = 0x00001100;
    env->excp_vectors[POWERPC_EXCP_DSTLB]    = 0x00001200;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    env->excp_vectors[POWERPC_EXCP_WDT]      = 0x00001500;
    env->excp_vectors[POWERPC_EXCP_EMUL]     = 0x00001600;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_603(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_IFTLB]    = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_DLTLB]    = 0x00001100;
    env->excp_vectors[POWERPC_EXCP_DSTLB]    = 0x00001200;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_604(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_7x0(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    env->excp_vectors[POWERPC_EXCP_THERM]    = 0x00001700;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_750cl(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_750cx(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_THERM]    = 0x00001700;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

/* XXX: Check if this is correct */
static void init_excp_7x5(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_IFTLB]    = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_DLTLB]    = 0x00001100;
    env->excp_vectors[POWERPC_EXCP_DSTLB]    = 0x00001200;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    env->excp_vectors[POWERPC_EXCP_THERM]    = 0x00001700;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_7400(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_VPU]      = 0x00000F20;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    env->excp_vectors[POWERPC_EXCP_VPUA]     = 0x00001600;
    env->excp_vectors[POWERPC_EXCP_THERM]    = 0x00001700;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

static void init_excp_7450(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_VPU]      = 0x00000F20;
    env->excp_vectors[POWERPC_EXCP_IFTLB]    = 0x00001000;
    env->excp_vectors[POWERPC_EXCP_DLTLB]    = 0x00001100;
    env->excp_vectors[POWERPC_EXCP_DSTLB]    = 0x00001200;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_SMI]      = 0x00001400;
    env->excp_vectors[POWERPC_EXCP_VPUA]     = 0x00001600;
    /* Hardware reset vector */
    env->hreset_vector = 0x00000100UL;
}

#if defined(TARGET_PPC64)
static void init_excp_970(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_DSEG]     = 0x00000380;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_ISEG]     = 0x00000480;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_HDECR]    = 0x00000980;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_VPU]      = 0x00000F20;
    env->excp_vectors[POWERPC_EXCP_IABR]     = 0x00001300;
    env->excp_vectors[POWERPC_EXCP_MAINT]    = 0x00001600;
    env->excp_vectors[POWERPC_EXCP_VPUA]     = 0x00001700;
    env->excp_vectors[POWERPC_EXCP_THERM]    = 0x00001800;
    /* Hardware reset vector */
    env->hreset_vector = 0x0000000000000100ULL;
}

static void init_excp_POWER7(CPUPPCState *env)
{
    env->excp_vectors[POWERPC_EXCP_RESET]    = 0x00000100;
    env->excp_vectors[POWERPC_EXCP_MCHECK]   = 0x00000200;
    env->excp_vectors[POWERPC_EXCP_DSI]      = 0x00000300;
    env->excp_vectors[POWERPC_EXCP_DSEG]     = 0x00000380;
    env->excp_vectors[POWERPC_EXCP_ISI]      = 0x00000400;
    env->excp_vectors[POWERPC_EXCP_ISEG]     = 0x00000480;
    env->excp_vectors[POWERPC_EXCP_EXTERNAL] = 0x00000500;
    env->excp_vectors[POWERPC_EXCP_ALIGN]    = 0x00000600;
    env->excp_vectors[POWERPC_EXCP_PROGRAM]  = 0x00000700;
    env->excp_vectors[POWERPC_EXCP_FPU]      = 0x00000800;
    env->excp_vectors[POWERPC_EXCP_DECR]     = 0x00000900;
    env->excp_vectors[POWERPC_EXCP_HDECR]    = 0x00000980;
    env->excp_vectors[POWERPC_EXCP_SYSCALL]  = 0x00000C00;
    env->excp_vectors[POWERPC_EXCP_TRACE]    = 0x00000D00;
    env->excp_vectors[POWERPC_EXCP_HDSI]     = 0x00000E00;
    env->excp_vectors[POWERPC_EXCP_HISI]     = 0x00000E20;
    env->excp_vectors[POWERPC_EXCP_HV_EMU]   = 0x00000E40;
    env->excp_vectors[POWERPC_EXCP_HV_MAINT] = 0x00000E60;
    env->excp_vectors[POWERPC_EXCP_PERFM]    = 0x00000F00;
    env->excp_vectors[POWERPC_EXCP_VPU]      = 0x00000F20;
    env->excp_vectors[POWERPC_EXCP_VSXU]     = 0x00000F40;
    /* Hardware reset vector */
    env->hreset_vector = 0x0000000000000100ULL;
}

static void init_excp_POWER8(CPUPPCState *env)
{
    init_excp_POWER7(env);

    env->excp_vectors[POWERPC_EXCP_SDOOR]    = 0x00000A00;
    env->excp_vectors[POWERPC_EXCP_FU]       = 0x00000F60;
    env->excp_vectors[POWERPC_EXCP_HV_FU]    = 0x00000F80;
    env->excp_vectors[POWERPC_EXCP_SDOOR_HV] = 0x00000E80;
}

static void init_excp_POWER9(CPUPPCState *env)
{
    init_excp_POWER8(env);

    env->excp_vectors[POWERPC_EXCP_HVIRT]    = 0x00000EA0;
}

static void init_excp_POWER10(CPUPPCState *env)
{
    init_excp_POWER9(env);
}

#endif

/*****************************************************************************/
/* Power management enable checks                                            */
static int check_pow_none(CPUPPCState *env)
{
    return 0;
}

static int check_pow_nocheck(CPUPPCState *env)
{
    return 1;
}

static int check_pow_hid0(CPUPPCState *env)
{
    if (env->spr[SPR_HID0] & 0x00E00000) {
        return 1;
    }

    return 0;
}

static int check_pow_hid0_74xx(CPUPPCState *env)
{
    if (env->spr[SPR_HID0] & 0x00600000) {
        return 1;
    }

    return 0;
}

static bool ppc_cpu_interrupts_big_endian_always(PowerPCCPU *cpu)
{
    return true;
}

#ifdef TARGET_PPC64
static bool ppc_cpu_interrupts_big_endian_lpcr(PowerPCCPU *cpu)
{
    return !(cpu->env.spr[SPR_LPCR] & LPCR_ILE);
}
#endif

/*****************************************************************************/
/* PowerPC implementations definitions                                       */

#define POWERPC_FAMILY_NAME(_name)                                          \
    glue(glue(ppc_, _name), _cpu_family_class_init)

#define POWERPC_FAMILY(_name)                                               \
    static void                                                             \
    glue(glue(ppc_, _name), _cpu_family_class_init)(CPUClass *, void *);    \
                                                                            \
    static void glue(glue(ppc_, _name), _cpu_family_class_init)

static void init_proc_401(CPUPPCState *env)
{
    gen_spr_40x(env);
    gen_spr_401_403(env);
    gen_spr_401(env);
    init_excp_4xx_real(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(12, 16, 20, 24);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

POWERPC_FAMILY(401)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 401";
    pcc->init_proc = init_proc_401;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_WRTEE | PPC_DCR |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_40x_ICBT |
                       PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_4xx_COMMON | PPC_40x_EXCP;
    pcc->msr_mask = (1ull << MSR_KEY) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_REAL;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_401;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_401x2(CPUPPCState *env)
{
    gen_spr_40x(env);
    gen_spr_401_403(env);
    gen_spr_401x2(env);
    gen_spr_compress(env);
    /* Memory management */
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;
    init_excp_4xx_softmmu(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(12, 16, 20, 24);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

POWERPC_FAMILY(401x2)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 401x2";
    pcc->init_proc = init_proc_401x2;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_DCR | PPC_WRTEE |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_40x_ICBT |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_40x_TLB | PPC_MEM_TLBIA | PPC_MEM_TLBSYNC |
                       PPC_4xx_COMMON | PPC_40x_EXCP;
    pcc->msr_mask = (1ull << 20) |
                    (1ull << MSR_KEY) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_4xx_Z;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_401;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}

#if 0
static void init_proc_401x3(CPUPPCState *env)
{
    gen_spr_40x(env);
    gen_spr_401_403(env);
    gen_spr_401(env);
    gen_spr_401x2(env);
    gen_spr_compress(env);
    init_excp_4xx_softmmu(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(12, 16, 20, 24);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

POWERPC_FAMILY(401x3)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 401x3";
    pcc->init_proc = init_proc_401x3;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_DCR | PPC_WRTEE |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_40x_ICBT |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_40x_TLB | PPC_MEM_TLBIA | PPC_MEM_TLBSYNC |
                       PPC_4xx_COMMON | PPC_40x_EXCP;
    pcc->msr_mask = (1ull << 20) |
                    (1ull << MSR_KEY) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_4xx_Z;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_401;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}
#endif

static void init_proc_IOP480(CPUPPCState *env)
{
    gen_spr_40x(env);
    gen_spr_401_403(env);
    gen_spr_401x2(env);
    gen_spr_compress(env);
    /* Memory management */
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;
    init_excp_4xx_softmmu(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(8, 12, 16, 20);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

POWERPC_FAMILY(IOP480)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "IOP480";
    pcc->init_proc = init_proc_IOP480;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_DCR | PPC_WRTEE |
                       PPC_CACHE | PPC_CACHE_ICBI |  PPC_40x_ICBT |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_40x_TLB | PPC_MEM_TLBIA | PPC_MEM_TLBSYNC |
                       PPC_4xx_COMMON | PPC_40x_EXCP;
    pcc->msr_mask = (1ull << 20) |
                    (1ull << MSR_KEY) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_4xx_Z;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_401;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_403(CPUPPCState *env)
{
    gen_spr_40x(env);
    gen_spr_401_403(env);
    gen_spr_403(env);
    gen_spr_403_real(env);
    init_excp_4xx_real(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(8, 12, 16, 20);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

POWERPC_FAMILY(403)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 403";
    pcc->init_proc = init_proc_403;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_DCR | PPC_WRTEE |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_40x_ICBT |
                       PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_4xx_COMMON | PPC_40x_EXCP;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_PE) |
                    (1ull << MSR_PX) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_REAL;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_401;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_PX |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_403GCX(CPUPPCState *env)
{
    gen_spr_40x(env);
    gen_spr_401_403(env);
    gen_spr_403(env);
    gen_spr_403_real(env);
    gen_spr_403_mmu(env);
    /* Bus access control */
    /* not emulated, as QEMU never does speculative access */
    spr_register(env, SPR_40x_SGR, "SGR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0xFFFFFFFF);
    /* not emulated, as QEMU do not emulate caches */
    spr_register(env, SPR_40x_DCWR, "DCWR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;
    init_excp_4xx_softmmu(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(8, 12, 16, 20);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

POWERPC_FAMILY(403GCX)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 403 GCX";
    pcc->init_proc = init_proc_403GCX;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_DCR | PPC_WRTEE |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_40x_ICBT |
                       PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_40x_TLB | PPC_MEM_TLBIA | PPC_MEM_TLBSYNC |
                       PPC_4xx_COMMON | PPC_40x_EXCP;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_PE) |
                    (1ull << MSR_PX) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_4xx_Z;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_401;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_PX |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_405(CPUPPCState *env)
{
    /* Time base */
    gen_tbl(env);
    gen_spr_40x(env);
    gen_spr_405(env);
    /* Bus access control */
    /* not emulated, as QEMU never does speculative access */
    spr_register(env, SPR_40x_SGR, "SGR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0xFFFFFFFF);
    /* not emulated, as QEMU do not emulate caches */
    spr_register(env, SPR_40x_DCWR, "DCWR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;

    init_excp_4xx_softmmu(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(8, 12, 16, 20);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

POWERPC_FAMILY(405)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 405";
    pcc->init_proc = init_proc_405;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_DCR | PPC_WRTEE |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_40x_ICBT |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_40x_TLB | PPC_MEM_TLBIA | PPC_MEM_TLBSYNC |
                       PPC_4xx_COMMON | PPC_405_MAC | PPC_40x_EXCP;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_SOFT_4xx;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_405;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DWE |
                 POWERPC_FLAG_DE | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_440EP(CPUPPCState *env)
{
    /* Time base */
    gen_tbl(env);
    gen_spr_BookE(env, 0x000000000000FFFFULL);
    gen_spr_440(env);
    gen_spr_usprgh(env);
    /* Processor identification */
    spr_register(env, SPR_BOOKE_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pir,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC3, "IAC3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC4, "IAC4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DVC1, "DVC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DVC2, "DVC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_MCSR, "MCSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_MCSRR0, "MCSRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_MCSRR1, "MCSRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_CCR1, "CCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;

    init_excp_BookE(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(12, 16, 20, 24);
    SET_WDT_PERIOD(20, 24, 28, 32);
}

POWERPC_FAMILY(440EP)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 440 EP";
    pcc->init_proc = init_proc_440EP;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_FLOAT | PPC_FLOAT_FRES | PPC_FLOAT_FSEL |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_DCR | PPC_WRTEE | PPC_RFMCI |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_MFTB |
                       PPC_BOOKE | PPC_4xx_COMMON | PPC_405_MAC |
                       PPC_440_SPEC;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DWE |
                 POWERPC_FLAG_DE | POWERPC_FLAG_BUS_CLK;
}

POWERPC_FAMILY(460EX)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 460 EX";
    pcc->init_proc = init_proc_440EP;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_FLOAT | PPC_FLOAT_FRES | PPC_FLOAT_FSEL |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_DCR | PPC_DCRX | PPC_WRTEE | PPC_RFMCI |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_MFTB |
                       PPC_BOOKE | PPC_4xx_COMMON | PPC_405_MAC |
                       PPC_440_SPEC;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DWE |
                 POWERPC_FLAG_DE | POWERPC_FLAG_BUS_CLK;
}

#if defined(TODO_USER_ONLY)
static void init_proc_440GP(CPUPPCState *env)
{
    /* Time base */
    gen_tbl(env);
    gen_spr_BookE(env, 0x000000000000FFFFULL);
    gen_spr_440(env);
    gen_spr_usprgh(env);
    /* Processor identification */
    spr_register(env, SPR_BOOKE_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pir,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC3, "IAC3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC4, "IAC4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DVC1, "DVC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DVC2, "DVC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;

    init_excp_BookE(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* XXX: TODO: allocate internal IRQ controller */

    SET_FIT_PERIOD(12, 16, 20, 24);
    SET_WDT_PERIOD(20, 24, 28, 32);
}

POWERPC_FAMILY(440GP)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 440 GP";
    pcc->init_proc = init_proc_440GP;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_DCR | PPC_DCRX | PPC_WRTEE | PPC_MFAPIDI |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_TLBIVA | PPC_MFTB |
                       PPC_BOOKE | PPC_4xx_COMMON | PPC_405_MAC |
                       PPC_440_SPEC;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DWE |
                 POWERPC_FLAG_DE | POWERPC_FLAG_BUS_CLK;
}
#endif

#if 0
static void init_proc_440x4(CPUPPCState *env)
{
    /* Time base */
    gen_tbl(env);
    gen_spr_BookE(env, 0x000000000000FFFFULL);
    gen_spr_440(env);
    gen_spr_usprgh(env);
    /* Processor identification */
    spr_register(env, SPR_BOOKE_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pir,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC3, "IAC3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC4, "IAC4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DVC1, "DVC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DVC2, "DVC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;

    init_excp_BookE(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* XXX: TODO: allocate internal IRQ controller */

    SET_FIT_PERIOD(12, 16, 20, 24);
    SET_WDT_PERIOD(20, 24, 28, 32);
}

POWERPC_FAMILY(440x4)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 440x4";
    pcc->init_proc = init_proc_440x4;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_DCR | PPC_WRTEE |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_MFTB |
                       PPC_BOOKE | PPC_4xx_COMMON | PPC_405_MAC |
                       PPC_440_SPEC;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DWE |
                 POWERPC_FLAG_DE | POWERPC_FLAG_BUS_CLK;
}
#endif

static void init_proc_440x5(CPUPPCState *env)
{
    /* Time base */
    gen_tbl(env);
    gen_spr_BookE(env, 0x000000000000FFFFULL);
    gen_spr_440(env);
    gen_spr_usprgh(env);
    /* Processor identification */
    spr_register(env, SPR_BOOKE_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pir,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC3, "IAC3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC4, "IAC4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DVC1, "DVC1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_DVC2, "DVC2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_MCSR, "MCSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_MCSRR0, "MCSRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_MCSRR1, "MCSRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_440_CCR1, "CCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;

    init_excp_BookE(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    ppc40x_irq_init(env_archcpu(env));

    SET_FIT_PERIOD(12, 16, 20, 24);
    SET_WDT_PERIOD(20, 24, 28, 32);
}

POWERPC_FAMILY(440x5)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 440x5";
    pcc->init_proc = init_proc_440x5;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_DCR | PPC_WRTEE | PPC_RFMCI |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_MFTB |
                       PPC_BOOKE | PPC_4xx_COMMON | PPC_405_MAC |
                       PPC_440_SPEC;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DWE |
                 POWERPC_FLAG_DE | POWERPC_FLAG_BUS_CLK;
}

POWERPC_FAMILY(440x5wDFPU)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 440x5 with double precision FPU";
    pcc->init_proc = init_proc_440x5;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_FLOAT | PPC_FLOAT_FSQRT |
                       PPC_FLOAT_STFIWX |
                       PPC_DCR | PPC_WRTEE | PPC_RFMCI |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_MFTB |
                       PPC_BOOKE | PPC_4xx_COMMON | PPC_405_MAC |
                       PPC_440_SPEC;
    pcc->insns_flags2 = PPC2_FP_CVT_S64;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DWE |
                 POWERPC_FLAG_DE | POWERPC_FLAG_BUS_CLK;
}

#if defined(TODO_USER_ONLY)
static void init_proc_MPC5xx(CPUPPCState *env)
{
    /* Time base */
    gen_tbl(env);
    gen_spr_5xx_8xx(env);
    gen_spr_5xx(env);
    init_excp_MPC5xx(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* XXX: TODO: allocate internal IRQ controller */
}

POWERPC_FAMILY(MPC5xx)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "Freescale 5xx cores (aka RCPU)";
    pcc->init_proc = init_proc_MPC5xx;
    pcc->check_pow = check_pow_none;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_MEM_EIEIO | PPC_MEM_SYNC |
                       PPC_CACHE_ICBI | PPC_FLOAT | PPC_FLOAT_STFIWX |
                       PPC_MFTB;
    pcc->msr_mask = (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_REAL;
    pcc->excp_model = POWERPC_EXCP_603;
    pcc->bus_model = PPC_FLAGS_INPUT_RCPU;
    pcc->bfd_mach = bfd_mach_ppc_505;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_BUS_CLK;
}
#endif

#if defined(TODO_USER_ONLY)
static void init_proc_MPC8xx(CPUPPCState *env)
{
    /* Time base */
    gen_tbl(env);
    gen_spr_5xx_8xx(env);
    gen_spr_8xx(env);
    init_excp_MPC8xx(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* XXX: TODO: allocate internal IRQ controller */
}

POWERPC_FAMILY(MPC8xx)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "Freescale 8xx cores (aka PowerQUICC)";
    pcc->init_proc = init_proc_MPC8xx;
    pcc->check_pow = check_pow_none;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING  |
                       PPC_MEM_EIEIO | PPC_MEM_SYNC |
                       PPC_CACHE_ICBI | PPC_MFTB;
    pcc->msr_mask = (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_MPC8xx;
    pcc->excp_model = POWERPC_EXCP_603;
    pcc->bus_model = PPC_FLAGS_INPUT_RCPU;
    pcc->bfd_mach = bfd_mach_ppc_860;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_BUS_CLK;
}
#endif

/* Freescale 82xx cores (aka PowerQUICC-II)                                  */

static void init_proc_G2(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_G2_755(env);
    gen_spr_G2(env);
    /* Time base */
    gen_tbl(env);
    /* External access control */
    /* XXX : not implemented */
    spr_register(env, SPR_EAR, "EAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Hardware implementation register */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_6xx_7xx_soft_tlb(env, 64, 2);
    init_excp_G2(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(G2)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC G2";
    pcc->init_proc = init_proc_G2;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC | PPC_6xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_TGPR) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_AL) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_RI);
    pcc->mmu_model = POWERPC_MMU_SOFT_6xx;
    pcc->excp_model = POWERPC_EXCP_G2;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_ec603e;
    pcc->flags = POWERPC_FLAG_TGPR | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_G2LE(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_G2_755(env);
    gen_spr_G2(env);
    /* Time base */
    gen_tbl(env);
    /* External access control */
    /* XXX : not implemented */
    spr_register(env, SPR_EAR, "EAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Hardware implementation register */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);

    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_6xx_7xx_soft_tlb(env, 64, 2);
    init_excp_G2(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(G2LE)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC G2LE";
    pcc->init_proc = init_proc_G2LE;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC | PPC_6xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_TGPR) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_AL) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_6xx;
    pcc->excp_model = POWERPC_EXCP_G2;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_ec603e;
    pcc->flags = POWERPC_FLAG_TGPR | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_e200(CPUPPCState *env)
{
    /* Time base */
    gen_tbl(env);
    gen_spr_BookE(env, 0x000000070000FFFFULL);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_SPEFSCR, "SPEFSCR",
                 &spr_read_spefscr, &spr_write_spefscr,
                 &spr_read_spefscr, &spr_write_spefscr,
                 0x00000000);
    /* Memory management */
    gen_spr_BookE206(env, 0x0000005D, NULL, 0);
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_ALTCTXCR, "ALTCTXCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_BUCSR, "BUCSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_CTXCR, "CTXCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_DBCNT, "DBCNT",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_DBCR3, "DBCR3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_L1CFG0, "L1CFG0",
                 &spr_read_generic, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_L1CSR0, "L1CSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_L1FINV0, "L1FINV0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_TLB0CFG, "TLB0CFG",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_TLB1CFG, "TLB1CFG",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC3, "IAC3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_IAC4, "IAC4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MMUCSR0, "MMUCSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000); /* TOFIX */
    spr_register(env, SPR_BOOKE_DSRR0, "DSRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_DSRR1, "DSRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;

    init_excp_e200(env, 0xFFFF0000UL);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* XXX: TODO: allocate internal IRQ controller */
}

POWERPC_FAMILY(e200)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "e200 core";
    pcc->init_proc = init_proc_e200;
    pcc->check_pow = check_pow_hid0;
    /*
     * XXX: unimplemented instructions:
     * dcblc
     * dcbtlst
     * dcbtstls
     * icblc
     * icbtls
     * tlbivax
     * all SPE multiply-accumulate instructions
     */
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL |
                       PPC_SPE | PPC_SPE_SINGLE |
                       PPC_WRTEE | PPC_RFDI |
                       PPC_CACHE | PPC_CACHE_LOCK | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_TLBIVAX |
                       PPC_BOOKE;
    pcc->msr_mask = (1ull << MSR_UCLE) |
                    (1ull << MSR_SPE) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE206;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_860;
    pcc->flags = POWERPC_FLAG_SPE | POWERPC_FLAG_CE |
                 POWERPC_FLAG_UBLE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_e300(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_603(env);
    /* Time base */
    gen_tbl(env);
    /* hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Breakpoints */
    /* XXX : not implemented */
    spr_register(env, SPR_DABR, "DABR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_DABR2, "DABR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_IABR2, "IABR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_IBCR, "IBCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_DBCR, "DBCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_6xx_7xx_soft_tlb(env, 64, 2);
    init_excp_603(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(e300)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "e300 core";
    pcc->init_proc = init_proc_e300;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC | PPC_6xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_TGPR) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_AL) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_6xx;
    pcc->excp_model = POWERPC_EXCP_603;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_603;
    pcc->flags = POWERPC_FLAG_TGPR | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_BUS_CLK;
}

static void spr_write_mas73(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv val = tcg_temp_new(tcg_ctx);
    tcg_gen_ext32u_tl(tcg_ctx, val, cpu_gpr[gprn]);
    gen_store_spr(tcg_ctx, SPR_BOOKE_MAS3, val);
    tcg_gen_shri_tl(tcg_ctx, val, cpu_gpr[gprn], 32);
    gen_store_spr(tcg_ctx, SPR_BOOKE_MAS7, val);
    tcg_temp_free(tcg_ctx, val);
}

static void spr_read_mas73(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    TCGv mas7 = tcg_temp_new(tcg_ctx);
    TCGv mas3 = tcg_temp_new(tcg_ctx);
    gen_load_spr(tcg_ctx, mas7, SPR_BOOKE_MAS7);
    tcg_gen_shli_tl(tcg_ctx, mas7, mas7, 32);
    gen_load_spr(tcg_ctx, mas3, SPR_BOOKE_MAS3);
    tcg_gen_or_tl(tcg_ctx, cpu_gpr[gprn], mas3, mas7);
    tcg_temp_free(tcg_ctx, mas3);
    tcg_temp_free(tcg_ctx, mas7);
}

enum fsl_e500_version {
    fsl_e500v1,
    fsl_e500v2,
    fsl_e500mc,
    fsl_e5500,
    fsl_e6500,
};

static void init_proc_e500(CPUPPCState *env, int version)
{
    uint32_t tlbncfg[2];
    uint64_t ivor_mask;
    uint64_t ivpr_mask = 0xFFFF0000ULL;
    uint32_t l1cfg0 = 0x3800  /* 8 ways */
                    | 0x0020; /* 32 kb */
    uint32_t l1cfg1 = 0x3800  /* 8 ways */
                    | 0x0020; /* 32 kb */
    uint32_t mmucfg = 0;
    int i;

    /* Time base */
    gen_tbl(env);
    /*
     * XXX The e500 doesn't implement IVOR7 and IVOR9, but doesn't
     *     complain when accessing them.
     * gen_spr_BookE(env, 0x0000000F0000FD7FULL);
     */
    switch (version) {
    case fsl_e500v1:
    case fsl_e500v2:
    default:
        ivor_mask = 0x0000000F0000FFFFULL;
        break;
    case fsl_e500mc:
    case fsl_e5500:
        ivor_mask = 0x000003FE0000FFFFULL;
        break;
    case fsl_e6500:
        ivor_mask = 0x000003FF0000FFFFULL;
        break;
    }
    gen_spr_BookE(env, ivor_mask);
    gen_spr_usprg3(env);
    /* Processor identification */
    spr_register(env, SPR_BOOKE_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pir,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_SPEFSCR, "SPEFSCR",
                 &spr_read_spefscr, &spr_write_spefscr,
                 &spr_read_spefscr, &spr_write_spefscr,
                 0x00000000);
    /* Memory management */
    env->nb_pids = 3;
    env->nb_ways = 2;
    env->id_tlbs = 0;
    switch (version) {
    case fsl_e500v1:
        tlbncfg[0] = gen_tlbncfg(2, 1, 1, 0, 256);
        tlbncfg[1] = gen_tlbncfg(16, 1, 9, TLBnCFG_AVAIL | TLBnCFG_IPROT, 16);
        break;
    case fsl_e500v2:
        tlbncfg[0] = gen_tlbncfg(4, 1, 1, 0, 512);
        tlbncfg[1] = gen_tlbncfg(16, 1, 12, TLBnCFG_AVAIL | TLBnCFG_IPROT, 16);
        break;
    case fsl_e500mc:
    case fsl_e5500:
        tlbncfg[0] = gen_tlbncfg(4, 1, 1, 0, 512);
        tlbncfg[1] = gen_tlbncfg(64, 1, 12, TLBnCFG_AVAIL | TLBnCFG_IPROT, 64);
        break;
    case fsl_e6500:
        mmucfg = 0x6510B45;
        env->nb_pids = 1;
        tlbncfg[0] = 0x08052400;
        tlbncfg[1] = 0x40028040;
        break;
    default:
        cpu_abort(env_cpu(env), "Unknown CPU: " TARGET_FMT_lx "\n",
                  env->spr[SPR_PVR]);
    }

    /* Cache sizes */
    switch (version) {
    case fsl_e500v1:
    case fsl_e500v2:
        env->dcache_line_size = 32;
        env->icache_line_size = 32;
        break;
    case fsl_e500mc:
    case fsl_e5500:
        env->dcache_line_size = 64;
        env->icache_line_size = 64;
        l1cfg0 |= 0x1000000; /* 64 byte cache block size */
        l1cfg1 |= 0x1000000; /* 64 byte cache block size */
        break;
    case fsl_e6500:
        env->dcache_line_size = 32;
        env->icache_line_size = 32;
        l1cfg0 |= 0x0F83820;
        l1cfg1 |= 0x0B83820;
        break;
    default:
        cpu_abort(env_cpu(env), "Unknown CPU: " TARGET_FMT_lx "\n",
                  env->spr[SPR_PVR]);
    }
    gen_spr_BookE206(env, 0x000000DF, tlbncfg, mmucfg);
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_BBEAR, "BBEAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_BBTAR, "BBTAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_MCAR, "MCAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_BOOKE_MCSR, "MCSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_NPIDR, "NPIDR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_BUCSR, "BUCSR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_Exxx_L1CFG0, "L1CFG0",
                 &spr_read_generic, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 l1cfg0);
    spr_register(env, SPR_Exxx_L1CFG1, "L1CFG1",
                 &spr_read_generic, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 l1cfg1);
    spr_register(env, SPR_Exxx_L1CSR0, "L1CSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_e500_l1csr0,
                 0x00000000);
    spr_register(env, SPR_Exxx_L1CSR1, "L1CSR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_e500_l1csr1,
                 0x00000000);
    spr_register(env, SPR_BOOKE_MCSRR0, "MCSRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BOOKE_MCSRR1, "MCSRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_MMUCSR0, "MMUCSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_booke206_mmucsr0,
                 0x00000000);
    spr_register(env, SPR_BOOKE_EPR, "EPR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
    /* XXX better abstract into Emb.xxx features */
    if ((version == fsl_e5500) || (version == fsl_e6500)) {
        spr_register(env, SPR_BOOKE_EPCR, "EPCR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     0x00000000);
        spr_register(env, SPR_BOOKE_MAS7_MAS3, "MAS7_MAS3",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_mas73, &spr_write_mas73,
                     0x00000000);
        ivpr_mask = (target_ulong)~0xFFFFULL;
    }

    if (version == fsl_e6500) {
        /* Thread identification */
        spr_register(env, SPR_TIR, "TIR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, SPR_NOACCESS,
                     0x00000000);
        spr_register(env, SPR_BOOKE_TLB0PS, "TLB0PS",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, SPR_NOACCESS,
                     0x00000004);
        spr_register(env, SPR_BOOKE_TLB1PS, "TLB1PS",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, SPR_NOACCESS,
                     0x7FFFFFFC);
    }

    env->nb_tlb = 0;
    env->tlb_type = TLB_MAS;
    for (i = 0; i < BOOKE206_MAX_TLBN; i++) {
        env->nb_tlb += booke206_tlb_size(env, i);
    }

    init_excp_e200(env, ivpr_mask);
    /* Allocate hardware IRQ controller */
    ppce500_irq_init(env_archcpu(env));
}

static void init_proc_e500v1(CPUPPCState *env)
{
    init_proc_e500(env, fsl_e500v1);
}

POWERPC_FAMILY(e500v1)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "e500v1 core";
    pcc->init_proc = init_proc_e500v1;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL |
                       PPC_SPE | PPC_SPE_SINGLE |
                       PPC_WRTEE | PPC_RFDI |
                       PPC_CACHE | PPC_CACHE_LOCK | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_TLBIVAX | PPC_MEM_SYNC;
    pcc->insns_flags2 = PPC2_BOOKE206;
    pcc->msr_mask = (1ull << MSR_UCLE) |
                    (1ull << MSR_SPE) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE206;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_860;
    pcc->flags = POWERPC_FLAG_SPE | POWERPC_FLAG_CE |
                 POWERPC_FLAG_UBLE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_e500v2(CPUPPCState *env)
{
    init_proc_e500(env, fsl_e500v2);
}

POWERPC_FAMILY(e500v2)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "e500v2 core";
    pcc->init_proc = init_proc_e500v2;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL |
                       PPC_SPE | PPC_SPE_SINGLE | PPC_SPE_DOUBLE |
                       PPC_WRTEE | PPC_RFDI |
                       PPC_CACHE | PPC_CACHE_LOCK | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_TLBIVAX | PPC_MEM_SYNC;
    pcc->insns_flags2 = PPC2_BOOKE206;
    pcc->msr_mask = (1ull << MSR_UCLE) |
                    (1ull << MSR_SPE) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
#if 0
    pcc->mmu_model = POWERPC_MMU_BOOKE206;
#else
    /* disable mmu */
    pcc->mmu_model = POWERPC_MMU_REAL;
#endif
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_860;
    pcc->flags = POWERPC_FLAG_SPE | POWERPC_FLAG_CE |
                 POWERPC_FLAG_UBLE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_e500mc(CPUPPCState *env)
{
    init_proc_e500(env, fsl_e500mc);
}

POWERPC_FAMILY(e500mc)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "e500mc core";
    pcc->init_proc = init_proc_e500mc;
    pcc->check_pow = check_pow_none;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL | PPC_MFTB |
                       PPC_WRTEE | PPC_RFDI | PPC_RFMCI |
                       PPC_CACHE | PPC_CACHE_LOCK | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_FLOAT | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_FSEL |
                       PPC_FLOAT_STFIWX | PPC_WAIT |
                       PPC_MEM_TLBSYNC | PPC_TLBIVAX | PPC_MEM_SYNC;
    pcc->insns_flags2 = PPC2_BOOKE206 | PPC2_PRCNTL;
    pcc->msr_mask = (1ull << MSR_GS) |
                    (1ull << MSR_UCLE) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PX) |
                    (1ull << MSR_RI);
    pcc->mmu_model = POWERPC_MMU_BOOKE206;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    /* FIXME: figure out the correct flag for e500mc */
    pcc->bfd_mach = bfd_mach_ppc_e500;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

#ifdef TARGET_PPC64
static void init_proc_e5500(CPUPPCState *env)
{
    init_proc_e500(env, fsl_e5500);
}

POWERPC_FAMILY(e5500)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "e5500 core";
    pcc->init_proc = init_proc_e5500;
    pcc->check_pow = check_pow_none;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL | PPC_MFTB |
                       PPC_WRTEE | PPC_RFDI | PPC_RFMCI |
                       PPC_CACHE | PPC_CACHE_LOCK | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_FLOAT | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_FSEL |
                       PPC_FLOAT_STFIWX | PPC_WAIT |
                       PPC_MEM_TLBSYNC | PPC_TLBIVAX | PPC_MEM_SYNC |
                       PPC_64B | PPC_POPCNTB | PPC_POPCNTWD;
    pcc->insns_flags2 = PPC2_BOOKE206 | PPC2_PRCNTL | PPC2_PERM_ISA206 | \
                        PPC2_FP_CVT_S64;
    pcc->msr_mask = (1ull << MSR_CM) |
                    (1ull << MSR_GS) |
                    (1ull << MSR_UCLE) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PX) |
                    (1ull << MSR_RI);
    pcc->mmu_model = POWERPC_MMU_BOOKE206;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    /* FIXME: figure out the correct flag for e5500 */
    pcc->bfd_mach = bfd_mach_ppc_e500;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_e6500(CPUPPCState *env)
{
    init_proc_e500(env, fsl_e6500);
}

POWERPC_FAMILY(e6500)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "e6500 core";
    pcc->init_proc = init_proc_e6500;
    pcc->check_pow = check_pow_none;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL | PPC_MFTB |
                       PPC_WRTEE | PPC_RFDI | PPC_RFMCI |
                       PPC_CACHE | PPC_CACHE_LOCK | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_FLOAT | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_FSEL |
                       PPC_FLOAT_STFIWX | PPC_WAIT |
                       PPC_MEM_TLBSYNC | PPC_TLBIVAX | PPC_MEM_SYNC |
                       PPC_64B | PPC_POPCNTB | PPC_POPCNTWD | PPC_ALTIVEC;
    pcc->insns_flags2 = PPC2_BOOKE206 | PPC2_PRCNTL | PPC2_PERM_ISA206 | \
                        PPC2_FP_CVT_S64 | PPC2_ATOMIC_ISA206;
    pcc->msr_mask = (1ull << MSR_CM) |
                    (1ull << MSR_GS) |
                    (1ull << MSR_UCLE) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IS) |
                    (1ull << MSR_DS) |
                    (1ull << MSR_PX) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_VR);
    pcc->mmu_model = POWERPC_MMU_BOOKE206;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = bfd_mach_ppc_e500;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK | POWERPC_FLAG_VRE;
}

#endif

/* Non-embedded PowerPC                                                      */

#define POWERPC_MSRR_601     (0x0000000000001040ULL)

static void init_proc_601(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_601(env);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_hid0_601,
                 0x80010080);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_601_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_601_HID5, "HID5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    init_excp_601(env);
    /*
     * XXX: beware that dcache line size is 64
     *      but dcbz uses 32 bytes "sectors"
     * XXX: this breaks clcs instruction !
     */
    env->dcache_line_size = 32;
    env->icache_line_size = 64;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(601)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 601";
    pcc->init_proc = init_proc_601;
    pcc->check_pow = check_pow_none;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_POWER_BR |
                       PPC_FLOAT |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO | PPC_MEM_TLBIE |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_601;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_601;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_601;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_RTC_CLK;
}

#define POWERPC_MSRR_601v    (0x0000000000001040ULL)

static void init_proc_601v(CPUPPCState *env)
{
    init_proc_601(env);
    /* XXX : not implemented */
    spr_register(env, SPR_601_HID15, "HID15",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

POWERPC_FAMILY(601v)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 601v";
    pcc->init_proc = init_proc_601v;
    pcc->check_pow = check_pow_none;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_POWER_BR |
                       PPC_FLOAT |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO | PPC_MEM_TLBIE |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_601;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_601;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_RTC_CLK;
}

static void init_proc_602(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_602(env);
    /* Time base */
    gen_tbl(env);
    /* hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_6xx_7xx_soft_tlb(env, 64, 2);
    init_excp_602(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(602)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 602";
    pcc->init_proc = init_proc_602;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_6xx_TLB | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_602_SPEC;
    pcc->msr_mask = (1ull << MSR_VSX) |
                    (1ull << MSR_SA) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_TGPR) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    /* XXX: 602 MMU is quite specific. Should add a special case */
    pcc->mmu_model = POWERPC_MMU_SOFT_6xx;
    pcc->excp_model = POWERPC_EXCP_602;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_602;
    pcc->flags = POWERPC_FLAG_TGPR | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_603(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_603(env);
    /* Time base */
    gen_tbl(env);
    /* hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_6xx_7xx_soft_tlb(env, 64, 2);
    init_excp_603(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(603)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 603";
    pcc->init_proc = init_proc_603;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC | PPC_6xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_TGPR) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_6xx;
    pcc->excp_model = POWERPC_EXCP_603;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_603;
    pcc->flags = POWERPC_FLAG_TGPR | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_603E(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_603(env);
    /* Time base */
    gen_tbl(env);
    /* hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_6xx_7xx_soft_tlb(env, 64, 2);
    init_excp_603(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(603E)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 603e";
    pcc->init_proc = init_proc_603E;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC | PPC_6xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_TGPR) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_6xx;
    pcc->excp_model = POWERPC_EXCP_603E;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_ec603e;
    pcc->flags = POWERPC_FLAG_TGPR | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_604(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_604(env);
    /* Time base */
    gen_tbl(env);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    init_excp_604(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(604)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 604";
    pcc->init_proc = init_proc_604;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_604;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_604;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_604E(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_604(env);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_MMCR1, "MMCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC3, "PMC3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC4, "PMC4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Time base */
    gen_tbl(env);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    init_excp_604(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(604E)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 604E";
    pcc->init_proc = init_proc_604E;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_604;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_604;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_740(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* Thermal management */
    gen_spr_thrm(env);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    init_excp_7x0(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(740)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 740";
    pcc->init_proc = init_proc_740;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_7x0;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_750;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_750(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* XXX : not implemented */
    spr_register(env, SPR_L2CR, "L2CR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, spr_access_nop,
                 0x00000000);
    /* Time base */
    gen_tbl(env);
    /* Thermal management */
    gen_spr_thrm(env);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    /*
     * XXX: high BATs are also present but are known to be bugged on
     *      die version 1.x
     */
    init_excp_7x0(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(750)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 750";
    pcc->init_proc = init_proc_750;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_7x0;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_750;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_750cl(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* XXX : not implemented */
    spr_register(env, SPR_L2CR, "L2CR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, spr_access_nop,
                 0x00000000);
    /* Time base */
    gen_tbl(env);
    /* Thermal management */
    /* Those registers are fake on 750CL */
    spr_register(env, SPR_THRM1, "THRM1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_THRM2, "THRM2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_THRM3, "THRM3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX: not implemented */
    spr_register(env, SPR_750_TDCL, "TDCL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_750_TDCH, "TDCH",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* DMA */
    /* XXX : not implemented */
    spr_register(env, SPR_750_WPAR, "WPAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_750_DMAL, "DMAL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_750_DMAU, "DMAU",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750CL_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750CL_HID4, "HID4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Quantization registers */
    /* XXX : not implemented */
    spr_register(env, SPR_750_GQR0, "GQR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750_GQR1, "GQR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750_GQR2, "GQR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750_GQR3, "GQR3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750_GQR4, "GQR4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750_GQR5, "GQR5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750_GQR6, "GQR6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750_GQR7, "GQR7",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    /* PowerPC 750cl has 8 DBATs and 8 IBATs */
    gen_high_BATs(env);
    init_excp_750cl(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(750cl)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 750 CL";
    pcc->init_proc = init_proc_750cl;
    pcc->check_pow = check_pow_hid0;
    /*
     * XXX: not implemented:
     * cache lock instructions:
     * dcbz_l
     * floating point paired instructions
     * psq_lux
     * psq_lx
     * psq_stux
     * psq_stx
     * ps_abs
     * ps_add
     * ps_cmpo0
     * ps_cmpo1
     * ps_cmpu0
     * ps_cmpu1
     * ps_div
     * ps_madd
     * ps_madds0
     * ps_madds1
     * ps_merge00
     * ps_merge01
     * ps_merge10
     * ps_merge11
     * ps_mr
     * ps_msub
     * ps_mul
     * ps_muls0
     * ps_muls1
     * ps_nabs
     * ps_neg
     * ps_nmadd
     * ps_nmsub
     * ps_res
     * ps_rsqrte
     * ps_sel
     * ps_sub
     * ps_sum0
     * ps_sum1
     */
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_7x0;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_750;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_750cx(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* XXX : not implemented */
    spr_register(env, SPR_L2CR, "L2CR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, spr_access_nop,
                 0x00000000);
    /* Time base */
    gen_tbl(env);
    /* Thermal management */
    gen_spr_thrm(env);
    /* This register is not implemented but is present for compatibility */
    spr_register(env, SPR_SDA, "SDA",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    /* PowerPC 750cx has 8 DBATs and 8 IBATs */
    gen_high_BATs(env);
    init_excp_750cx(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(750cx)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 750CX";
    pcc->init_proc = init_proc_750cx;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_7x0;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_750;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_750fx(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* XXX : not implemented */
    spr_register(env, SPR_L2CR, "L2CR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, spr_access_nop,
                 0x00000000);
    /* Time base */
    gen_tbl(env);
    /* Thermal management */
    gen_spr_thrm(env);
    /* XXX : not implemented */
    spr_register(env, SPR_750_THRM4, "THRM4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_750FX_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    /* PowerPC 750fx & 750gx has 8 DBATs and 8 IBATs */
    gen_high_BATs(env);
    init_excp_7x0(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(750fx)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 750FX";
    pcc->init_proc = init_proc_750fx;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_7x0;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_750;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_750gx(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* XXX : not implemented (XXX: different from 750fx) */
    spr_register(env, SPR_L2CR, "L2CR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, spr_access_nop,
                 0x00000000);
    /* Time base */
    gen_tbl(env);
    /* Thermal management */
    gen_spr_thrm(env);
    /* XXX : not implemented */
    spr_register(env, SPR_750_THRM4, "THRM4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Hardware implementation registers */
    /* XXX : not implemented (XXX: different from 750fx) */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented (XXX: different from 750fx) */
    spr_register(env, SPR_750FX_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    /* PowerPC 750fx & 750gx has 8 DBATs and 8 IBATs */
    gen_high_BATs(env);
    init_excp_7x0(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(750gx)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 750GX";
    pcc->init_proc = init_proc_750gx;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_7x0;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_750;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_745(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    gen_spr_G2_755(env);
    /* Time base */
    gen_tbl(env);
    /* Thermal management */
    gen_spr_thrm(env);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_6xx_7xx_soft_tlb(env, 64, 2);
    init_excp_7x5(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(745)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 745";
    pcc->init_proc = init_proc_745;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC | PPC_6xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_6xx;
    pcc->excp_model = POWERPC_EXCP_7x5;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_750;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_755(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    gen_spr_G2_755(env);
    /* Time base */
    gen_tbl(env);
    /* L2 cache control */
    /* XXX : not implemented */
    spr_register(env, SPR_L2CR, "L2CR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, spr_access_nop,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_L2PMCR, "L2PMCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Thermal management */
    gen_spr_thrm(env);
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_HID2, "HID2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_6xx_7xx_soft_tlb(env, 64, 2);
    init_excp_7x5(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(755)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 755";
    pcc->init_proc = init_proc_755;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC | PPC_6xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_6xx;
    pcc->excp_model = POWERPC_EXCP_7x5;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_750;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

static void init_proc_7400(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* 74xx specific SPR */
    gen_spr_74xx(env);
    /* XXX : not implemented */
    spr_register(env, SPR_UBAMR, "UBAMR",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX: this seems not implemented on all revisions. */
    /* XXX : not implemented */
    spr_register(env, SPR_MSSCR1, "MSSCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Thermal management */
    gen_spr_thrm(env);
    /* Memory management */
    gen_low_BATs(env);
    init_excp_7400(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(7400)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 7400 (aka G4)";
    pcc->init_proc = init_proc_7400;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBA | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_MEM_TLBIA |
                       PPC_SEGMENT | PPC_EXTERN |
                       PPC_ALTIVEC;
    pcc->msr_mask = (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_74xx;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_7400;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_7410(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* 74xx specific SPR */
    gen_spr_74xx(env);
    /* XXX : not implemented */
    spr_register(env, SPR_UBAMR, "UBAMR",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* Thermal management */
    gen_spr_thrm(env);
    /* L2PMCR */
    /* XXX : not implemented */
    spr_register(env, SPR_L2PMCR, "L2PMCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* LDSTDB */
    /* XXX : not implemented */
    spr_register(env, SPR_LDSTDB, "LDSTDB",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    init_excp_7400(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(7410)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 7410 (aka G4)";
    pcc->init_proc = init_proc_7410;
    pcc->check_pow = check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBA | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_MEM_TLBIA |
                       PPC_SEGMENT | PPC_EXTERN |
                       PPC_ALTIVEC;
    pcc->msr_mask = (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_74xx;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_7400;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_7440(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* 74xx specific SPR */
    gen_spr_74xx(env);
    /* XXX : not implemented */
    spr_register(env, SPR_UBAMR, "UBAMR",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* LDSTCR */
    /* XXX : not implemented */
    spr_register(env, SPR_LDSTCR, "LDSTCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* ICTRL */
    /* XXX : not implemented */
    spr_register(env, SPR_ICTRL, "ICTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* MSSSR0 */
    /* XXX : not implemented */
    spr_register(env, SPR_MSSSR0, "MSSSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* PMC */
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC5, "PMC5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC5, "UPMC5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC6, "PMC6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC6, "UPMC6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_74xx_soft_tlb(env, 128, 2);
    init_excp_7450(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(7440)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 7440 (aka G4)";
    pcc->init_proc = init_proc_7440;
    pcc->check_pow = check_pow_hid0_74xx;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBA | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_MEM_TLBIA | PPC_74xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN |
                       PPC_ALTIVEC;
    pcc->msr_mask = (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_74xx;
    pcc->excp_model = POWERPC_EXCP_74xx;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_7400;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_7450(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* 74xx specific SPR */
    gen_spr_74xx(env);
    /* Level 3 cache control */
    gen_l3_ctrl(env);
    /* L3ITCR1 */
    /* XXX : not implemented */
    spr_register(env, SPR_L3ITCR1, "L3ITCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* L3ITCR2 */
    /* XXX : not implemented */
    spr_register(env, SPR_L3ITCR2, "L3ITCR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* L3ITCR3 */
    /* XXX : not implemented */
    spr_register(env, SPR_L3ITCR3, "L3ITCR3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* L3OHCR */
    /* XXX : not implemented */
    spr_register(env, SPR_L3OHCR, "L3OHCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_UBAMR, "UBAMR",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* LDSTCR */
    /* XXX : not implemented */
    spr_register(env, SPR_LDSTCR, "LDSTCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* ICTRL */
    /* XXX : not implemented */
    spr_register(env, SPR_ICTRL, "ICTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* MSSSR0 */
    /* XXX : not implemented */
    spr_register(env, SPR_MSSSR0, "MSSSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* PMC */
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC5, "PMC5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC5, "UPMC5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC6, "PMC6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC6, "UPMC6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_74xx_soft_tlb(env, 128, 2);
    init_excp_7450(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(7450)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 7450 (aka G4)";
    pcc->init_proc = init_proc_7450;
    pcc->check_pow = check_pow_hid0_74xx;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBA | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_MEM_TLBIA | PPC_74xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN |
                       PPC_ALTIVEC;
    pcc->msr_mask = (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_74xx;
    pcc->excp_model = POWERPC_EXCP_74xx;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_7400;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_7445(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* 74xx specific SPR */
    gen_spr_74xx(env);
    /* LDSTCR */
    /* XXX : not implemented */
    spr_register(env, SPR_LDSTCR, "LDSTCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* ICTRL */
    /* XXX : not implemented */
    spr_register(env, SPR_ICTRL, "ICTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* MSSSR0 */
    /* XXX : not implemented */
    spr_register(env, SPR_MSSSR0, "MSSSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* PMC */
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC5, "PMC5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC5, "UPMC5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC6, "PMC6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC6, "UPMC6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* SPRGs */
    spr_register(env, SPR_SPRG4, "SPRG4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG4, "USPRG4",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG5, "SPRG5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG5, "USPRG5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG6, "SPRG6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG6, "USPRG6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG7, "SPRG7",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG7, "USPRG7",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_74xx_soft_tlb(env, 128, 2);
    init_excp_7450(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(7445)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 7445 (aka G4)";
    pcc->init_proc = init_proc_7445;
    pcc->check_pow = check_pow_hid0_74xx;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBA | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_MEM_TLBIA | PPC_74xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN |
                       PPC_ALTIVEC;
    pcc->msr_mask = (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_74xx;
    pcc->excp_model = POWERPC_EXCP_74xx;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_7400;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
}

static void init_proc_7455(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* 74xx specific SPR */
    gen_spr_74xx(env);
    /* Level 3 cache control */
    gen_l3_ctrl(env);
    /* LDSTCR */
    /* XXX : not implemented */
    spr_register(env, SPR_LDSTCR, "LDSTCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* ICTRL */
    /* XXX : not implemented */
    spr_register(env, SPR_ICTRL, "ICTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* MSSSR0 */
    /* XXX : not implemented */
    spr_register(env, SPR_MSSSR0, "MSSSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* PMC */
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC5, "PMC5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC5, "UPMC5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC6, "PMC6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC6, "UPMC6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* SPRGs */
    spr_register(env, SPR_SPRG4, "SPRG4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG4, "USPRG4",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG5, "SPRG5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG5, "USPRG5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG6, "SPRG6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG6, "USPRG6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG7, "SPRG7",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG7, "USPRG7",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_74xx_soft_tlb(env, 128, 2);
    init_excp_7450(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(7455)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 7455 (aka G4)";
    pcc->init_proc = init_proc_7455;
    pcc->check_pow = check_pow_hid0_74xx;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBA | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_MEM_TLBIA | PPC_74xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN |
                       PPC_ALTIVEC;
    pcc->msr_mask = (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_74xx;
    pcc->excp_model = POWERPC_EXCP_74xx;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_7400;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
}

#if 0
static void init_proc_7457(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* 74xx specific SPR */
    gen_spr_74xx(env);
    /* Level 3 cache control */
    gen_l3_ctrl(env);
    /* L3ITCR1 */
    /* XXX : not implemented */
    spr_register(env, SPR_L3ITCR1, "L3ITCR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* L3ITCR2 */
    /* XXX : not implemented */
    spr_register(env, SPR_L3ITCR2, "L3ITCR2",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* L3ITCR3 */
    /* XXX : not implemented */
    spr_register(env, SPR_L3ITCR3, "L3ITCR3",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* L3OHCR */
    /* XXX : not implemented */
    spr_register(env, SPR_L3OHCR, "L3OHCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* LDSTCR */
    /* XXX : not implemented */
    spr_register(env, SPR_LDSTCR, "LDSTCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* ICTRL */
    /* XXX : not implemented */
    spr_register(env, SPR_ICTRL, "ICTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* MSSSR0 */
    /* XXX : not implemented */
    spr_register(env, SPR_MSSSR0, "MSSSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* PMC */
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC5, "PMC5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC5, "UPMC5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC6, "PMC6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC6, "UPMC6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* SPRGs */
    spr_register(env, SPR_SPRG4, "SPRG4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG4, "USPRG4",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG5, "SPRG5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG5, "USPRG5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG6, "SPRG6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG6, "USPRG6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG7, "SPRG7",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG7, "USPRG7",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_74xx_soft_tlb(env, 128, 2);
    init_excp_7450(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(7457)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 7457 (aka G4)";
    pcc->init_proc = init_proc_7457;
    pcc->check_pow = check_pow_hid0_74xx;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBA | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_MEM_TLBIA | PPC_74xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN |
                       PPC_ALTIVEC;
    pcc->msr_mask = (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_SOFT_74xx;
    pcc->excp_model = POWERPC_EXCP_74xx;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_7400;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
}
#endif

static void init_proc_e600(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_spr_sdr1(env);
    gen_spr_7xx(env);
    /* Time base */
    gen_tbl(env);
    /* 74xx specific SPR */
    gen_spr_74xx(env);
    /* XXX : not implemented */
    spr_register(env, SPR_UBAMR, "UBAMR",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_LDSTCR, "LDSTCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_ICTRL, "ICTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_MSSSR0, "MSSSR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC5, "PMC5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC5, "UPMC5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_PMC6, "PMC6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    /* XXX : not implemented */
    spr_register(env, SPR_7XX_UPMC6, "UPMC6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* SPRGs */
    spr_register(env, SPR_SPRG4, "SPRG4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG4, "USPRG4",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG5, "SPRG5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG5, "USPRG5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG6, "SPRG6",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG6, "USPRG6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    spr_register(env, SPR_SPRG7, "SPRG7",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_USPRG7, "USPRG7",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
    /* Memory management */
    gen_low_BATs(env);
    gen_high_BATs(env);
    gen_74xx_soft_tlb(env, 128, 2);
    init_excp_7450(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    ppc6xx_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(e600)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC e600";
    pcc->init_proc = init_proc_e600;
    pcc->check_pow = check_pow_hid0_74xx;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBA | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_MEM_TLBIA | PPC_74xx_TLB |
                       PPC_SEGMENT | PPC_EXTERN |
                       PPC_ALTIVEC;
    pcc->insns_flags2 = PPC_NONE;
    pcc->msr_mask = (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
    pcc->excp_model = POWERPC_EXCP_74xx;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    pcc->bfd_mach = bfd_mach_ppc_7400;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
}

#if defined(TARGET_PPC64)
#define POWERPC970_HID5_INIT 0x00000000

static void gen_fscr_facility_check(DisasContext *ctx, int facility_sprn,
                                    int bit, int sprn, int cause)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t1 = tcg_const_i32(tcg_ctx, bit);
    TCGv_i32 t2 = tcg_const_i32(tcg_ctx, sprn);
    TCGv_i32 t3 = tcg_const_i32(tcg_ctx, cause);

    gen_helper_fscr_facility_check(tcg_ctx, tcg_ctx->cpu_env, t1, t2, t3);

    tcg_temp_free_i32(tcg_ctx, t3);
    tcg_temp_free_i32(tcg_ctx, t2);
    tcg_temp_free_i32(tcg_ctx, t1);
}

static void gen_msr_facility_check(DisasContext *ctx, int facility_sprn,
                                   int bit, int sprn, int cause)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t1 = tcg_const_i32(tcg_ctx, bit);
    TCGv_i32 t2 = tcg_const_i32(tcg_ctx, sprn);
    TCGv_i32 t3 = tcg_const_i32(tcg_ctx, cause);

    gen_helper_msr_facility_check(tcg_ctx, tcg_ctx->cpu_env, t1, t2, t3);

    tcg_temp_free_i32(tcg_ctx, t3);
    tcg_temp_free_i32(tcg_ctx, t2);
    tcg_temp_free_i32(tcg_ctx, t1);
}

static void spr_read_prev_upper32(DisasContext *ctx, int gprn, int sprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv spr_up = tcg_temp_new(tcg_ctx);
    TCGv spr = tcg_temp_new(tcg_ctx);

    gen_load_spr(tcg_ctx, spr, sprn - 1);
    tcg_gen_shri_tl(tcg_ctx, spr_up, spr, 32);
    tcg_gen_ext32u_tl(tcg_ctx, cpu_gpr[gprn], spr_up);

    tcg_temp_free(tcg_ctx, spr);
    tcg_temp_free(tcg_ctx, spr_up);
}

static void spr_write_prev_upper32(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv spr = tcg_temp_new(tcg_ctx);

    gen_load_spr(tcg_ctx, spr, sprn - 1);
    tcg_gen_deposit_tl(tcg_ctx, spr, spr, cpu_gpr[gprn], 32, 32);
    gen_store_spr(tcg_ctx, sprn - 1, spr);

    tcg_temp_free(tcg_ctx, spr);
}

static int check_pow_970(CPUPPCState *env)
{
    if (env->spr[SPR_HID0] & (HID0_DEEPNAP | HID0_DOZE | HID0_NAP)) {
        return 1;
    }

    return 0;
}

static void gen_spr_970_hid(CPUPPCState *env)
{
    /* Hardware implementation registers */
    /* XXX : not implemented */
    spr_register(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_clear,
                 0x60000000);
    spr_register(env, SPR_HID1, "HID1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_970_HID5, "HID5",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 POWERPC970_HID5_INIT);
}

static void gen_spr_970_hior(CPUPPCState *env)
{
    spr_register(env, SPR_HIOR, "SPR_HIOR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_hior, &spr_write_hior,
                 0x00000000);
}

static void gen_spr_book3s_ctrl(CPUPPCState *env)
{
    spr_register(env, SPR_CTRL, "SPR_CTRL",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_UCTRL, "SPR_UCTRL",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, SPR_NOACCESS,
                 0x00000000);
}

static void gen_spr_book3s_altivec(CPUPPCState *env)
{
    if (!(env->insns_flags & PPC_ALTIVEC)) {
        return;
    }

    spr_register_kvm(env, SPR_VRSAVE, "VRSAVE",
                     &spr_read_generic, &spr_write_generic,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_VRSAVE, 0x00000000);

    /*
     * Can't find information on what this should be on reset.  This
     * value is the one used by 74xx processors.
     */
    vscr_init(env, 0x00010000);
}

static void gen_spr_book3s_dbg(CPUPPCState *env)
{
    /*
     * TODO: different specs define different scopes for these,
     * will have to address this:
     * 970: super/write and super/read
     * powerisa 2.03..2.04: hypv/write and super/read.
     * powerisa 2.05 and newer: hypv/write and hypv/read.
     */
    spr_register_kvm(env, SPR_DABR, "DABR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DABR, 0x00000000);
    spr_register_kvm(env, SPR_DABRX, "DABRX",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DABRX, 0x00000000);
}

static void gen_spr_book3s_207_dbg(CPUPPCState *env)
{
    spr_register_kvm_hv(env, SPR_DAWR, "DAWR",
                        SPR_NOACCESS, SPR_NOACCESS,
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_generic, &spr_write_generic,
                        KVM_REG_PPC_DAWR, 0x00000000);
    spr_register_kvm_hv(env, SPR_DAWRX, "DAWRX",
                        SPR_NOACCESS, SPR_NOACCESS,
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_generic, &spr_write_generic,
                        KVM_REG_PPC_DAWRX, 0x00000000);
    spr_register_kvm_hv(env, SPR_CIABR, "CIABR",
                        SPR_NOACCESS, SPR_NOACCESS,
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_generic, &spr_write_generic,
                        KVM_REG_PPC_CIABR, 0x00000000);
}

static void gen_spr_970_dbg(CPUPPCState *env)
{
    /* Breakpoints */
    spr_register(env, SPR_IABR, "IABR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_book3s_pmu_sup(CPUPPCState *env)
{
    spr_register_kvm(env, SPR_POWER_MMCR0, "MMCR0",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_MMCR0, 0x00000000);
    spr_register_kvm(env, SPR_POWER_MMCR1, "MMCR1",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_MMCR1, 0x00000000);
    spr_register_kvm(env, SPR_POWER_MMCRA, "MMCRA",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_MMCRA, 0x00000000);
    spr_register_kvm(env, SPR_POWER_PMC1, "PMC1",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PMC1, 0x00000000);
    spr_register_kvm(env, SPR_POWER_PMC2, "PMC2",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PMC2, 0x00000000);
    spr_register_kvm(env, SPR_POWER_PMC3, "PMC3",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PMC3, 0x00000000);
    spr_register_kvm(env, SPR_POWER_PMC4, "PMC4",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PMC4, 0x00000000);
    spr_register_kvm(env, SPR_POWER_PMC5, "PMC5",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PMC5, 0x00000000);
    spr_register_kvm(env, SPR_POWER_PMC6, "PMC6",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PMC6, 0x00000000);
    spr_register_kvm(env, SPR_POWER_SIAR, "SIAR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_SIAR, 0x00000000);
    spr_register_kvm(env, SPR_POWER_SDAR, "SDAR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_SDAR, 0x00000000);
}

static void gen_spr_book3s_pmu_user(CPUPPCState *env)
{
    spr_register(env, SPR_POWER_UMMCR0, "UMMCR0",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_UMMCR1, "UMMCR1",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_UMMCRA, "UMMCRA",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_UPMC1, "UPMC1",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_UPMC2, "UPMC2",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_UPMC3, "UPMC3",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_UPMC4, "UPMC4",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_UPMC5, "UPMC5",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_UPMC6, "UPMC6",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_USIAR, "USIAR",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_USDAR, "USDAR",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
}

static void gen_spr_970_pmu_sup(CPUPPCState *env)
{
    spr_register_kvm(env, SPR_970_PMC7, "PMC7",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PMC7, 0x00000000);
    spr_register_kvm(env, SPR_970_PMC8, "PMC8",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PMC8, 0x00000000);
}

static void gen_spr_970_pmu_user(CPUPPCState *env)
{
    spr_register(env, SPR_970_UPMC7, "UPMC7",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_970_UPMC8, "UPMC8",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
}

static void gen_spr_power8_pmu_sup(CPUPPCState *env)
{
    spr_register_kvm(env, SPR_POWER_MMCR2, "MMCR2",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_MMCR2, 0x00000000);
    spr_register_kvm(env, SPR_POWER_MMCRS, "MMCRS",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_MMCRS, 0x00000000);
    spr_register_kvm(env, SPR_POWER_SIER, "SIER",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_SIER, 0x00000000);
    spr_register_kvm(env, SPR_POWER_SPMC1, "SPMC1",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_SPMC1, 0x00000000);
    spr_register_kvm(env, SPR_POWER_SPMC2, "SPMC2",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_SPMC2, 0x00000000);
    spr_register_kvm(env, SPR_TACR, "TACR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_TACR, 0x00000000);
    spr_register_kvm(env, SPR_TCSCR, "TCSCR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_TCSCR, 0x00000000);
    spr_register_kvm(env, SPR_CSIGR, "CSIGR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_CSIGR, 0x00000000);
}

static void gen_spr_power8_pmu_user(CPUPPCState *env)
{
    spr_register(env, SPR_POWER_UMMCR2, "UMMCR2",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
                 0x00000000);
    spr_register(env, SPR_POWER_USIER, "USIER",
                 &spr_read_generic, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_power5p_ear(CPUPPCState *env)
{
    /* External access control */
    spr_register(env, SPR_EAR, "EAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_power5p_tb(CPUPPCState *env)
{
    /* TBU40 (High 40 bits of the Timebase register */
    spr_register_hv(env, SPR_TBU40, "TBU40",
                    SPR_NOACCESS, SPR_NOACCESS,
                    SPR_NOACCESS, SPR_NOACCESS,
                    SPR_NOACCESS, &spr_write_tbu40,
                    0x00000000);
}

static void spr_write_hmer(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv hmer = tcg_temp_new(tcg_ctx);

    gen_load_spr(tcg_ctx, hmer, sprn);
    tcg_gen_and_tl(tcg_ctx, hmer, cpu_gpr[gprn], hmer);
    gen_store_spr(tcg_ctx, sprn, hmer);
    spr_store_dump_spr(sprn);
    tcg_temp_free(tcg_ctx, hmer);
}

static void spr_write_lpcr(DisasContext *ctx, int sprn, int gprn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    gen_helper_store_lpcr(tcg_ctx, tcg_ctx->cpu_env, cpu_gpr[gprn]);
}

static void gen_spr_970_lpar(CPUPPCState *env)
{
    /*
     * PPC970: HID4 covers things later controlled by the LPCR and
     * RMOR in later CPUs, but with a different encoding.  We only
     * support the 970 in "Apple mode" which has all hypervisor
     * facilities disabled by strapping, so we can basically just
     * ignore it
     */
    spr_register(env, SPR_970_HID4, "HID4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_power5p_lpar(CPUPPCState *env)
{
    /* Logical partitionning */
    spr_register_kvm_hv(env, SPR_LPCR, "LPCR",
                        SPR_NOACCESS, SPR_NOACCESS,
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_generic, &spr_write_lpcr,
                        KVM_REG_PPC_LPCR, LPCR_LPES0 | LPCR_LPES1);
    spr_register_hv(env, SPR_HDEC, "HDEC",
                    SPR_NOACCESS, SPR_NOACCESS,
                    SPR_NOACCESS, SPR_NOACCESS,
                    &spr_read_hdecr, &spr_write_hdecr, 0);
}

static void gen_spr_book3s_ids(CPUPPCState *env)
{
    /* FIXME: Will need to deal with thread vs core only SPRs */

    /* Processor identification */
    spr_register_hv(env, SPR_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 &spr_read_generic, NULL,
                 0x00000000);
    spr_register_hv(env, SPR_HID0, "HID0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_TSCR, "TSCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_HMER, "HMER",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_hmer,
                 0x00000000);
    spr_register_hv(env, SPR_HMEER, "HMEER",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_TFMR, "TFMR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_LPIDR, "LPIDR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_lpidr,
                 0x00000000);
    spr_register_hv(env, SPR_HFSCR, "HFSCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_MMCRC, "MMCRC",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_MMCRH, "MMCRH",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_HSPRG0, "HSPRG0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_HSPRG1, "HSPRG1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_HSRR0, "HSRR0",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_HSRR1, "HSRR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_HDAR, "HDAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_HDSISR, "HDSISR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register_hv(env, SPR_HRMOR, "HRMOR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_rmor(CPUPPCState *env)
{
    spr_register_hv(env, SPR_RMOR, "RMOR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_power8_ids(CPUPPCState *env)
{
    /* Thread identification */
    spr_register(env, SPR_TIR, "TIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000);
}

static void gen_spr_book3s_purr(CPUPPCState *env)
{
    /* PURR & SPURR: Hack - treat these as aliases for the TB for now */
    spr_register_kvm_hv(env, SPR_PURR,   "PURR",
                        &spr_read_purr, SPR_NOACCESS,
                        &spr_read_purr, SPR_NOACCESS,
                        &spr_read_purr, &spr_write_purr,
                        KVM_REG_PPC_PURR, 0x00000000);
    spr_register_kvm_hv(env, SPR_SPURR,   "SPURR",
                        &spr_read_purr, SPR_NOACCESS,
                        &spr_read_purr, SPR_NOACCESS,
                        &spr_read_purr, &spr_write_purr,
                        KVM_REG_PPC_SPURR, 0x00000000);
}

static void gen_spr_power6_dbg(CPUPPCState *env)
{
    spr_register(env, SPR_CFAR, "SPR_CFAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_cfar, &spr_write_cfar,
                 0x00000000);
}

static void gen_spr_power5p_common(CPUPPCState *env)
{
    spr_register_kvm(env, SPR_PPR, "PPR",
                     &spr_read_generic, &spr_write_generic,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PPR, 0x00000000);
}

static void gen_spr_power6_common(CPUPPCState *env)
{
    spr_register_kvm(env, SPR_DSCR, "SPR_DSCR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DSCR, 0x00000000);
    /*
     * Register PCR to report POWERPC_EXCP_PRIV_REG instead of
     * POWERPC_EXCP_INVAL_SPR in userspace. Permit hypervisor access.
     */
    spr_register_hv(env, SPR_PCR, "PCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pcr,
                 0x00000000);
}

static void spr_read_tar(DisasContext *ctx, int gprn, int sprn)
{
    gen_fscr_facility_check(ctx, SPR_FSCR, FSCR_TAR, sprn, FSCR_IC_TAR);
    spr_read_generic(ctx, gprn, sprn);
}

static void spr_write_tar(DisasContext *ctx, int sprn, int gprn)
{
    gen_fscr_facility_check(ctx, SPR_FSCR, FSCR_TAR, sprn, FSCR_IC_TAR);
    spr_write_generic(ctx, sprn, gprn);
}

static void gen_spr_power8_tce_address_control(CPUPPCState *env)
{
    spr_register_kvm(env, SPR_TAR, "TAR",
                     &spr_read_tar, &spr_write_tar,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_TAR, 0x00000000);
}

static void spr_read_tm(DisasContext *ctx, int gprn, int sprn)
{
    gen_msr_facility_check(ctx, SPR_FSCR, MSR_TM, sprn, FSCR_IC_TM);
    spr_read_generic(ctx, gprn, sprn);
}

static void spr_write_tm(DisasContext *ctx, int sprn, int gprn)
{
    gen_msr_facility_check(ctx, SPR_FSCR, MSR_TM, sprn, FSCR_IC_TM);
    spr_write_generic(ctx, sprn, gprn);
}

static void spr_read_tm_upper32(DisasContext *ctx, int gprn, int sprn)
{
    gen_msr_facility_check(ctx, SPR_FSCR, MSR_TM, sprn, FSCR_IC_TM);
    spr_read_prev_upper32(ctx, gprn, sprn);
}

static void spr_write_tm_upper32(DisasContext *ctx, int sprn, int gprn)
{
    gen_msr_facility_check(ctx, SPR_FSCR, MSR_TM, sprn, FSCR_IC_TM);
    spr_write_prev_upper32(ctx, sprn, gprn);
}

static void gen_spr_power8_tm(CPUPPCState *env)
{
    spr_register_kvm(env, SPR_TFHAR, "TFHAR",
                     &spr_read_tm, &spr_write_tm,
                     &spr_read_tm, &spr_write_tm,
                     KVM_REG_PPC_TFHAR, 0x00000000);
    spr_register_kvm(env, SPR_TFIAR, "TFIAR",
                     &spr_read_tm, &spr_write_tm,
                     &spr_read_tm, &spr_write_tm,
                     KVM_REG_PPC_TFIAR, 0x00000000);
    spr_register_kvm(env, SPR_TEXASR, "TEXASR",
                     &spr_read_tm, &spr_write_tm,
                     &spr_read_tm, &spr_write_tm,
                     KVM_REG_PPC_TEXASR, 0x00000000);
    spr_register(env, SPR_TEXASRU, "TEXASRU",
                 &spr_read_tm_upper32, &spr_write_tm_upper32,
                 &spr_read_tm_upper32, &spr_write_tm_upper32,
                 0x00000000);
}

static void spr_read_ebb(DisasContext *ctx, int gprn, int sprn)
{
    gen_fscr_facility_check(ctx, SPR_FSCR, FSCR_EBB, sprn, FSCR_IC_EBB);
    spr_read_generic(ctx, gprn, sprn);
}

static void spr_write_ebb(DisasContext *ctx, int sprn, int gprn)
{
    gen_fscr_facility_check(ctx, SPR_FSCR, FSCR_EBB, sprn, FSCR_IC_EBB);
    spr_write_generic(ctx, sprn, gprn);
}

static void spr_read_ebb_upper32(DisasContext *ctx, int gprn, int sprn)
{
    gen_fscr_facility_check(ctx, SPR_FSCR, FSCR_EBB, sprn, FSCR_IC_EBB);
    spr_read_prev_upper32(ctx, gprn, sprn);
}

static void spr_write_ebb_upper32(DisasContext *ctx, int sprn, int gprn)
{
    gen_fscr_facility_check(ctx, SPR_FSCR, FSCR_EBB, sprn, FSCR_IC_EBB);
    spr_write_prev_upper32(ctx, sprn, gprn);
}

static void gen_spr_power8_ebb(CPUPPCState *env)
{
    spr_register(env, SPR_BESCRS, "BESCRS",
                 &spr_read_ebb, &spr_write_ebb,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BESCRSU, "BESCRSU",
                 &spr_read_ebb_upper32, &spr_write_ebb_upper32,
                 &spr_read_prev_upper32, &spr_write_prev_upper32,
                 0x00000000);
    spr_register(env, SPR_BESCRR, "BESCRR",
                 &spr_read_ebb, &spr_write_ebb,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
    spr_register(env, SPR_BESCRRU, "BESCRRU",
                 &spr_read_ebb_upper32, &spr_write_ebb_upper32,
                 &spr_read_prev_upper32, &spr_write_prev_upper32,
                 0x00000000);
    spr_register_kvm(env, SPR_EBBHR, "EBBHR",
                     &spr_read_ebb, &spr_write_ebb,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_EBBHR, 0x00000000);
    spr_register_kvm(env, SPR_EBBRR, "EBBRR",
                     &spr_read_ebb, &spr_write_ebb,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_EBBRR, 0x00000000);
    spr_register_kvm(env, SPR_BESCR, "BESCR",
                     &spr_read_ebb, &spr_write_ebb,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_BESCR, 0x00000000);
}

/* Virtual Time Base */
static void gen_spr_vtb(CPUPPCState *env)
{
    spr_register_kvm_hv(env, SPR_VTB, "VTB",
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_vtb, SPR_NOACCESS,
                        &spr_read_vtb, &spr_write_vtb,
                        KVM_REG_PPC_VTB, 0x00000000);
}

static void gen_spr_power8_fscr(CPUPPCState *env)
{
    target_ulong initval = 0;
    spr_register_kvm(env, SPR_FSCR, "FSCR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_FSCR, initval);
}

static void gen_spr_power8_pspb(CPUPPCState *env)
{
    spr_register_kvm(env, SPR_PSPB, "PSPB",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic32,
                     KVM_REG_PPC_PSPB, 0);
}

static void gen_spr_power8_dpdes(CPUPPCState *env)
{
    /* Directed Privileged Door-bell Exception State, used for IPI */
    spr_register_kvm_hv(env, SPR_DPDES, "DPDES",
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_dpdes, SPR_NOACCESS,
                        &spr_read_dpdes, &spr_write_dpdes,
                        KVM_REG_PPC_DPDES, 0x00000000);
}

static void gen_spr_power8_ic(CPUPPCState *env)
{
    spr_register_hv(env, SPR_IC, "IC",
                    SPR_NOACCESS, SPR_NOACCESS,
                    &spr_read_generic, SPR_NOACCESS,
                    &spr_read_generic, &spr_write_generic,
                    0);
}

static void gen_spr_power8_book4(CPUPPCState *env)
{
    /* Add a number of P8 book4 registers */
    spr_register_kvm(env, SPR_ACOP, "ACOP",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_ACOP, 0);
    spr_register_kvm(env, SPR_BOOKS_PID, "PID",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_pidr,
                     KVM_REG_PPC_PID, 0);
    spr_register_kvm(env, SPR_WORT, "WORT",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_WORT, 0);
}

static void gen_spr_power7_book4(CPUPPCState *env)
{
    /* Add a number of P7 book4 registers */
    spr_register_kvm(env, SPR_ACOP, "ACOP",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_ACOP, 0);
    spr_register_kvm(env, SPR_BOOKS_PID, "PID",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_PID, 0);
}

static void gen_spr_power8_rpr(CPUPPCState *env)
{
    spr_register_hv(env, SPR_RPR, "RPR",
                    SPR_NOACCESS, SPR_NOACCESS,
                    SPR_NOACCESS, SPR_NOACCESS,
                    &spr_read_generic, &spr_write_generic,
                    0x00000103070F1F3F);
}

static void gen_spr_power9_mmu(CPUPPCState *env)
{
    /* Partition Table Control */
    spr_register_kvm_hv(env, SPR_PTCR, "PTCR",
                        SPR_NOACCESS, SPR_NOACCESS,
                        SPR_NOACCESS, SPR_NOACCESS,
                        &spr_read_generic, &spr_write_ptcr,
                        KVM_REG_PPC_PTCR, 0x00000000);
    /* Address Segment Descriptor Register */
    spr_register_hv(env, SPR_ASDR, "ASDR",
                    SPR_NOACCESS, SPR_NOACCESS,
                    SPR_NOACCESS, SPR_NOACCESS,
                    &spr_read_generic, &spr_write_generic,
                    0x0000000000000000);
}

static void init_proc_book3s_common(CPUPPCState *env)
{
    gen_spr_ne_601(env);
    gen_tbl(env);
    gen_spr_usprg3(env);
    gen_spr_book3s_altivec(env);
    gen_spr_book3s_pmu_sup(env);
    gen_spr_book3s_pmu_user(env);
    gen_spr_book3s_ctrl(env);
}

static void init_proc_970(CPUPPCState *env)
{
    /* Common Registers */
    init_proc_book3s_common(env);
    gen_spr_sdr1(env);
    gen_spr_book3s_dbg(env);

    /* 970 Specific Registers */
    gen_spr_970_hid(env);
    gen_spr_970_hior(env);
    gen_low_BATs(env);
    gen_spr_970_pmu_sup(env);
    gen_spr_970_pmu_user(env);
    gen_spr_970_lpar(env);
    gen_spr_970_dbg(env);

    /* env variables */
    env->dcache_line_size = 128;
    env->icache_line_size = 128;

    /* Allocate hardware IRQ controller */
    init_excp_970(env);
    ppc970_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(970)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->desc = "PowerPC 970";
    pcc->init_proc = init_proc_970;
    pcc->check_pow = check_pow_970;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_64B | PPC_ALTIVEC |
                       PPC_SEGMENT_64B | PPC_SLBI;
    pcc->insns_flags2 = PPC2_FP_CVT_S64;
    pcc->msr_mask = (1ull << MSR_SF) |
                    (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI);
    pcc->mmu_model = POWERPC_MMU_64B;
    pcc->handle_mmu_fault = ppc_hash64_handle_mmu_fault;
    pcc->hash64_opts = &ppc_hash64_opts_basic;
    pcc->excp_model = POWERPC_EXCP_970;
    pcc->bus_model = PPC_FLAGS_INPUT_970;
    pcc->bfd_mach = bfd_mach_ppc64;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
    pcc->l1_dcache_size = 0x8000;
    pcc->l1_icache_size = 0x10000;
}

static void init_proc_power5plus(CPUPPCState *env)
{
    /* Common Registers */
    init_proc_book3s_common(env);
    gen_spr_sdr1(env);
    gen_spr_book3s_dbg(env);

    /* POWER5+ Specific Registers */
    gen_spr_970_hid(env);
    gen_spr_970_hior(env);
    gen_low_BATs(env);
    gen_spr_970_pmu_sup(env);
    gen_spr_970_pmu_user(env);
    gen_spr_power5p_common(env);
    gen_spr_power5p_lpar(env);
    gen_spr_power5p_ear(env);
    gen_spr_power5p_tb(env);

    /* env variables */
    env->dcache_line_size = 128;
    env->icache_line_size = 128;

    /* Allocate hardware IRQ controller */
    init_excp_970(env);
    ppc970_irq_init(env_archcpu(env));
}

POWERPC_FAMILY(POWER5P)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);

//    dc->fw_name = "PowerPC,POWER5";
//    dc->desc = "POWER5+";
    pcc->init_proc = init_proc_power5plus;
    pcc->check_pow = check_pow_970;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_64B |
                       PPC_SEGMENT_64B | PPC_SLBI;
    pcc->insns_flags2 = PPC2_FP_CVT_S64;
    pcc->msr_mask = (1ull << MSR_SF) |
                    (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI);
    pcc->lpcr_mask = LPCR_RMLS | LPCR_ILE | LPCR_LPES0 | LPCR_LPES1 |
        LPCR_RMI | LPCR_HDICE;
    pcc->mmu_model = POWERPC_MMU_2_03;
    pcc->handle_mmu_fault = ppc_hash64_handle_mmu_fault;
    pcc->hash64_opts = &ppc_hash64_opts_basic;
    pcc->lrg_decr_bits = 32;
    pcc->excp_model = POWERPC_EXCP_970;
    pcc->bus_model = PPC_FLAGS_INPUT_970;
    pcc->bfd_mach = bfd_mach_ppc64;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
    pcc->l1_dcache_size = 0x8000;
    pcc->l1_icache_size = 0x10000;
}

static void init_proc_POWER7(CPUPPCState *env)
{
    /* Common Registers */
    init_proc_book3s_common(env);
    gen_spr_sdr1(env);
    gen_spr_book3s_dbg(env);

    /* POWER7 Specific Registers */
    gen_spr_book3s_ids(env);
    gen_spr_rmor(env);
    gen_spr_amr(env);
    gen_spr_book3s_purr(env);
    gen_spr_power5p_common(env);
    gen_spr_power5p_lpar(env);
    gen_spr_power5p_ear(env);
    gen_spr_power5p_tb(env);
    gen_spr_power6_common(env);
    gen_spr_power6_dbg(env);
    gen_spr_power7_book4(env);

    /* env variables */
    env->dcache_line_size = 128;
    env->icache_line_size = 128;

    /* Allocate hardware IRQ controller */
    init_excp_POWER7(env);
    ppcPOWER7_irq_init(env_archcpu(env));
}

static bool ppc_pvr_match_power7(PowerPCCPUClass *pcc, uint32_t pvr)
{
    if ((pvr & CPU_POWERPC_POWER_SERVER_MASK) == CPU_POWERPC_POWER7P_BASE) {
        return true;
    }
    if ((pvr & CPU_POWERPC_POWER_SERVER_MASK) == CPU_POWERPC_POWER7_BASE) {
        return true;
    }
    return false;
}

static bool cpu_has_work_POWER7(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    if (cs->halted) {
        if (!(cs->interrupt_request & CPU_INTERRUPT_HARD)) {
            return false;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_EXT)) &&
            (env->spr[SPR_LPCR] & LPCR_P7_PECE0)) {
            return true;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_DECR)) &&
            (env->spr[SPR_LPCR] & LPCR_P7_PECE1)) {
            return true;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_MCK)) &&
            (env->spr[SPR_LPCR] & LPCR_P7_PECE2)) {
            return true;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_HMI)) &&
            (env->spr[SPR_LPCR] & LPCR_P7_PECE2)) {
            return true;
        }
        if (env->pending_interrupts & (1u << PPC_INTERRUPT_RESET)) {
            return true;
        }
        return false;
    } else {
        return msr_ee && (cs->interrupt_request & CPU_INTERRUPT_HARD);
    }
}

POWERPC_FAMILY(POWER7)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);

//    dc->fw_name = "PowerPC,POWER7";
//    dc->desc = "POWER7";
    pcc->pvr_match = ppc_pvr_match_power7;
    pcc->pcr_mask = PCR_VEC_DIS | PCR_VSX_DIS | PCR_COMPAT_2_05;
    pcc->pcr_supported = PCR_COMPAT_2_06 | PCR_COMPAT_2_05;
    pcc->init_proc = init_proc_POWER7;
    pcc->check_pow = check_pow_nocheck;
    cc->has_work = cpu_has_work_POWER7;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_FRSQRTES |
                       PPC_FLOAT_STFIWX |
                       PPC_FLOAT_EXT |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_64B | PPC_64H | PPC_64BX | PPC_ALTIVEC |
                       PPC_SEGMENT_64B | PPC_SLBI |
                       PPC_POPCNTB | PPC_POPCNTWD |
                       PPC_CILDST;
    pcc->insns_flags2 = PPC2_VSX | PPC2_DFP | PPC2_DBRX | PPC2_ISA205 |
                        PPC2_PERM_ISA206 | PPC2_DIVE_ISA206 |
                        PPC2_ATOMIC_ISA206 | PPC2_FP_CVT_ISA206 |
                        PPC2_FP_TST_ISA206 | PPC2_FP_CVT_S64 |
                        PPC2_PM_ISA206;
    pcc->msr_mask = (1ull << MSR_SF) |
                    (1ull << MSR_VR) |
                    (1ull << MSR_VSX) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->lpcr_mask = LPCR_VPM0 | LPCR_VPM1 | LPCR_ISL | LPCR_DPFD |
        LPCR_VRMASD | LPCR_RMLS | LPCR_ILE |
        LPCR_P7_PECE0 | LPCR_P7_PECE1 | LPCR_P7_PECE2 |
        LPCR_MER | LPCR_TC |
        LPCR_LPES0 | LPCR_LPES1 | LPCR_HDICE;
    pcc->lpcr_pm = LPCR_P7_PECE0 | LPCR_P7_PECE1 | LPCR_P7_PECE2;
    pcc->mmu_model = POWERPC_MMU_2_06;
    pcc->handle_mmu_fault = ppc_hash64_handle_mmu_fault;
    pcc->hash64_opts = &ppc_hash64_opts_POWER7;
    pcc->lrg_decr_bits = 32;
    pcc->excp_model = POWERPC_EXCP_POWER7;
    pcc->bus_model = PPC_FLAGS_INPUT_POWER7;
    pcc->bfd_mach = bfd_mach_ppc64;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK | POWERPC_FLAG_CFAR |
                 POWERPC_FLAG_VSX;
    pcc->l1_dcache_size = 0x8000;
    pcc->l1_icache_size = 0x8000;
    pcc->interrupts_big_endian = ppc_cpu_interrupts_big_endian_lpcr;
}

static void init_proc_POWER8(CPUPPCState *env)
{
    /* Common Registers */
    init_proc_book3s_common(env);
    gen_spr_sdr1(env);
    gen_spr_book3s_207_dbg(env);

    /* POWER8 Specific Registers */
    gen_spr_book3s_ids(env);
    gen_spr_rmor(env);
    gen_spr_amr(env);
    gen_spr_iamr(env);
    gen_spr_book3s_purr(env);
    gen_spr_power5p_common(env);
    gen_spr_power5p_lpar(env);
    gen_spr_power5p_ear(env);
    gen_spr_power5p_tb(env);
    gen_spr_power6_common(env);
    gen_spr_power6_dbg(env);
    gen_spr_power8_tce_address_control(env);
    gen_spr_power8_ids(env);
    gen_spr_power8_ebb(env);
    gen_spr_power8_fscr(env);
    gen_spr_power8_pmu_sup(env);
    gen_spr_power8_pmu_user(env);
    gen_spr_power8_tm(env);
    gen_spr_power8_pspb(env);
    gen_spr_power8_dpdes(env);
    gen_spr_vtb(env);
    gen_spr_power8_ic(env);
    gen_spr_power8_book4(env);
    gen_spr_power8_rpr(env);

    /* env variables */
    env->dcache_line_size = 128;
    env->icache_line_size = 128;

    /* Allocate hardware IRQ controller */
    init_excp_POWER8(env);
    ppcPOWER7_irq_init(env_archcpu(env));
}

static bool ppc_pvr_match_power8(PowerPCCPUClass *pcc, uint32_t pvr)
{
    if ((pvr & CPU_POWERPC_POWER_SERVER_MASK) == CPU_POWERPC_POWER8NVL_BASE) {
        return true;
    }
    if ((pvr & CPU_POWERPC_POWER_SERVER_MASK) == CPU_POWERPC_POWER8E_BASE) {
        return true;
    }
    if ((pvr & CPU_POWERPC_POWER_SERVER_MASK) == CPU_POWERPC_POWER8_BASE) {
        return true;
    }
    return false;
}

static bool cpu_has_work_POWER8(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    if (cs->halted) {
        if (!(cs->interrupt_request & CPU_INTERRUPT_HARD)) {
            return false;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_EXT)) &&
            (env->spr[SPR_LPCR] & LPCR_P8_PECE2)) {
            return true;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_DECR)) &&
            (env->spr[SPR_LPCR] & LPCR_P8_PECE3)) {
            return true;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_MCK)) &&
            (env->spr[SPR_LPCR] & LPCR_P8_PECE4)) {
            return true;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_HMI)) &&
            (env->spr[SPR_LPCR] & LPCR_P8_PECE4)) {
            return true;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_DOORBELL)) &&
            (env->spr[SPR_LPCR] & LPCR_P8_PECE0)) {
            return true;
        }
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_HDOORBELL)) &&
            (env->spr[SPR_LPCR] & LPCR_P8_PECE1)) {
            return true;
        }
        if (env->pending_interrupts & (1u << PPC_INTERRUPT_RESET)) {
            return true;
        }
        return false;
    } else {
        return msr_ee && (cs->interrupt_request & CPU_INTERRUPT_HARD);
    }
}

POWERPC_FAMILY(POWER8)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);

//    dc->fw_name = "PowerPC,POWER8";
//    dc->desc = "POWER8";
    pcc->pvr_match = ppc_pvr_match_power8;
    pcc->pcr_mask = PCR_TM_DIS | PCR_COMPAT_2_06 | PCR_COMPAT_2_05;
    pcc->pcr_supported = PCR_COMPAT_2_07 | PCR_COMPAT_2_06 | PCR_COMPAT_2_05;
    pcc->init_proc = init_proc_POWER8;
    pcc->check_pow = check_pow_nocheck;
    cc->has_work = cpu_has_work_POWER8;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_FRSQRTES |
                       PPC_FLOAT_STFIWX |
                       PPC_FLOAT_EXT |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_64B | PPC_64H | PPC_64BX | PPC_ALTIVEC |
                       PPC_SEGMENT_64B | PPC_SLBI |
                       PPC_POPCNTB | PPC_POPCNTWD |
                       PPC_CILDST;
    pcc->insns_flags2 = PPC2_VSX | PPC2_VSX207 | PPC2_DFP | PPC2_DBRX |
                        PPC2_PERM_ISA206 | PPC2_DIVE_ISA206 |
                        PPC2_ATOMIC_ISA206 | PPC2_FP_CVT_ISA206 |
                        PPC2_FP_TST_ISA206 | PPC2_BCTAR_ISA207 |
                        PPC2_LSQ_ISA207 | PPC2_ALTIVEC_207 |
                        PPC2_ISA205 | PPC2_ISA207S | PPC2_FP_CVT_S64 |
                        PPC2_TM | PPC2_PM_ISA206;
    pcc->msr_mask = (1ull << MSR_SF) |
                    (1ull << MSR_HV) |
                    (1ull << MSR_TM) |
                    (1ull << MSR_VR) |
                    (1ull << MSR_VSX) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_TS0) |
                    (1ull << MSR_TS1) |
                    (1ull << MSR_LE);
    pcc->lpcr_mask = LPCR_VPM0 | LPCR_VPM1 | LPCR_ISL | LPCR_KBV |
        LPCR_DPFD | LPCR_VRMASD | LPCR_RMLS | LPCR_ILE |
        LPCR_AIL | LPCR_ONL | LPCR_P8_PECE0 | LPCR_P8_PECE1 |
        LPCR_P8_PECE2 | LPCR_P8_PECE3 | LPCR_P8_PECE4 |
        LPCR_MER | LPCR_TC | LPCR_LPES0 | LPCR_HDICE;
    pcc->lpcr_pm = LPCR_P8_PECE0 | LPCR_P8_PECE1 | LPCR_P8_PECE2 |
                   LPCR_P8_PECE3 | LPCR_P8_PECE4;
    pcc->mmu_model = POWERPC_MMU_2_07;
    pcc->handle_mmu_fault = ppc_hash64_handle_mmu_fault;
    pcc->hash64_opts = &ppc_hash64_opts_POWER7;
    pcc->lrg_decr_bits = 32;
    pcc->n_host_threads = 8;
    pcc->excp_model = POWERPC_EXCP_POWER8;
    pcc->bus_model = PPC_FLAGS_INPUT_POWER7;
    pcc->bfd_mach = bfd_mach_ppc64;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK | POWERPC_FLAG_CFAR |
                 POWERPC_FLAG_VSX | POWERPC_FLAG_TM;
    pcc->l1_dcache_size = 0x8000;
    pcc->l1_icache_size = 0x8000;
    pcc->interrupts_big_endian = ppc_cpu_interrupts_big_endian_lpcr;
}

/*
 * Radix pg sizes and AP encodings for dt node ibm,processor-radix-AP-encodings
 * Encoded as array of int_32s in the form:
 *  0bxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
 *  x -> AP encoding
 *  y -> radix mode supported page size (encoded as a shift)
 */
static struct ppc_radix_page_info POWER9_radix_page_info = {
    .count = 4,
    .entries = {
        0x0000000c, /*  4K - enc: 0x0 */
        0xa0000010, /* 64K - enc: 0x5 */
        0x20000015, /*  2M - enc: 0x1 */
        0x4000001e  /*  1G - enc: 0x2 */
    }
};

static void init_proc_POWER9(CPUPPCState *env)
{
    /* Common Registers */
    init_proc_book3s_common(env);
    gen_spr_book3s_207_dbg(env);

    /* POWER8 Specific Registers */
    gen_spr_book3s_ids(env);
    gen_spr_amr(env);
    gen_spr_iamr(env);
    gen_spr_book3s_purr(env);
    gen_spr_power5p_common(env);
    gen_spr_power5p_lpar(env);
    gen_spr_power5p_ear(env);
    gen_spr_power5p_tb(env);
    gen_spr_power6_common(env);
    gen_spr_power6_dbg(env);
    gen_spr_power8_tce_address_control(env);
    gen_spr_power8_ids(env);
    gen_spr_power8_ebb(env);
    gen_spr_power8_fscr(env);
    gen_spr_power8_pmu_sup(env);
    gen_spr_power8_pmu_user(env);
    gen_spr_power8_tm(env);
    gen_spr_power8_pspb(env);
    gen_spr_power8_dpdes(env);
    gen_spr_vtb(env);
    gen_spr_power8_ic(env);
    gen_spr_power8_book4(env);
    gen_spr_power8_rpr(env);
    gen_spr_power9_mmu(env);

    /* POWER9 Specific registers */
    spr_register_kvm(env, SPR_TIDR, "TIDR", NULL, NULL,
                     spr_read_generic, spr_write_generic,
                     KVM_REG_PPC_TIDR, 0);

    /* FIXME: Filter fields properly based on privilege level */
    spr_register_kvm_hv(env, SPR_PSSCR, "PSSCR", NULL, NULL, NULL, NULL,
                        spr_read_generic, spr_write_generic,
                        KVM_REG_PPC_PSSCR, 0);

    /* env variables */
    env->dcache_line_size = 128;
    env->icache_line_size = 128;

    /* Allocate hardware IRQ controller */
    init_excp_POWER9(env);
    ppcPOWER9_irq_init(env_archcpu(env));
}

static bool ppc_pvr_match_power9(PowerPCCPUClass *pcc, uint32_t pvr)
{
    if ((pvr & CPU_POWERPC_POWER_SERVER_MASK) == CPU_POWERPC_POWER9_BASE) {
        return true;
    }
    return false;
}

static bool cpu_has_work_POWER9(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    if (cs->halted) {
        uint64_t psscr = env->spr[SPR_PSSCR];

        if (!(cs->interrupt_request & CPU_INTERRUPT_HARD)) {
            return false;
        }

        /* If EC is clear, just return true on any pending interrupt */
        if (!(psscr & PSSCR_EC)) {
            return true;
        }
        /* External Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_EXT)) &&
            (env->spr[SPR_LPCR] & LPCR_EEE)) {
            bool heic = !!(env->spr[SPR_LPCR] & LPCR_HEIC);
            if (heic == 0 || !msr_hv || msr_pr) {
                return true;
            }
        }
        /* Decrementer Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_DECR)) &&
            (env->spr[SPR_LPCR] & LPCR_DEE)) {
            return true;
        }
        /* Machine Check or Hypervisor Maintenance Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_MCK |
            1u << PPC_INTERRUPT_HMI)) && (env->spr[SPR_LPCR] & LPCR_OEE)) {
            return true;
        }
        /* Privileged Doorbell Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_DOORBELL)) &&
            (env->spr[SPR_LPCR] & LPCR_PDEE)) {
            return true;
        }
        /* Hypervisor Doorbell Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_HDOORBELL)) &&
            (env->spr[SPR_LPCR] & LPCR_HDEE)) {
            return true;
        }
        /* Hypervisor virtualization exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_HVIRT)) &&
            (env->spr[SPR_LPCR] & LPCR_HVEE)) {
            return true;
        }
        if (env->pending_interrupts & (1u << PPC_INTERRUPT_RESET)) {
            return true;
        }
        return false;
    } else {
        return msr_ee && (cs->interrupt_request & CPU_INTERRUPT_HARD);
    }
}

POWERPC_FAMILY(POWER9)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);

//    dc->fw_name = "PowerPC,POWER9";
//    dc->desc = "POWER9";
    pcc->pvr_match = ppc_pvr_match_power9;
    pcc->pcr_mask = PCR_COMPAT_2_05 | PCR_COMPAT_2_06 | PCR_COMPAT_2_07;
    pcc->pcr_supported = PCR_COMPAT_3_00 | PCR_COMPAT_2_07 | PCR_COMPAT_2_06 |
                         PCR_COMPAT_2_05;
    pcc->init_proc = init_proc_POWER9;
    pcc->check_pow = check_pow_nocheck;
    cc->has_work = cpu_has_work_POWER9;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_FRSQRTES |
                       PPC_FLOAT_STFIWX |
                       PPC_FLOAT_EXT |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBSYNC |
                       PPC_64B | PPC_64H | PPC_64BX | PPC_ALTIVEC |
                       PPC_SEGMENT_64B | PPC_SLBI |
                       PPC_POPCNTB | PPC_POPCNTWD |
                       PPC_CILDST;
    pcc->insns_flags2 = PPC2_VSX | PPC2_VSX207 | PPC2_DFP | PPC2_DBRX |
                        PPC2_PERM_ISA206 | PPC2_DIVE_ISA206 |
                        PPC2_ATOMIC_ISA206 | PPC2_FP_CVT_ISA206 |
                        PPC2_FP_TST_ISA206 | PPC2_BCTAR_ISA207 |
                        PPC2_LSQ_ISA207 | PPC2_ALTIVEC_207 |
                        PPC2_ISA205 | PPC2_ISA207S | PPC2_FP_CVT_S64 |
                        PPC2_TM | PPC2_ISA300 | PPC2_PRCNTL;
    pcc->msr_mask = (1ull << MSR_SF) |
                    (1ull << MSR_HV) |
                    (1ull << MSR_TM) |
                    (1ull << MSR_VR) |
                    (1ull << MSR_VSX) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->lpcr_mask = LPCR_VPM1 | LPCR_ISL | LPCR_KBV | LPCR_DPFD |
        (LPCR_PECE_U_MASK & LPCR_HVEE) | LPCR_ILE | LPCR_AIL |
        LPCR_UPRT | LPCR_EVIRT | LPCR_ONL | LPCR_HR | LPCR_LD |
        (LPCR_PECE_L_MASK & (LPCR_PDEE | LPCR_HDEE | LPCR_EEE |
                             LPCR_DEE | LPCR_OEE))
        | LPCR_MER | LPCR_GTSE | LPCR_TC |
        LPCR_HEIC | LPCR_LPES0 | LPCR_HVICE | LPCR_HDICE;
    pcc->lpcr_pm = LPCR_PDEE | LPCR_HDEE | LPCR_EEE | LPCR_DEE | LPCR_OEE;
    pcc->mmu_model = POWERPC_MMU_3_00;
    pcc->handle_mmu_fault = ppc64_v3_handle_mmu_fault;
    /* segment page size remain the same */
    pcc->hash64_opts = &ppc_hash64_opts_POWER7;
    pcc->radix_page_info = &POWER9_radix_page_info;
    pcc->lrg_decr_bits = 56;
    pcc->n_host_threads = 4;
    pcc->excp_model = POWERPC_EXCP_POWER9;
    pcc->bus_model = PPC_FLAGS_INPUT_POWER9;
    pcc->bfd_mach = bfd_mach_ppc64;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK | POWERPC_FLAG_CFAR |
                 POWERPC_FLAG_VSX | POWERPC_FLAG_TM;
    pcc->l1_dcache_size = 0x8000;
    pcc->l1_icache_size = 0x8000;
    pcc->interrupts_big_endian = ppc_cpu_interrupts_big_endian_lpcr;
}

/*
 * Radix pg sizes and AP encodings for dt node ibm,processor-radix-AP-encodings
 * Encoded as array of int_32s in the form:
 *  0bxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
 *  x -> AP encoding
 *  y -> radix mode supported page size (encoded as a shift)
 */
static struct ppc_radix_page_info POWER10_radix_page_info = {
    .count = 4,
    .entries = {
        0x0000000c, /*  4K - enc: 0x0 */
        0xa0000010, /* 64K - enc: 0x5 */
        0x20000015, /*  2M - enc: 0x1 */
        0x4000001e  /*  1G - enc: 0x2 */
    }
};

static void init_proc_POWER10(CPUPPCState *env)
{
    /* Common Registers */
    init_proc_book3s_common(env);
    gen_spr_book3s_207_dbg(env);

    /* POWER8 Specific Registers */
    gen_spr_book3s_ids(env);
    gen_spr_amr(env);
    gen_spr_iamr(env);
    gen_spr_book3s_purr(env);
    gen_spr_power5p_common(env);
    gen_spr_power5p_lpar(env);
    gen_spr_power5p_ear(env);
    gen_spr_power6_common(env);
    gen_spr_power6_dbg(env);
    gen_spr_power8_tce_address_control(env);
    gen_spr_power8_ids(env);
    gen_spr_power8_ebb(env);
    gen_spr_power8_fscr(env);
    gen_spr_power8_pmu_sup(env);
    gen_spr_power8_pmu_user(env);
    gen_spr_power8_tm(env);
    gen_spr_power8_pspb(env);
    gen_spr_vtb(env);
    gen_spr_power8_ic(env);
    gen_spr_power8_book4(env);
    gen_spr_power8_rpr(env);
    gen_spr_power9_mmu(env);

    /* POWER9 Specific registers */
    spr_register_kvm(env, SPR_TIDR, "TIDR", NULL, NULL,
                     spr_read_generic, spr_write_generic,
                     KVM_REG_PPC_TIDR, 0);

    /* FIXME: Filter fields properly based on privilege level */
    spr_register_kvm_hv(env, SPR_PSSCR, "PSSCR", NULL, NULL, NULL, NULL,
                        spr_read_generic, spr_write_generic,
                        KVM_REG_PPC_PSSCR, 0);

    /* env variables */
    env->dcache_line_size = 128;
    env->icache_line_size = 128;

    /* Allocate hardware IRQ controller */
    init_excp_POWER10(env);
    ppcPOWER9_irq_init(env_archcpu(env));
}

static bool ppc_pvr_match_power10(PowerPCCPUClass *pcc, uint32_t pvr)
{
    if ((pvr & CPU_POWERPC_POWER_SERVER_MASK) == CPU_POWERPC_POWER10_BASE) {
        return true;
    }
    return false;
}

static bool cpu_has_work_POWER10(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    if (cs->halted) {
        uint64_t psscr = env->spr[SPR_PSSCR];

        if (!(cs->interrupt_request & CPU_INTERRUPT_HARD)) {
            return false;
        }

        /* If EC is clear, just return true on any pending interrupt */
        if (!(psscr & PSSCR_EC)) {
            return true;
        }
        /* External Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_EXT)) &&
            (env->spr[SPR_LPCR] & LPCR_EEE)) {
            bool heic = !!(env->spr[SPR_LPCR] & LPCR_HEIC);
            if (heic == 0 || !msr_hv || msr_pr) {
                return true;
            }
        }
        /* Decrementer Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_DECR)) &&
            (env->spr[SPR_LPCR] & LPCR_DEE)) {
            return true;
        }
        /* Machine Check or Hypervisor Maintenance Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_MCK |
            1u << PPC_INTERRUPT_HMI)) && (env->spr[SPR_LPCR] & LPCR_OEE)) {
            return true;
        }
        /* Privileged Doorbell Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_DOORBELL)) &&
            (env->spr[SPR_LPCR] & LPCR_PDEE)) {
            return true;
        }
        /* Hypervisor Doorbell Exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_HDOORBELL)) &&
            (env->spr[SPR_LPCR] & LPCR_HDEE)) {
            return true;
        }
        /* Hypervisor virtualization exception */
        if ((env->pending_interrupts & (1u << PPC_INTERRUPT_HVIRT)) &&
            (env->spr[SPR_LPCR] & LPCR_HVEE)) {
            return true;
        }
        if (env->pending_interrupts & (1u << PPC_INTERRUPT_RESET)) {
            return true;
        }
        return false;
    } else {
        return msr_ee && (cs->interrupt_request & CPU_INTERRUPT_HARD);
    }
}

POWERPC_FAMILY(POWER10)(CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);

//    dc->fw_name = "PowerPC,POWER10";
//    dc->desc = "POWER10";
    pcc->pvr_match = ppc_pvr_match_power10;
    pcc->pcr_mask = PCR_COMPAT_2_05 | PCR_COMPAT_2_06 | PCR_COMPAT_2_07 |
                    PCR_COMPAT_3_00;
    pcc->pcr_supported = PCR_COMPAT_3_10 | PCR_COMPAT_3_00 | PCR_COMPAT_2_07 |
                         PCR_COMPAT_2_06 | PCR_COMPAT_2_05;
    pcc->init_proc = init_proc_POWER10;
    pcc->check_pow = check_pow_nocheck;
    cc->has_work = cpu_has_work_POWER10;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_FRSQRTES |
                       PPC_FLOAT_STFIWX |
                       PPC_FLOAT_EXT |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBSYNC |
                       PPC_64B | PPC_64H | PPC_64BX | PPC_ALTIVEC |
                       PPC_SEGMENT_64B | PPC_SLBI |
                       PPC_POPCNTB | PPC_POPCNTWD |
                       PPC_CILDST;
    pcc->insns_flags2 = PPC2_VSX | PPC2_VSX207 | PPC2_DFP | PPC2_DBRX |
                        PPC2_PERM_ISA206 | PPC2_DIVE_ISA206 |
                        PPC2_ATOMIC_ISA206 | PPC2_FP_CVT_ISA206 |
                        PPC2_FP_TST_ISA206 | PPC2_BCTAR_ISA207 |
                        PPC2_LSQ_ISA207 | PPC2_ALTIVEC_207 |
                        PPC2_ISA205 | PPC2_ISA207S | PPC2_FP_CVT_S64 |
                        PPC2_TM | PPC2_ISA300 | PPC2_PRCNTL;
    pcc->msr_mask = (1ull << MSR_SF) |
                    (1ull << MSR_HV) |
                    (1ull << MSR_TM) |
                    (1ull << MSR_VR) |
                    (1ull << MSR_VSX) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->lpcr_mask = LPCR_VPM1 | LPCR_ISL | LPCR_KBV | LPCR_DPFD |
        (LPCR_PECE_U_MASK & LPCR_HVEE) | LPCR_ILE | LPCR_AIL |
        LPCR_UPRT | LPCR_EVIRT | LPCR_ONL | LPCR_HR | LPCR_LD |
        (LPCR_PECE_L_MASK & (LPCR_PDEE | LPCR_HDEE | LPCR_EEE |
                             LPCR_DEE | LPCR_OEE))
        | LPCR_MER | LPCR_GTSE | LPCR_TC |
        LPCR_HEIC | LPCR_LPES0 | LPCR_HVICE | LPCR_HDICE;
    pcc->lpcr_pm = LPCR_PDEE | LPCR_HDEE | LPCR_EEE | LPCR_DEE | LPCR_OEE;
    pcc->mmu_model = POWERPC_MMU_3_00;
    pcc->handle_mmu_fault = ppc64_v3_handle_mmu_fault;
    /* segment page size remain the same */
    pcc->hash64_opts = &ppc_hash64_opts_POWER7;
    pcc->radix_page_info = &POWER10_radix_page_info;
    pcc->lrg_decr_bits = 56;
    pcc->excp_model = POWERPC_EXCP_POWER9;
    pcc->bus_model = PPC_FLAGS_INPUT_POWER9;
    pcc->bfd_mach = bfd_mach_ppc64;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK | POWERPC_FLAG_CFAR |
                 POWERPC_FLAG_VSX | POWERPC_FLAG_TM;
    pcc->l1_dcache_size = 0x8000;
    pcc->l1_icache_size = 0x8000;
    pcc->interrupts_big_endian = ppc_cpu_interrupts_big_endian_lpcr;
}

#if 0
void cpu_ppc_set_vhyp(PowerPCCPU *cpu, PPCVirtualHypervisor *vhyp)
{
    CPUPPCState *env = &cpu->env;

    cpu->vhyp = vhyp;

    /*
     * With a virtual hypervisor mode we never allow the CPU to go
     * hypervisor mode itself
     */
    env->msr_mask &= ~MSR_HVB;
}
#endif

#endif /* defined(TARGET_PPC64) */

/*****************************************************************************/
/* Generic CPU instantiation routine                                         */
static void init_ppc_proc(PowerPCCPU *cpu)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);
    CPUPPCState *env = &cpu->env;
    int i;

    env->irq_inputs = NULL;
    /* Set all exception vectors to an invalid address */
    for (i = 0; i < POWERPC_EXCP_NB; i++) {
#ifdef _MSC_VER
        env->excp_vectors[i] = (target_ulong)(0ULL - 1ULL);
#else
        env->excp_vectors[i] = (target_ulong)(-1ULL);
#endif
    }
    env->ivor_mask = 0x00000000;
    env->ivpr_mask = 0x00000000;
    /* Default MMU definitions */
    env->nb_BATs = 0;
    env->nb_tlb = 0;
    env->nb_ways = 0;
    env->tlb_type = TLB_NONE;

    /* Register SPR common to all PowerPC implementations */
    gen_spr_generic(env);
    spr_register(env, SPR_PVR, "PVR",
                 /* Linux permits userspace to read PVR */
                 SPR_NOACCESS,
                 SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 pcc->pvr);
    /* Register SVR if it's defined to anything else than POWERPC_SVR_NONE */
    if (pcc->svr != POWERPC_SVR_NONE) {
        if (pcc->svr & POWERPC_SVR_E500) {
            spr_register(env, SPR_E500_SVR, "SVR",
                         SPR_NOACCESS, SPR_NOACCESS,
                         &spr_read_generic, SPR_NOACCESS,
                         pcc->svr & ~POWERPC_SVR_E500);
        } else {
            spr_register(env, SPR_SVR, "SVR",
                         SPR_NOACCESS, SPR_NOACCESS,
                         &spr_read_generic, SPR_NOACCESS,
                         pcc->svr);
        }
    }
    /* PowerPC implementation specific initialisations (SPRs, timers, ...) */
    (*pcc->init_proc)(env);

#if 0
    ppc_gdb_gen_spr_xml(cpu);
#endif

    /* MSR bits & flags consistency checks */
    if (env->msr_mask & (1 << 25)) {
        switch (env->flags & (POWERPC_FLAG_SPE | POWERPC_FLAG_VRE)) {
        case POWERPC_FLAG_SPE:
        case POWERPC_FLAG_VRE:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_SPE or POWERPC_FLAG_VRE\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_SPE | POWERPC_FLAG_VRE)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_SPE nor POWERPC_FLAG_VRE\n");
        exit(1);
    }
    if (env->msr_mask & (1 << 17)) {
        switch (env->flags & (POWERPC_FLAG_TGPR | POWERPC_FLAG_CE)) {
        case POWERPC_FLAG_TGPR:
        case POWERPC_FLAG_CE:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_TGPR or POWERPC_FLAG_CE\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_TGPR | POWERPC_FLAG_CE)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_TGPR nor POWERPC_FLAG_CE\n");
        exit(1);
    }
    if (env->msr_mask & (1 << 10)) {
        switch (env->flags & (POWERPC_FLAG_SE | POWERPC_FLAG_DWE |
                              POWERPC_FLAG_UBLE)) {
        case POWERPC_FLAG_SE:
        case POWERPC_FLAG_DWE:
        case POWERPC_FLAG_UBLE:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_SE or POWERPC_FLAG_DWE or "
                    "POWERPC_FLAG_UBLE\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_SE | POWERPC_FLAG_DWE |
                             POWERPC_FLAG_UBLE)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_SE nor POWERPC_FLAG_DWE nor "
                "POWERPC_FLAG_UBLE\n");
            exit(1);
    }
    if (env->msr_mask & (1 << 9)) {
        switch (env->flags & (POWERPC_FLAG_BE | POWERPC_FLAG_DE)) {
        case POWERPC_FLAG_BE:
        case POWERPC_FLAG_DE:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_BE or POWERPC_FLAG_DE\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_BE | POWERPC_FLAG_DE)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_BE nor POWERPC_FLAG_DE\n");
        exit(1);
    }
    if (env->msr_mask & (1 << 2)) {
        switch (env->flags & (POWERPC_FLAG_PX | POWERPC_FLAG_PMM)) {
        case POWERPC_FLAG_PX:
        case POWERPC_FLAG_PMM:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_PX or POWERPC_FLAG_PMM\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_PX | POWERPC_FLAG_PMM)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_PX nor POWERPC_FLAG_PMM\n");
        exit(1);
    }
    if ((env->flags & (POWERPC_FLAG_RTC_CLK | POWERPC_FLAG_BUS_CLK)) == 0) {
        fprintf(stderr, "PowerPC flags inconsistency\n"
                "Should define the time-base and decrementer clock source\n");
        exit(1);
    }
    /* Allocate TLBs buffer when needed */
    if (env->nb_tlb != 0) {
        int nb_tlb = env->nb_tlb;
        if (env->id_tlbs != 0) {
            nb_tlb *= 2;
        }
        switch (env->tlb_type) {
        case TLB_6XX:
            env->tlb.tlb6 = g_new0(ppc6xx_tlb_t, nb_tlb);
            break;
        case TLB_EMB:
            env->tlb.tlbe = g_new0(ppcemb_tlb_t, nb_tlb);
            break;
        case TLB_MAS:
            env->tlb.tlbm = g_new0(ppcmas_tlb_t, nb_tlb);
            break;
        }
        /* Pre-compute some useful values */
        env->tlb_per_way = env->nb_tlb / env->nb_ways;
    }
#if 0
    if (env->irq_inputs == NULL) {
        warn_report("no internal IRQ controller registered."
                    " Attempt QEMU to crash very soon !");
    }
    if (env->check_pow == NULL) {
        warn_report("no power management check handler registered."
                    " Attempt QEMU to crash very soon !");
    }
#endif
}

#if defined(PPC_DUMP_CPU)
static void dump_ppc_sprs(CPUPPCState *env)
{
    ppc_spr_t *spr;
    uint32_t sr, sw;
    uint32_t ur, uw;
    int i, j, n;

    printf("Special purpose registers:\n");
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 32; j++) {
            n = (i << 5) | j;
            spr = &env->spr_cb[n];
            uw = spr->uea_write != NULL && spr->uea_write != SPR_NOACCESS;
            ur = spr->uea_read != NULL && spr->uea_read != SPR_NOACCESS;
            sw = spr->oea_write != NULL && spr->oea_write != SPR_NOACCESS;
            sr = spr->oea_read != NULL && spr->oea_read != SPR_NOACCESS;
            if (sw || sr || uw || ur) {
                printf("SPR: %4d (%03x) %-8s s%c%c u%c%c\n",
                       (i << 5) | j, (i << 5) | j, spr->name,
                       sw ? 'w' : '-', sr ? 'r' : '-',
                       uw ? 'w' : '-', ur ? 'r' : '-');
            }
        }
    }
    fflush(stdout);
    fflush(stderr);
}
#endif

/*****************************************************************************/

/* Opcode types */
enum {
    PPC_DIRECT   = 0, /* Opcode routine        */
    PPC_INDIRECT = 1, /* Indirect opcode table */
};

#define PPC_OPCODE_MASK 0x3

static inline int is_indirect_opcode(void *handler)
{
    return ((uintptr_t)handler & PPC_OPCODE_MASK) == PPC_INDIRECT;
}

static inline opc_handler_t **ind_table(void *handler)
{
    return (opc_handler_t **)((uintptr_t)handler & ~PPC_OPCODE_MASK);
}

/* Instruction table creation */
/* Opcodes tables creation */
static void fill_new_table(opc_handler_t **table, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        table[i] = &invalid_handler;
    }
}

static int create_new_table(opc_handler_t **table, unsigned char idx)
{
    opc_handler_t **tmp;

    tmp = g_new(opc_handler_t *, PPC_CPU_INDIRECT_OPCODES_LEN);
    fill_new_table(tmp, PPC_CPU_INDIRECT_OPCODES_LEN);
    table[idx] = (opc_handler_t *)((uintptr_t)tmp | PPC_INDIRECT);

    return 0;
}

static int insert_in_table(opc_handler_t **table, unsigned char idx,
                            opc_handler_t *handler)
{
    if (table[idx] != &invalid_handler) {
        return -1;
    }
    table[idx] = handler;

    return 0;
}

static int register_direct_insn(opc_handler_t **ppc_opcodes,
                                unsigned char idx, opc_handler_t *handler)
{
    if (insert_in_table(ppc_opcodes, idx, handler) < 0) {
        printf("*** ERROR: opcode %02x already assigned in main "
               "opcode table\n", idx);
#if defined(DO_PPC_STATISTICS) || defined(PPC_DUMP_CPU)
        printf("           Registered handler '%s' - new handler '%s'\n",
               ppc_opcodes[idx]->oname, handler->oname);
#endif
        return -1;
    }

    return 0;
}

static int register_ind_in_table(opc_handler_t **table,
                                 unsigned char idx1, unsigned char idx2,
                                 opc_handler_t *handler)
{
    if (table[idx1] == &invalid_handler) {
        if (create_new_table(table, idx1) < 0) {
            printf("*** ERROR: unable to create indirect table "
                   "idx=%02x\n", idx1);
            return -1;
        }
    } else {
        if (!is_indirect_opcode(table[idx1])) {
            printf("*** ERROR: idx %02x already assigned to a direct "
                   "opcode\n", idx1);
#if defined(DO_PPC_STATISTICS) || defined(PPC_DUMP_CPU)
            printf("           Registered handler '%s' - new handler '%s'\n",
                   ind_table(table[idx1])[idx2]->oname, handler->oname);
#endif
            return -1;
        }
    }
    if (handler != NULL &&
        insert_in_table(ind_table(table[idx1]), idx2, handler) < 0) {
        printf("*** ERROR: opcode %02x already assigned in "
               "opcode table %02x\n", idx2, idx1);
#if defined(DO_PPC_STATISTICS) || defined(PPC_DUMP_CPU)
        printf("           Registered handler '%s' - new handler '%s'\n",
               ind_table(table[idx1])[idx2]->oname, handler->oname);
#endif
        return -1;
    }

    return 0;
}

static int register_ind_insn(opc_handler_t **ppc_opcodes,
                             unsigned char idx1, unsigned char idx2,
                             opc_handler_t *handler)
{
    return register_ind_in_table(ppc_opcodes, idx1, idx2, handler);
}

static int register_dblind_insn(opc_handler_t **ppc_opcodes,
                                unsigned char idx1, unsigned char idx2,
                                unsigned char idx3, opc_handler_t *handler)
{
    if (register_ind_in_table(ppc_opcodes, idx1, idx2, NULL) < 0) {
        printf("*** ERROR: unable to join indirect table idx "
               "[%02x-%02x]\n", idx1, idx2);
        return -1;
    }
    if (register_ind_in_table(ind_table(ppc_opcodes[idx1]), idx2, idx3,
                              handler) < 0) {
        printf("*** ERROR: unable to insert opcode "
               "[%02x-%02x-%02x]\n", idx1, idx2, idx3);
        return -1;
    }

    return 0;
}

static int register_trplind_insn(opc_handler_t **ppc_opcodes,
                                 unsigned char idx1, unsigned char idx2,
                                 unsigned char idx3, unsigned char idx4,
                                 opc_handler_t *handler)
{
    opc_handler_t **table;

    if (register_ind_in_table(ppc_opcodes, idx1, idx2, NULL) < 0) {
        printf("*** ERROR: unable to join indirect table idx "
               "[%02x-%02x]\n", idx1, idx2);
        return -1;
    }
    table = ind_table(ppc_opcodes[idx1]);
    if (register_ind_in_table(table, idx2, idx3, NULL) < 0) {
        printf("*** ERROR: unable to join 2nd-level indirect table idx "
               "[%02x-%02x-%02x]\n", idx1, idx2, idx3);
        return -1;
    }
    table = ind_table(table[idx2]);
    if (register_ind_in_table(table, idx3, idx4, handler) < 0) {
        printf("*** ERROR: unable to insert opcode "
               "[%02x-%02x-%02x-%02x]\n", idx1, idx2, idx3, idx4);
        return -1;
    }
    return 0;
}
static int register_insn(opc_handler_t **ppc_opcodes, opcode_t *insn)
{
    if (insn->opc2 != 0xFF) {
        if (insn->opc3 != 0xFF) {
            if (insn->opc4 != 0xFF) {
                if (register_trplind_insn(ppc_opcodes, insn->opc1, insn->opc2,
                                          insn->opc3, insn->opc4,
                                          &insn->handler) < 0) {
                    return -1;
                }
            } else {
                if (register_dblind_insn(ppc_opcodes, insn->opc1, insn->opc2,
                                         insn->opc3, &insn->handler) < 0) {
                    return -1;
                }
            }
        } else {
            if (register_ind_insn(ppc_opcodes, insn->opc1,
                                  insn->opc2, &insn->handler) < 0) {
                return -1;
            }
        }
    } else {
        if (register_direct_insn(ppc_opcodes, insn->opc1, &insn->handler) < 0) {
            return -1;
        }
    }

    return 0;
}

static int test_opcode_table(opc_handler_t **table, int len)
{
    int i, count, tmp;

    for (i = 0, count = 0; i < len; i++) {
        /* Consistency fixup */
        if (table[i] == NULL) {
            table[i] = &invalid_handler;
        }
        if (table[i] != &invalid_handler) {
            if (is_indirect_opcode(table[i])) {
                tmp = test_opcode_table(ind_table(table[i]),
                    PPC_CPU_INDIRECT_OPCODES_LEN);
                if (tmp == 0) {
                    free(table[i]);
                    table[i] = &invalid_handler;
                } else {
                    count++;
                }
            } else {
                count++;
            }
        }
    }

    return count;
}

static void fix_opcode_tables(opc_handler_t **ppc_opcodes)
{
    if (test_opcode_table(ppc_opcodes, PPC_CPU_OPCODES_LEN) == 0) {
        printf("*** WARNING: no opcode defined !\n");
    }
}

/*****************************************************************************/
static int create_ppc_opcodes(PowerPCCPU *cpu)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);
    opcode_t *opc;

    fill_new_table(cpu->opcodes, PPC_CPU_OPCODES_LEN);
    for (opc = opcodes; opc < &opcodes[ARRAY_SIZE(opcodes)]; opc++) {
        if (((opc->handler.type & pcc->insns_flags) != 0) ||
            ((opc->handler.type2 & pcc->insns_flags2) != 0)) {
            if (register_insn(cpu->opcodes, opc) < 0) {
#if 0
                error_setg(errp, "ERROR initializing PowerPC instruction "
                           "0x%02x 0x%02x 0x%02x", opc->opc1, opc->opc2,
                           opc->opc3);
#endif
                return 1;
            }
        }
    }
    fix_opcode_tables(cpu->opcodes);
    fflush(stdout);
    fflush(stderr);
    return 0;
}

#if defined(PPC_DUMP_CPU)
static void dump_ppc_insns(CPUPPCState *env)
{
    opc_handler_t **table, *handler;
    const char *p, *q;
    uint8_t opc1, opc2, opc3, opc4;

    printf("Instructions set:\n");
    /* opc1 is 6 bits long */
    for (opc1 = 0x00; opc1 < PPC_CPU_OPCODES_LEN; opc1++) {
        table = env->opcodes;
        handler = table[opc1];
        if (is_indirect_opcode(handler)) {
            /* opc2 is 5 bits long */
            for (opc2 = 0; opc2 < PPC_CPU_INDIRECT_OPCODES_LEN; opc2++) {
                table = env->opcodes;
                handler = env->opcodes[opc1];
                table = ind_table(handler);
                handler = table[opc2];
                if (is_indirect_opcode(handler)) {
                    table = ind_table(handler);
                    /* opc3 is 5 bits long */
                    for (opc3 = 0; opc3 < PPC_CPU_INDIRECT_OPCODES_LEN;
                            opc3++) {
                        handler = table[opc3];
                        if (is_indirect_opcode(handler)) {
                            table = ind_table(handler);
                            /* opc4 is 5 bits long */
                            for (opc4 = 0; opc4 < PPC_CPU_INDIRECT_OPCODES_LEN;
                                 opc4++) {
                                handler = table[opc4];
                                if (handler->handler != &gen_invalid) {
                                    printf("INSN: %02x %02x %02x %02x -- "
                                           "(%02d %04d %02d) : %s\n",
                                           opc1, opc2, opc3, opc4,
                                           opc1, (opc3 << 5) | opc2, opc4,
                                           handler->oname);
                                }
                            }
                        } else {
                            if (handler->handler != &gen_invalid) {
                                /* Special hack to properly dump SPE insns */
                                p = strchr(handler->oname, '_');
                                if (p == NULL) {
                                    printf("INSN: %02x %02x %02x (%02d %04d) : "
                                           "%s\n",
                                           opc1, opc2, opc3, opc1,
                                           (opc3 << 5) | opc2,
                                           handler->oname);
                                } else {
                                    q = "speundef";
                                    if ((p - handler->oname) != strlen(q)
                                        || (memcmp(handler->oname, q, strlen(q))
                                            != 0)) {
                                        /* First instruction */
                                        printf("INSN: %02x %02x %02x"
                                               "(%02d %04d) : %.*s\n",
                                               opc1, opc2 << 1, opc3, opc1,
                                               (opc3 << 6) | (opc2 << 1),
                                               (int)(p - handler->oname),
                                               handler->oname);
                                    }
                                    if (strcmp(p + 1, q) != 0) {
                                        /* Second instruction */
                                        printf("INSN: %02x %02x %02x "
                                               "(%02d %04d) : %s\n", opc1,
                                               (opc2 << 1) | 1, opc3, opc1,
                                               (opc3 << 6) | (opc2 << 1) | 1,
                                               p + 1);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    if (handler->handler != &gen_invalid) {
                        printf("INSN: %02x %02x -- (%02d %04d) : %s\n",
                               opc1, opc2, opc1, opc2, handler->oname);
                    }
                }
            }
        } else {
            if (handler->handler != &gen_invalid) {
                printf("INSN: %02x -- -- (%02d ----) : %s\n",
                       opc1, opc1, handler->oname);
            }
        }
    }
}
#endif

#if 0
static bool avr_need_swap(CPUPPCState *env)
{
#ifdef HOST_WORDS_BIGENDIAN
    return msr_le;
#else
    return !msr_le;
#endif
}

static int gdb_find_spr_idx(CPUPPCState *env, int n)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(env->spr_cb); i++) {
        ppc_spr_t *spr = &env->spr_cb[i];

        if (spr->name && spr->gdb_id == n) {
            return i;
        }
    }
    return -1;
}

static int gdb_get_spr_reg(CPUPPCState *env, GByteArray *buf, int n)
{
    int reg;
    int len;

    reg = gdb_find_spr_idx(env, n);
    if (reg < 0) {
        return 0;
    }

    len = TARGET_LONG_SIZE;
    gdb_get_regl(buf, env->spr[reg]);
    ppc_maybe_bswap_register(env, gdb_get_reg_ptr(buf, len), len);
    return len;
}

static int gdb_set_spr_reg(CPUPPCState *env, uint8_t *mem_buf, int n)
{
    int reg;
    int len;

    reg = gdb_find_spr_idx(env, n);
    if (reg < 0) {
        return 0;
    }

    len = TARGET_LONG_SIZE;
    ppc_maybe_bswap_register(env, mem_buf, len);
    env->spr[reg] = ldn_p(mem_buf, len);

    return len;
}

static int gdb_get_float_reg(CPUPPCState *env, GByteArray *buf, int n)
{
    uint8_t *mem_buf;
    if (n < 32) {
        gdb_get_reg64(buf, *cpu_fpr_ptr(env, n));
        mem_buf = gdb_get_reg_ptr(buf, 8);
        ppc_maybe_bswap_register(env, mem_buf, 8);
        return 8;
    }
    if (n == 32) {
        gdb_get_reg32(buf, env->fpscr);
        mem_buf = gdb_get_reg_ptr(buf, 4);
        ppc_maybe_bswap_register(env, mem_buf, 4);
        return 4;
    }
    return 0;
}

static int gdb_set_float_reg(CPUPPCState *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        ppc_maybe_bswap_register(env, mem_buf, 8);
        *cpu_fpr_ptr(env, n) = ldfq_p(mem_buf);
        return 8;
    }
    if (n == 32) {
        ppc_maybe_bswap_register(env, mem_buf, 4);
        helper_store_fpscr(env, ldl_p(mem_buf), 0xffffffff);
        return 4;
    }
    return 0;
}

static int gdb_get_avr_reg(CPUPPCState *env, GByteArray *buf, int n)
{
    uint8_t *mem_buf;

    if (n < 32) {
        ppc_avr_t *avr = cpu_avr_ptr(env, n);
        if (!avr_need_swap(env)) {
            gdb_get_reg128(buf, avr->u64[0] , avr->u64[1]);
        } else {
            gdb_get_reg128(buf, avr->u64[1] , avr->u64[0]);
        }
        mem_buf = gdb_get_reg_ptr(buf, 16);
        ppc_maybe_bswap_register(env, mem_buf, 8);
        ppc_maybe_bswap_register(env, mem_buf + 8, 8);
        return 16;
    }
    if (n == 32) {
        gdb_get_reg32(buf, helper_mfvscr(env));
        mem_buf = gdb_get_reg_ptr(buf, 4);
        ppc_maybe_bswap_register(env, mem_buf, 4);
        return 4;
    }
    if (n == 33) {
        gdb_get_reg32(buf, (uint32_t)env->spr[SPR_VRSAVE]);
        mem_buf = gdb_get_reg_ptr(buf, 4);
        ppc_maybe_bswap_register(env, mem_buf, 4);
        return 4;
    }
    return 0;
}

static int gdb_set_avr_reg(CPUPPCState *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        ppc_avr_t *avr = cpu_avr_ptr(env, n);
        ppc_maybe_bswap_register(env, mem_buf, 8);
        ppc_maybe_bswap_register(env, mem_buf + 8, 8);
        if (!avr_need_swap(env)) {
            avr->u64[0] = ldq_p(mem_buf);
            avr->u64[1] = ldq_p(mem_buf + 8);
        } else {
            avr->u64[1] = ldq_p(mem_buf);
            avr->u64[0] = ldq_p(mem_buf + 8);
        }
        return 16;
    }
    if (n == 32) {
        ppc_maybe_bswap_register(env, mem_buf, 4);
        helper_mtvscr(env, ldl_p(mem_buf));
        return 4;
    }
    if (n == 33) {
        ppc_maybe_bswap_register(env, mem_buf, 4);
        env->spr[SPR_VRSAVE] = (target_ulong)ldl_p(mem_buf);
        return 4;
    }
    return 0;
}

static int gdb_get_spe_reg(CPUPPCState *env, GByteArray *buf, int n)
{
    if (n < 32) {
#if defined(TARGET_PPC64)
        gdb_get_reg32(buf, env->gpr[n] >> 32);
        ppc_maybe_bswap_register(env, gdb_get_reg_ptr(buf, 4), 4);
#else
        gdb_get_reg32(buf, env->gprh[n]);
#endif
        return 4;
    }
    if (n == 32) {
        gdb_get_reg64(buf, env->spe_acc);
        ppc_maybe_bswap_register(env, gdb_get_reg_ptr(buf, 8), 8);
        return 8;
    }
    if (n == 33) {
        gdb_get_reg32(buf, env->spe_fscr);
        ppc_maybe_bswap_register(env, gdb_get_reg_ptr(buf, 4), 4);
        return 4;
    }
    return 0;
}

static int gdb_set_spe_reg(CPUPPCState *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
#if defined(TARGET_PPC64)
        target_ulong lo = (uint32_t)env->gpr[n];
        target_ulong hi;

        ppc_maybe_bswap_register(env, mem_buf, 4);

        hi = (target_ulong)ldl_p(mem_buf) << 32;
        env->gpr[n] = lo | hi;
#else
        env->gprh[n] = ldl_p(mem_buf);
#endif
        return 4;
    }
    if (n == 32) {
        ppc_maybe_bswap_register(env, mem_buf, 8);
        env->spe_acc = ldq_p(mem_buf);
        return 8;
    }
    if (n == 33) {
        ppc_maybe_bswap_register(env, mem_buf, 4);
        env->spe_fscr = ldl_p(mem_buf);
        return 4;
    }
    return 0;
}

static int gdb_get_vsx_reg(CPUPPCState *env, GByteArray *buf, int n)
{
    if (n < 32) {
        gdb_get_reg64(buf, *cpu_vsrl_ptr(env, n));
        ppc_maybe_bswap_register(env, gdb_get_reg_ptr(buf, 8), 8);
        return 8;
    }
    return 0;
}

static int gdb_set_vsx_reg(CPUPPCState *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        ppc_maybe_bswap_register(env, mem_buf, 8);
        *cpu_vsrl_ptr(env, n) = ldq_p(mem_buf);
        return 8;
    }
    return 0;
}
#endif

static int ppc_fixup_cpu(PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;

    /*
     * TCG doesn't (yet) emulate some groups of instructions that are
     * implemented on some otherwise supported CPUs (e.g. VSX and
     * decimal floating point instructions on POWER7).  We remove
     * unsupported instruction groups from the cpu state's instruction
     * masks and hope the guest can cope.  For at least the pseries
     * machine, the unavailability of these instructions can be
     * advertised to the guest via the device tree.
     */
    if ((env->insns_flags & ~PPC_TCG_INSNS)
        || (env->insns_flags2 & ~PPC_TCG_INSNS2)) {
#if 0
        warn_report("Disabling some instructions which are not "
                    "emulated by TCG (0x%" PRIx64 ", 0x%" PRIx64 ")",
                    env->insns_flags & ~PPC_TCG_INSNS,
                    env->insns_flags2 & ~PPC_TCG_INSNS2);
#endif
    }
    env->insns_flags &= PPC_TCG_INSNS;
    env->insns_flags2 &= PPC_TCG_INSNS2;
    return 0;
}

static void ppc_cpu_realize(struct uc_struct *uc, CPUState *dev)
{
    CPUState *cs = CPU(dev);
    PowerPCCPU *cpu = POWERPC_CPU(dev);
#if 0
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);
#endif

    cpu_exec_realizefn(cs);
    if (cpu->vcpu_id == UNASSIGNED_CPU_INDEX) {
        cpu->vcpu_id = cs->cpu_index;
    }

    if (ppc_fixup_cpu(cpu) != 0) {
        goto unrealize;
    }

    if (create_ppc_opcodes(cpu) != 0) {
        goto unrealize;
    }

    init_ppc_proc(cpu);

#if defined(PPC_DUMP_CPU)
    {
        CPUPPCState *env = &cpu->env;
        const char *mmu_model, *excp_model, *bus_model;
        switch (env->mmu_model) {
        case POWERPC_MMU_32B:
            mmu_model = "PowerPC 32";
            break;
        case POWERPC_MMU_SOFT_6xx:
            mmu_model = "PowerPC 6xx/7xx with software driven TLBs";
            break;
        case POWERPC_MMU_SOFT_74xx:
            mmu_model = "PowerPC 74xx with software driven TLBs";
            break;
        case POWERPC_MMU_SOFT_4xx:
            mmu_model = "PowerPC 4xx with software driven TLBs";
            break;
        case POWERPC_MMU_SOFT_4xx_Z:
            mmu_model = "PowerPC 4xx with software driven TLBs "
                "and zones protections";
            break;
        case POWERPC_MMU_REAL:
            mmu_model = "PowerPC real mode only";
            break;
        case POWERPC_MMU_MPC8xx:
            mmu_model = "PowerPC MPC8xx";
            break;
        case POWERPC_MMU_BOOKE:
            mmu_model = "PowerPC BookE";
            break;
        case POWERPC_MMU_BOOKE206:
            mmu_model = "PowerPC BookE 2.06";
            break;
        case POWERPC_MMU_601:
            mmu_model = "PowerPC 601";
            break;
#if defined(TARGET_PPC64)
        case POWERPC_MMU_64B:
            mmu_model = "PowerPC 64";
            break;
#endif
        default:
            mmu_model = "Unknown or invalid";
            break;
        }
        switch (env->excp_model) {
        case POWERPC_EXCP_STD:
            excp_model = "PowerPC";
            break;
        case POWERPC_EXCP_40x:
            excp_model = "PowerPC 40x";
            break;
        case POWERPC_EXCP_601:
            excp_model = "PowerPC 601";
            break;
        case POWERPC_EXCP_602:
            excp_model = "PowerPC 602";
            break;
        case POWERPC_EXCP_603:
            excp_model = "PowerPC 603";
            break;
        case POWERPC_EXCP_603E:
            excp_model = "PowerPC 603e";
            break;
        case POWERPC_EXCP_604:
            excp_model = "PowerPC 604";
            break;
        case POWERPC_EXCP_7x0:
            excp_model = "PowerPC 740/750";
            break;
        case POWERPC_EXCP_7x5:
            excp_model = "PowerPC 745/755";
            break;
        case POWERPC_EXCP_74xx:
            excp_model = "PowerPC 74xx";
            break;
        case POWERPC_EXCP_BOOKE:
            excp_model = "PowerPC BookE";
            break;
#if defined(TARGET_PPC64)
        case POWERPC_EXCP_970:
            excp_model = "PowerPC 970";
            break;
#endif
        default:
            excp_model = "Unknown or invalid";
            break;
        }
        switch (env->bus_model) {
        case PPC_FLAGS_INPUT_6xx:
            bus_model = "PowerPC 6xx";
            break;
        case PPC_FLAGS_INPUT_BookE:
            bus_model = "PowerPC BookE";
            break;
        case PPC_FLAGS_INPUT_405:
            bus_model = "PowerPC 405";
            break;
        case PPC_FLAGS_INPUT_401:
            bus_model = "PowerPC 401/403";
            break;
        case PPC_FLAGS_INPUT_RCPU:
            bus_model = "RCPU / MPC8xx";
            break;
#if defined(TARGET_PPC64)
        case PPC_FLAGS_INPUT_970:
            bus_model = "PowerPC 970";
            break;
#endif
        default:
            bus_model = "Unknown or invalid";
            break;
        }
        printf("PowerPC %-12s : PVR %08x MSR %016" PRIx64 "\n"
               "    MMU model        : %s\n",
               object_class_get_name(OBJECT_CLASS(pcc)),
               pcc->pvr, pcc->msr_mask, mmu_model);
        if (env->tlb.tlb6) {
            printf("                       %d %s TLB in %d ways\n",
                   env->nb_tlb, env->id_tlbs ? "splitted" : "merged",
                   env->nb_ways);
        }
        printf("    Exceptions model : %s\n"
               "    Bus model        : %s\n",
               excp_model, bus_model);
        printf("    MSR features     :\n");
        if (env->flags & POWERPC_FLAG_SPE) {
            printf("                        signal processing engine enable"
                   "\n");
        } else if (env->flags & POWERPC_FLAG_VRE) {
            printf("                        vector processor enable\n");
        }
        if (env->flags & POWERPC_FLAG_TGPR) {
            printf("                        temporary GPRs\n");
        } else if (env->flags & POWERPC_FLAG_CE) {
            printf("                        critical input enable\n");
        }
        if (env->flags & POWERPC_FLAG_SE) {
            printf("                        single-step trace mode\n");
        } else if (env->flags & POWERPC_FLAG_DWE) {
            printf("                        debug wait enable\n");
        } else if (env->flags & POWERPC_FLAG_UBLE) {
            printf("                        user BTB lock enable\n");
        }
        if (env->flags & POWERPC_FLAG_BE) {
            printf("                        branch-step trace mode\n");
        } else if (env->flags & POWERPC_FLAG_DE) {
            printf("                        debug interrupt enable\n");
        }
        if (env->flags & POWERPC_FLAG_PX) {
            printf("                        inclusive protection\n");
        } else if (env->flags & POWERPC_FLAG_PMM) {
            printf("                        performance monitor mark\n");
        }
        if (env->flags == POWERPC_FLAG_NONE) {
            printf("                        none\n");
        }
        printf("    Time-base/decrementer clock source: %s\n",
               env->flags & POWERPC_FLAG_RTC_CLK ? "RTC clock" : "bus clock");
        dump_ppc_insns(env);
        dump_ppc_sprs(env);
        fflush(stdout);
    }
#endif
    return;

unrealize:
    cpu_exec_unrealizefn(cs);
}

void ppc_cpu_unrealize(CPUState *dev)
{
    PowerPCCPU *cpu = POWERPC_CPU(dev);
    opc_handler_t **table, **table_2;
    int i, j, k;

    for (i = 0; i < PPC_CPU_OPCODES_LEN; i++) {
        if (cpu->opcodes[i] == &invalid_handler) {
            continue;
        }
        if (is_indirect_opcode(cpu->opcodes[i])) {
            table = ind_table(cpu->opcodes[i]);
            for (j = 0; j < PPC_CPU_INDIRECT_OPCODES_LEN; j++) {
                if (table[j] == &invalid_handler) {
                    continue;
                }
                if (is_indirect_opcode(table[j])) {
                    table_2 = ind_table(table[j]);
                    for (k = 0; k < PPC_CPU_INDIRECT_OPCODES_LEN; k++) {
                        if (table_2[k] != &invalid_handler &&
                            is_indirect_opcode(table_2[k])) {
                            g_free((opc_handler_t *)((uintptr_t)table_2[k] &
                                                     ~PPC_INDIRECT));
                        }
                    }
                    g_free((opc_handler_t *)((uintptr_t)table[j] &
                                             ~PPC_INDIRECT));
                }
            }
            g_free((opc_handler_t *)((uintptr_t)cpu->opcodes[i] &
                ~PPC_INDIRECT));
        }
    }
}

static void ppc_cpu_set_pc(CPUState *cs, vaddr value)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);

    cpu->env.nip = value;
}

static bool ppc_cpu_has_work(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    return msr_ee && (cs->interrupt_request & CPU_INTERRUPT_HARD);
}

static void ppc_cpu_reset(CPUState *dev)
{
    CPUState *s = CPU(dev);
    PowerPCCPU *cpu = POWERPC_CPU(s);
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);
    CPUPPCState *env = &cpu->env;
    target_ulong msr;
    int i;

    pcc->parent_reset(dev);

    msr = (target_ulong)0;
    msr |= (target_ulong)MSR_HVB;
    msr |= (target_ulong)0 << MSR_AP; /* TO BE CHECKED */
    msr |= (target_ulong)0 << MSR_SA; /* TO BE CHECKED */
    msr |= (target_ulong)1 << MSR_EP;
#if defined(DO_SINGLE_STEP) && 0
    /* Single step trace mode */
    msr |= (target_ulong)1 << MSR_SE;
    msr |= (target_ulong)1 << MSR_BE;
#endif

#if defined(TARGET_PPC64)
    if (env->mmu_model & POWERPC_MMU_64) {
        msr |= (1ULL << MSR_SF);
    }
#endif

    hreg_store_msr(env, msr, 1);

    env->nip = env->hreset_vector | env->excp_prefix;
    if (env->mmu_model != POWERPC_MMU_REAL) {
        ppc_tlb_invalidate_all(env);
    }

    hreg_compute_hflags(env);
#ifdef _MSC_VER
    env->reserve_addr = (target_ulong)(0ULL - 1ULL);
#else
    env->reserve_addr = (target_ulong)-1ULL;
#endif
    /* Be sure no exception or interrupt is pending */
    env->pending_interrupts = 0;
    s->exception_index = POWERPC_EXCP_NONE;
    env->error_code = 0;
    ppc_irq_reset(cpu);

    /* tininess for underflow is detected before rounding */
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->fp_status);

    for (i = 0; i < ARRAY_SIZE(env->spr_cb); i++) {
        ppc_spr_t *spr = &env->spr_cb[i];

        if (!spr->name) {
            continue;
        }
        env->spr[i] = spr->default_value;
    }
}

#if 0
static bool ppc_cpu_is_big_endian(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

//    cpu_synchronize_state(cs);

    return !msr_le;
}
#endif

static void ppc_cpu_exec_enter(CPUState *cs)
{
#if 0
    PowerPCCPU *cpu = POWERPC_CPU(cs);

    if (cpu->vhyp) {
        PPCVirtualHypervisorClass *vhc =
            PPC_VIRTUAL_HYPERVISOR_GET_CLASS(cpu->vhyp);
        vhc->cpu_exec_enter(cpu->vhyp, cpu);
    }
#endif
}

static void ppc_cpu_exec_exit(CPUState *cs)
{
#if 0
    PowerPCCPU *cpu = POWERPC_CPU(cs);

    if (cpu->vhyp) {
        PPCVirtualHypervisorClass *vhc =
            PPC_VIRTUAL_HYPERVISOR_GET_CLASS(cpu->vhyp);
        vhc->cpu_exec_exit(cpu->vhyp, cpu);
    }
#endif
}

static void ppc_cpu_instance_init(struct uc_struct *uc, CPUState *obj)
{
    PowerPCCPU *cpu = POWERPC_CPU(obj);
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);
    CPUPPCState *env = &cpu->env;

    env->uc = uc;
    cpu_set_cpustate_pointers(cpu);
    cpu->vcpu_id = UNASSIGNED_CPU_INDEX;

    env->msr_mask = pcc->msr_mask;
    env->mmu_model = pcc->mmu_model;
    env->excp_model = pcc->excp_model;
    env->bus_model = pcc->bus_model;
    env->insns_flags = pcc->insns_flags;
    env->insns_flags2 = pcc->insns_flags2;
    env->flags = pcc->flags;
    env->bfd_mach = pcc->bfd_mach;
    env->check_pow = pcc->check_pow;

    /*
     * Mark HV mode as supported if the CPU has an MSR_HV bit in the
     * msr_mask. The mask can later be cleared by PAPR mode but the hv
     * mode support will remain, thus enforcing that we cannot use
     * priv. instructions in guest in PAPR mode. For 970 we currently
     * simply don't set HV in msr_mask thus simulating an "Apple mode"
     * 970. If we ever want to support 970 HV mode, we'll have to add
     * a processor attribute of some sort.
     */
    env->has_hv_mode = !!(env->msr_mask & MSR_HVB);

#ifdef TARGET_PPC64
    ppc_hash64_init(cpu);
#endif
}

void ppc_cpu_instance_finalize(CPUState *obj)
{
#ifdef TARGET_PPC64
    PowerPCCPU *cpu = POWERPC_CPU(obj);

    ppc_hash64_finalize(cpu);
#endif
}

static bool ppc_pvr_match_default(PowerPCCPUClass *pcc, uint32_t pvr)
{
    return pcc->pvr == pvr;
}

#if 0
static gchar *ppc_gdb_arch_name(CPUState *cs)
{
#if defined(TARGET_PPC64)
    return g_strdup("powerpc:common64");
#else
    return g_strdup("powerpc:common");
#endif
}

static void ppc_disas_set_info(CPUState *cs, disassemble_info *info)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    if ((env->hflags >> MSR_LE) & 1) {
        info->endian = BFD_ENDIAN_LITTLE;
    }
    info->mach = env->bfd_mach;
    if (!env->bfd_mach) {
#ifdef TARGET_PPC64
        info->mach = bfd_mach_ppc64;
#else
        info->mach = bfd_mach_ppc;
#endif
    }
    info->disassembler_options = (char *)"any";
    info->print_insn = print_insn_ppc;

    info->cap_arch = CS_ARCH_PPC;
#ifdef TARGET_PPC64
    info->cap_mode = CS_MODE_64;
#endif
}

static Property ppc_cpu_properties[] = {
    DEFINE_PROP_BOOL("pre-2.8-migration", PowerPCCPU, pre_2_8_migration, false),
    DEFINE_PROP_BOOL("pre-2.10-migration", PowerPCCPU, pre_2_10_migration,
                     false),
    DEFINE_PROP_BOOL("pre-3.0-migration", PowerPCCPU, pre_3_0_migration,
                     false),
    DEFINE_PROP_END_OF_LIST(),
};
#endif

static void ppc_cpu_class_init(struct uc_struct *uc, CPUClass *oc)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
#if 0
    DeviceClass *dc = DEVICE_CLASS(oc);

    device_class_set_parent_realize(dc, ppc_cpu_realize,
                                    &pcc->parent_realize);
    device_class_set_parent_unrealize(dc, ppc_cpu_unrealize,
                                      &pcc->parent_unrealize);
#endif
    pcc->pvr_match = ppc_pvr_match_default;
    pcc->interrupts_big_endian = ppc_cpu_interrupts_big_endian_always;
#if 0
    device_class_set_props(dc, ppc_cpu_properties);

    device_class_set_parent_reset(dc, ppc_cpu_reset, &pcc->parent_reset);

    cc->class_by_name = ppc_cpu_class_by_name;
    pcc->parent_parse_features = cc->parse_features;
    cc->parse_features = ppc_cpu_parse_featurestr;
#endif
    /* parent class is CPUClass, parent_reset() is cpu_common_reset(). */
    pcc->parent_reset = cc->reset;
    /* overwrite the CPUClass->reset to arch reset: arm_cpu_reset(). */
    cc->reset = ppc_cpu_reset;

    cc->has_work = ppc_cpu_has_work;
    cc->do_interrupt = ppc_cpu_do_interrupt;
    cc->cpu_exec_interrupt = ppc_cpu_exec_interrupt;
#if 0
    cc->dump_state = ppc_cpu_dump_state;
    cc->dump_statistics = ppc_cpu_dump_statistics;
#endif
    cc->set_pc = ppc_cpu_set_pc;
#if 0
    cc->gdb_read_register = ppc_cpu_gdb_read_register;
    cc->gdb_write_register = ppc_cpu_gdb_write_register;
#endif
    cc->do_unaligned_access = ppc_cpu_do_unaligned_access;
    cc->get_phys_page_debug = ppc_cpu_get_phys_page_debug;
#if 0
    cc->vmsd = &vmstate_ppc_cpu;
    cc->write_elf64_note = ppc64_cpu_write_elf64_note;
    cc->write_elf32_note = ppc32_cpu_write_elf32_note;

    cc->gdb_num_core_regs = 71;
    cc->gdb_get_dynamic_xml = ppc_gdb_get_dynamic_xml;
#ifdef USE_APPLE_GDB
    cc->gdb_read_register = ppc_cpu_gdb_read_register_apple;
    cc->gdb_write_register = ppc_cpu_gdb_write_register_apple;
    cc->gdb_num_core_regs = 71 + 32;
#endif

    cc->gdb_arch_name = ppc_gdb_arch_name;
#if defined(TARGET_PPC64)
    cc->gdb_core_xml_file = "power64-core.xml";
#else
    cc->gdb_core_xml_file = "power-core.xml";
#endif
    cc->virtio_is_big_endian = ppc_cpu_is_big_endian;
#endif
    cc->tcg_initialize = ppc_translate_init;
    cc->tlb_fill = ppc_cpu_tlb_fill;
    cc->cpu_exec_enter = ppc_cpu_exec_enter;
    cc->cpu_exec_exit = ppc_cpu_exec_exit;

#if 0
    cc->disas_set_info = ppc_disas_set_info;
    dc->fw_name = "PowerPC,UNKNOWN";
#endif
}

/* PowerPC CPU definitions from cpu-models.c*/
typedef struct PowerPCCPUInfo {
    const char *name;
    uint32_t pvr;
    uint32_t svr;
    void (*cpu_family_class_init)(CPUClass *oc, void *data);
} PowerPCCPUInfo;

#define POWERPC_DEF_SVR(_name, _desc, _pvr, _svr, _type) \
    { _name, _pvr, _svr, POWERPC_FAMILY_NAME(_type) },

#define POWERPC_DEF(_name, _pvr, _type, _desc) \
    POWERPC_DEF_SVR(_name, _desc, _pvr, POWERPC_SVR_NONE, _type)


static const PowerPCCPUInfo ppc_cpus[] = {
    /* Embedded PowerPC                                                      */
    /* PowerPC 401 family                                                    */
    POWERPC_DEF("401",           CPU_POWERPC_401,                    401,
                "Generic PowerPC 401")
    /* PowerPC 401 cores                                                     */
    POWERPC_DEF("401a1",         CPU_POWERPC_401A1,                  401,
                "PowerPC 401A1")
    POWERPC_DEF("401b2",         CPU_POWERPC_401B2,                  401x2,
                "PowerPC 401B2")
    POWERPC_DEF("401c2",         CPU_POWERPC_401C2,                  401x2,
                "PowerPC 401C2")
    POWERPC_DEF("401d2",         CPU_POWERPC_401D2,                  401x2,
                "PowerPC 401D2")
    POWERPC_DEF("401e2",         CPU_POWERPC_401E2,                  401x2,
                "PowerPC 401E2")
    POWERPC_DEF("401f2",         CPU_POWERPC_401F2,                  401x2,
                "PowerPC 401F2")
    /* XXX: to be checked */
    POWERPC_DEF("401g2",         CPU_POWERPC_401G2,                  401x2,
                "PowerPC 401G2")
    /* PowerPC 401 microcontrollers                                          */
    POWERPC_DEF("iop480",        CPU_POWERPC_IOP480,                 IOP480,
                "IOP480 (401 microcontroller)")
    POWERPC_DEF("cobra",         CPU_POWERPC_COBRA,                  401,
                "IBM Processor for Network Resources")
    /* PowerPC 403 family                                                    */
    /* PowerPC 403 microcontrollers                                          */
    POWERPC_DEF("403ga",         CPU_POWERPC_403GA,                  403,
                "PowerPC 403 GA")
    POWERPC_DEF("403gb",         CPU_POWERPC_403GB,                  403,
                "PowerPC 403 GB")
    POWERPC_DEF("403gc",         CPU_POWERPC_403GC,                  403,
                "PowerPC 403 GC")
    POWERPC_DEF("403gcx",        CPU_POWERPC_403GCX,                 403GCX,
                "PowerPC 403 GCX")
    /* PowerPC 405 family                                                    */
    /* PowerPC 405 cores                                                     */
    POWERPC_DEF("405d2",         CPU_POWERPC_405D2,                  405,
                "PowerPC 405 D2")
    POWERPC_DEF("405d4",         CPU_POWERPC_405D4,                  405,
                "PowerPC 405 D4")
    /* PowerPC 405 microcontrollers                                          */
    POWERPC_DEF("405cra",        CPU_POWERPC_405CRa,                 405,
                "PowerPC 405 CRa")
    POWERPC_DEF("405crb",        CPU_POWERPC_405CRb,                 405,
                "PowerPC 405 CRb")
    POWERPC_DEF("405crc",        CPU_POWERPC_405CRc,                 405,
                "PowerPC 405 CRc")
    POWERPC_DEF("405ep",         CPU_POWERPC_405EP,                  405,
                "PowerPC 405 EP")
    POWERPC_DEF("405ez",         CPU_POWERPC_405EZ,                  405,
                "PowerPC 405 EZ")
    POWERPC_DEF("405gpa",        CPU_POWERPC_405GPa,                 405,
                "PowerPC 405 GPa")
    POWERPC_DEF("405gpb",        CPU_POWERPC_405GPb,                 405,
                "PowerPC 405 GPb")
    POWERPC_DEF("405gpc",        CPU_POWERPC_405GPc,                 405,
                "PowerPC 405 GPc")
    POWERPC_DEF("405gpd",        CPU_POWERPC_405GPd,                 405,
                "PowerPC 405 GPd")
    POWERPC_DEF("405gpr",        CPU_POWERPC_405GPR,                 405,
                "PowerPC 405 GPR")
    POWERPC_DEF("405lp",         CPU_POWERPC_405LP,                  405,
                "PowerPC 405 LP")
    POWERPC_DEF("npe405h",       CPU_POWERPC_NPE405H,                405,
                "Npe405 H")
    POWERPC_DEF("npe405h2",      CPU_POWERPC_NPE405H2,               405,
                "Npe405 H2")
    POWERPC_DEF("npe405l",       CPU_POWERPC_NPE405L,                405,
                "Npe405 L")
    POWERPC_DEF("npe4gs3",       CPU_POWERPC_NPE4GS3,                405,
                "Npe4GS3")
    /* PowerPC 401/403/405 based set-top-box microcontrollers                */
    POWERPC_DEF("stb03",         CPU_POWERPC_STB03,                  405,
                "STB03xx")
    POWERPC_DEF("stb04",         CPU_POWERPC_STB04,                  405,
                "STB04xx")
    POWERPC_DEF("stb25",         CPU_POWERPC_STB25,                  405,
                "STB25xx")
    /* Xilinx PowerPC 405 cores                                              */
    POWERPC_DEF("x2vp4",         CPU_POWERPC_X2VP4,                  405,
                NULL)
    POWERPC_DEF("x2vp20",        CPU_POWERPC_X2VP20,                 405,
                NULL)
    /* PowerPC 440 family                                                    */
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440",           CPU_POWERPC_440,                    440GP,
                "Generic PowerPC 440")
#endif
    /* PowerPC 440 cores                                                     */
    POWERPC_DEF("440-xilinx",    CPU_POWERPC_440_XILINX,             440x5,
                "PowerPC 440 Xilinx 5")

    POWERPC_DEF("440-xilinx-w-dfpu",    CPU_POWERPC_440_XILINX, 440x5wDFPU,
                "PowerPC 440 Xilinx 5 With a Double Prec. FPU")
    /* PowerPC 440 microcontrollers                                          */
    POWERPC_DEF("440epa",        CPU_POWERPC_440EPa,                 440EP,
                "PowerPC 440 EPa")
    POWERPC_DEF("440epb",        CPU_POWERPC_440EPb,                 440EP,
                "PowerPC 440 EPb")
    POWERPC_DEF("440epx",        CPU_POWERPC_440EPX,                 440EP,
                "PowerPC 440 EPX")
    POWERPC_DEF("460exb",        CPU_POWERPC_460EXb,                 460EX,
                "PowerPC 460 EXb")
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440gpb",        CPU_POWERPC_440GPb,                 440GP,
                "PowerPC 440 GPb")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440gpc",        CPU_POWERPC_440GPc,                 440GP,
                "PowerPC 440 GPc")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440gra",        CPU_POWERPC_440GRa,                 440x5,
                "PowerPC 440 GRa")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440grx",        CPU_POWERPC_440GRX,                 440x5,
                "PowerPC 440 GRX")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440gxa",        CPU_POWERPC_440GXa,                 440EP,
                "PowerPC 440 GXa")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440gxb",        CPU_POWERPC_440GXb,                 440EP,
                "PowerPC 440 GXb")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440gxc",        CPU_POWERPC_440GXc,                 440EP,
                "PowerPC 440 GXc")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440gxf",        CPU_POWERPC_440GXf,                 440EP,
                "PowerPC 440 GXf")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440sp",         CPU_POWERPC_440SP,                  440EP,
                "PowerPC 440 SP")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440sp2",        CPU_POWERPC_440SP2,                 440EP,
                "PowerPC 440 SP2")
#endif
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("440spe",        CPU_POWERPC_440SPE,                 440EP,
                "PowerPC 440 SPE")
#endif
    /* Freescale embedded PowerPC cores                                      */
    /* MPC5xx family (aka RCPU)                                              */
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("mpc5xx",        CPU_POWERPC_MPC5xx,                 MPC5xx,
                "Generic MPC5xx core")
#endif
    /* MPC8xx family (aka PowerQUICC)                                        */
#if defined(TODO_USER_ONLY)
    POWERPC_DEF("mpc8xx",        CPU_POWERPC_MPC8xx,                 MPC8xx,
                "Generic MPC8xx core")
#endif
    /* MPC82xx family (aka PowerQUICC-II)                                    */
    POWERPC_DEF("g2",            CPU_POWERPC_G2,                     G2,
                "PowerPC G2 core")
    POWERPC_DEF("g2h4",          CPU_POWERPC_G2H4,                   G2,
                "PowerPC G2 H4 core")
    POWERPC_DEF("g2gp",          CPU_POWERPC_G2gp,                   G2,
                "PowerPC G2 GP core")
    POWERPC_DEF("g2ls",          CPU_POWERPC_G2ls,                   G2,
                "PowerPC G2 LS core")
    POWERPC_DEF("g2hip3",        CPU_POWERPC_G2_HIP3,                G2,
                "PowerPC G2 HiP3 core")
    POWERPC_DEF("g2hip4",        CPU_POWERPC_G2_HIP4,                G2,
                "PowerPC G2 HiP4 core")
    POWERPC_DEF("mpc603",        CPU_POWERPC_MPC603,                 603E,
                "PowerPC MPC603 core")
    POWERPC_DEF("g2le",          CPU_POWERPC_G2LE,                   G2LE,
        "PowerPC G2le core (same as G2 plus little-endian mode support)")
    POWERPC_DEF("g2legp",        CPU_POWERPC_G2LEgp,                 G2LE,
                "PowerPC G2LE GP core")
    POWERPC_DEF("g2lels",        CPU_POWERPC_G2LEls,                 G2LE,
                "PowerPC G2LE LS core")
    POWERPC_DEF("g2legp1",       CPU_POWERPC_G2LEgp1,                G2LE,
                "PowerPC G2LE GP1 core")
    POWERPC_DEF("g2legp3",       CPU_POWERPC_G2LEgp3,                G2LE,
                "PowerPC G2LE GP3 core")
    /* PowerPC G2 microcontrollers                                           */
    POWERPC_DEF_SVR("mpc5200_v10", "MPC5200 v1.0",
                    CPU_POWERPC_MPC5200_v10,  POWERPC_SVR_5200_v10,  G2LE)
    POWERPC_DEF_SVR("mpc5200_v11", "MPC5200 v1.1",
                    CPU_POWERPC_MPC5200_v11,  POWERPC_SVR_5200_v11,  G2LE)
    POWERPC_DEF_SVR("mpc5200_v12", "MPC5200 v1.2",
                    CPU_POWERPC_MPC5200_v12,  POWERPC_SVR_5200_v12,  G2LE)
    POWERPC_DEF_SVR("mpc5200b_v20", "MPC5200B v2.0",
                    CPU_POWERPC_MPC5200B_v20, POWERPC_SVR_5200B_v20, G2LE)
    POWERPC_DEF_SVR("mpc5200b_v21", "MPC5200B v2.1",
                    CPU_POWERPC_MPC5200B_v21, POWERPC_SVR_5200B_v21, G2LE)
    /* e200 family                                                           */
    POWERPC_DEF("e200z5",        CPU_POWERPC_e200z5,                 e200,
                "PowerPC e200z5 core")
    POWERPC_DEF("e200z6",        CPU_POWERPC_e200z6,                 e200,
                "PowerPC e200z6 core")
    /* e300 family                                                           */
    POWERPC_DEF("e300c1",        CPU_POWERPC_e300c1,                 e300,
                "PowerPC e300c1 core")
    POWERPC_DEF("e300c2",        CPU_POWERPC_e300c2,                 e300,
                "PowerPC e300c2 core")
    POWERPC_DEF("e300c3",        CPU_POWERPC_e300c3,                 e300,
                "PowerPC e300c3 core")
    POWERPC_DEF("e300c4",        CPU_POWERPC_e300c4,                 e300,
                "PowerPC e300c4 core")
    /* PowerPC e300 microcontrollers                                         */
    POWERPC_DEF_SVR("mpc8343", "MPC8343",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8343,      e300)
    POWERPC_DEF_SVR("mpc8343a", "MPC8343A",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8343A,     e300)
    POWERPC_DEF_SVR("mpc8343e", "MPC8343E",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8343E,     e300)
    POWERPC_DEF_SVR("mpc8343ea", "MPC8343EA",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8343EA,    e300)
    POWERPC_DEF_SVR("mpc8347t", "MPC8347T",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8347T,     e300)
    POWERPC_DEF_SVR("mpc8347p", "MPC8347P",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8347P,     e300)
    POWERPC_DEF_SVR("mpc8347at", "MPC8347AT",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8347AT,    e300)
    POWERPC_DEF_SVR("mpc8347ap", "MPC8347AP",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8347AP,    e300)
    POWERPC_DEF_SVR("mpc8347et", "MPC8347ET",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8347ET,    e300)
    POWERPC_DEF_SVR("mpc8347ep", "MPC8343EP",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8347EP,    e300)
    POWERPC_DEF_SVR("mpc8347eat", "MPC8347EAT",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8347EAT,   e300)
    POWERPC_DEF_SVR("mpc8347eap", "MPC8343EAP",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8347EAP,   e300)
    POWERPC_DEF_SVR("mpc8349", "MPC8349",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8349,      e300)
    POWERPC_DEF_SVR("mpc8349a", "MPC8349A",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8349A,     e300)
    POWERPC_DEF_SVR("mpc8349e", "MPC8349E",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8349E,     e300)
    POWERPC_DEF_SVR("mpc8349ea", "MPC8349EA",
                    CPU_POWERPC_MPC834x,      POWERPC_SVR_8349EA,    e300)
    POWERPC_DEF_SVR("mpc8377", "MPC8377",
                    CPU_POWERPC_MPC837x,      POWERPC_SVR_8377,      e300)
    POWERPC_DEF_SVR("mpc8377e", "MPC8377E",
                    CPU_POWERPC_MPC837x,      POWERPC_SVR_8377E,     e300)
    POWERPC_DEF_SVR("mpc8378", "MPC8378",
                    CPU_POWERPC_MPC837x,      POWERPC_SVR_8378,      e300)
    POWERPC_DEF_SVR("mpc8378e", "MPC8378E",
                    CPU_POWERPC_MPC837x,      POWERPC_SVR_8378E,     e300)
    POWERPC_DEF_SVR("mpc8379", "MPC8379",
                    CPU_POWERPC_MPC837x,      POWERPC_SVR_8379,      e300)
    POWERPC_DEF_SVR("mpc8379e", "MPC8379E",
                    CPU_POWERPC_MPC837x,      POWERPC_SVR_8379E,     e300)
    /* e500 family                                                           */
    POWERPC_DEF_SVR("e500_v10", "PowerPC e500 v1.0 core",
                    CPU_POWERPC_e500v1_v10,   POWERPC_SVR_E500,      e500v1)
    POWERPC_DEF_SVR("e500_v20", "PowerPC e500 v2.0 core",
                    CPU_POWERPC_e500v1_v20,   POWERPC_SVR_E500,      e500v1)
    POWERPC_DEF_SVR("e500v2_v10", "PowerPC e500v2 v1.0 core",
                    CPU_POWERPC_e500v2_v10,   POWERPC_SVR_E500,      e500v2)
    POWERPC_DEF_SVR("e500v2_v20", "PowerPC e500v2 v2.0 core",
                    CPU_POWERPC_e500v2_v20,   POWERPC_SVR_E500,      e500v2)
    POWERPC_DEF_SVR("e500v2_v21", "PowerPC e500v2 v2.1 core",
                    CPU_POWERPC_e500v2_v21,   POWERPC_SVR_E500,      e500v2)
    POWERPC_DEF_SVR("e500v2_v22", "PowerPC e500v2 v2.2 core",
                    CPU_POWERPC_e500v2_v22,   POWERPC_SVR_E500,      e500v2)
    POWERPC_DEF_SVR("e500v2_v30", "PowerPC e500v2 v3.0 core",
                    CPU_POWERPC_e500v2_v30,   POWERPC_SVR_E500,      e500v2)
    POWERPC_DEF_SVR("e500mc", "e500mc",
                    CPU_POWERPC_e500mc,       POWERPC_SVR_E500,      e500mc)
    /* PowerPC e500 microcontrollers                                         */
    POWERPC_DEF_SVR("mpc8533_v10", "MPC8533 v1.0",
                    CPU_POWERPC_MPC8533_v10,  POWERPC_SVR_8533_v10,  e500v2)
    POWERPC_DEF_SVR("mpc8533_v11", "MPC8533 v1.1",
                    CPU_POWERPC_MPC8533_v11,  POWERPC_SVR_8533_v11,  e500v2)
    POWERPC_DEF_SVR("mpc8533e_v10", "MPC8533E v1.0",
                    CPU_POWERPC_MPC8533E_v10, POWERPC_SVR_8533E_v10, e500v2)
    POWERPC_DEF_SVR("mpc8533e_v11", "MPC8533E v1.1",
                    CPU_POWERPC_MPC8533E_v11, POWERPC_SVR_8533E_v11, e500v2)
    POWERPC_DEF_SVR("mpc8540_v10", "MPC8540 v1.0",
                    CPU_POWERPC_MPC8540_v10,  POWERPC_SVR_8540_v10,  e500v1)
    POWERPC_DEF_SVR("mpc8540_v20", "MPC8540 v2.0",
                    CPU_POWERPC_MPC8540_v20,  POWERPC_SVR_8540_v20,  e500v1)
    POWERPC_DEF_SVR("mpc8540_v21", "MPC8540 v2.1",
                    CPU_POWERPC_MPC8540_v21,  POWERPC_SVR_8540_v21,  e500v1)
    POWERPC_DEF_SVR("mpc8541_v10", "MPC8541 v1.0",
                    CPU_POWERPC_MPC8541_v10,  POWERPC_SVR_8541_v10,  e500v1)
    POWERPC_DEF_SVR("mpc8541_v11", "MPC8541 v1.1",
                    CPU_POWERPC_MPC8541_v11,  POWERPC_SVR_8541_v11,  e500v1)
    POWERPC_DEF_SVR("mpc8541e_v10", "MPC8541E v1.0",
                    CPU_POWERPC_MPC8541E_v10, POWERPC_SVR_8541E_v10, e500v1)
    POWERPC_DEF_SVR("mpc8541e_v11", "MPC8541E v1.1",
                    CPU_POWERPC_MPC8541E_v11, POWERPC_SVR_8541E_v11, e500v1)
    POWERPC_DEF_SVR("mpc8543_v10", "MPC8543 v1.0",
                    CPU_POWERPC_MPC8543_v10,  POWERPC_SVR_8543_v10,  e500v2)
    POWERPC_DEF_SVR("mpc8543_v11", "MPC8543 v1.1",
                    CPU_POWERPC_MPC8543_v11,  POWERPC_SVR_8543_v11,  e500v2)
    POWERPC_DEF_SVR("mpc8543_v20", "MPC8543 v2.0",
                    CPU_POWERPC_MPC8543_v20,  POWERPC_SVR_8543_v20,  e500v2)
    POWERPC_DEF_SVR("mpc8543_v21", "MPC8543 v2.1",
                    CPU_POWERPC_MPC8543_v21,  POWERPC_SVR_8543_v21,  e500v2)
    POWERPC_DEF_SVR("mpc8543e_v10", "MPC8543E v1.0",
                    CPU_POWERPC_MPC8543E_v10, POWERPC_SVR_8543E_v10, e500v2)
    POWERPC_DEF_SVR("mpc8543e_v11", "MPC8543E v1.1",
                    CPU_POWERPC_MPC8543E_v11, POWERPC_SVR_8543E_v11, e500v2)
    POWERPC_DEF_SVR("mpc8543e_v20", "MPC8543E v2.0",
                    CPU_POWERPC_MPC8543E_v20, POWERPC_SVR_8543E_v20, e500v2)
    POWERPC_DEF_SVR("mpc8543e_v21", "MPC8543E v2.1",
                    CPU_POWERPC_MPC8543E_v21, POWERPC_SVR_8543E_v21, e500v2)
    POWERPC_DEF_SVR("mpc8544_v10", "MPC8544 v1.0",
                    CPU_POWERPC_MPC8544_v10,  POWERPC_SVR_8544_v10,  e500v2)
    POWERPC_DEF_SVR("mpc8544_v11", "MPC8544 v1.1",
                    CPU_POWERPC_MPC8544_v11,  POWERPC_SVR_8544_v11,  e500v2)
    POWERPC_DEF_SVR("mpc8544e_v10", "MPC8544E v1.0",
                    CPU_POWERPC_MPC8544E_v10, POWERPC_SVR_8544E_v10, e500v2)
    POWERPC_DEF_SVR("mpc8544e_v11", "MPC8544E v1.1",
                    CPU_POWERPC_MPC8544E_v11, POWERPC_SVR_8544E_v11, e500v2)
    POWERPC_DEF_SVR("mpc8545_v20", "MPC8545 v2.0",
                    CPU_POWERPC_MPC8545_v20,  POWERPC_SVR_8545_v20,  e500v2)
    POWERPC_DEF_SVR("mpc8545_v21", "MPC8545 v2.1",
                    CPU_POWERPC_MPC8545_v21,  POWERPC_SVR_8545_v21,  e500v2)
    POWERPC_DEF_SVR("mpc8545e_v20", "MPC8545E v2.0",
                    CPU_POWERPC_MPC8545E_v20, POWERPC_SVR_8545E_v20, e500v2)
    POWERPC_DEF_SVR("mpc8545e_v21", "MPC8545E v2.1",
                    CPU_POWERPC_MPC8545E_v21, POWERPC_SVR_8545E_v21, e500v2)
    POWERPC_DEF_SVR("mpc8547e_v20", "MPC8547E v2.0",
                    CPU_POWERPC_MPC8547E_v20, POWERPC_SVR_8547E_v20, e500v2)
    POWERPC_DEF_SVR("mpc8547e_v21", "MPC8547E v2.1",
                    CPU_POWERPC_MPC8547E_v21, POWERPC_SVR_8547E_v21, e500v2)
    POWERPC_DEF_SVR("mpc8548_v10", "MPC8548 v1.0",
                    CPU_POWERPC_MPC8548_v10,  POWERPC_SVR_8548_v10,  e500v2)
    POWERPC_DEF_SVR("mpc8548_v11", "MPC8548 v1.1",
                    CPU_POWERPC_MPC8548_v11,  POWERPC_SVR_8548_v11,  e500v2)
    POWERPC_DEF_SVR("mpc8548_v20", "MPC8548 v2.0",
                    CPU_POWERPC_MPC8548_v20,  POWERPC_SVR_8548_v20,  e500v2)
    POWERPC_DEF_SVR("mpc8548_v21", "MPC8548 v2.1",
                    CPU_POWERPC_MPC8548_v21,  POWERPC_SVR_8548_v21,  e500v2)
    POWERPC_DEF_SVR("mpc8548e_v10", "MPC8548E v1.0",
                    CPU_POWERPC_MPC8548E_v10, POWERPC_SVR_8548E_v10, e500v2)
    POWERPC_DEF_SVR("mpc8548e_v11", "MPC8548E v1.1",
                    CPU_POWERPC_MPC8548E_v11, POWERPC_SVR_8548E_v11, e500v2)
    POWERPC_DEF_SVR("mpc8548e_v20", "MPC8548E v2.0",
                    CPU_POWERPC_MPC8548E_v20, POWERPC_SVR_8548E_v20, e500v2)
    POWERPC_DEF_SVR("mpc8548e_v21", "MPC8548E v2.1",
                    CPU_POWERPC_MPC8548E_v21, POWERPC_SVR_8548E_v21, e500v2)
    POWERPC_DEF_SVR("mpc8555_v10", "MPC8555 v1.0",
                    CPU_POWERPC_MPC8555_v10,  POWERPC_SVR_8555_v10,  e500v2)
    POWERPC_DEF_SVR("mpc8555_v11", "MPC8555 v1.1",
                    CPU_POWERPC_MPC8555_v11,  POWERPC_SVR_8555_v11,  e500v2)
    POWERPC_DEF_SVR("mpc8555e_v10", "MPC8555E v1.0",
                    CPU_POWERPC_MPC8555E_v10, POWERPC_SVR_8555E_v10, e500v2)
    POWERPC_DEF_SVR("mpc8555e_v11", "MPC8555E v1.1",
                    CPU_POWERPC_MPC8555E_v11, POWERPC_SVR_8555E_v11, e500v2)
    POWERPC_DEF_SVR("mpc8560_v10", "MPC8560 v1.0",
                    CPU_POWERPC_MPC8560_v10,  POWERPC_SVR_8560_v10,  e500v2)
    POWERPC_DEF_SVR("mpc8560_v20", "MPC8560 v2.0",
                    CPU_POWERPC_MPC8560_v20,  POWERPC_SVR_8560_v20,  e500v2)
    POWERPC_DEF_SVR("mpc8560_v21", "MPC8560 v2.1",
                    CPU_POWERPC_MPC8560_v21,  POWERPC_SVR_8560_v21,  e500v2)
    POWERPC_DEF_SVR("mpc8567", "MPC8567",
                    CPU_POWERPC_MPC8567,      POWERPC_SVR_8567,      e500v2)
    POWERPC_DEF_SVR("mpc8567e", "MPC8567E",
                    CPU_POWERPC_MPC8567E,     POWERPC_SVR_8567E,     e500v2)
    POWERPC_DEF_SVR("mpc8568", "MPC8568",
                    CPU_POWERPC_MPC8568,      POWERPC_SVR_8568,      e500v2)
    POWERPC_DEF_SVR("mpc8568e", "MPC8568E",
                    CPU_POWERPC_MPC8568E,     POWERPC_SVR_8568E,     e500v2)
    POWERPC_DEF_SVR("mpc8572", "MPC8572",
                    CPU_POWERPC_MPC8572,      POWERPC_SVR_8572,      e500v2)
    POWERPC_DEF_SVR("mpc8572e", "MPC8572E",
                    CPU_POWERPC_MPC8572E,     POWERPC_SVR_8572E,     e500v2)
    /* e600 family                                                           */
    POWERPC_DEF("e600",          CPU_POWERPC_e600,                   e600,
                "PowerPC e600 core")
    /* PowerPC e600 microcontrollers                                         */
    POWERPC_DEF_SVR("mpc8610", "MPC8610",
                    CPU_POWERPC_MPC8610,      POWERPC_SVR_8610,      e600)
    POWERPC_DEF_SVR("mpc8641", "MPC8641",
                    CPU_POWERPC_MPC8641,      POWERPC_SVR_8641,      e600)
    POWERPC_DEF_SVR("mpc8641d", "MPC8641D",
                    CPU_POWERPC_MPC8641D,     POWERPC_SVR_8641D,     e600)
    /* 32 bits "classic" PowerPC                                             */
    /* PowerPC 6xx family                                                    */
    POWERPC_DEF("601_v0",        CPU_POWERPC_601_v0,                 601,
                "PowerPC 601v0")
    POWERPC_DEF("601_v1",        CPU_POWERPC_601_v1,                 601,
                "PowerPC 601v1")
    POWERPC_DEF("601_v2",        CPU_POWERPC_601_v2,                 601v,
                "PowerPC 601v2")
    POWERPC_DEF("602",           CPU_POWERPC_602,                    602,
                "PowerPC 602")
    POWERPC_DEF("603",           CPU_POWERPC_603,                    603,
                "PowerPC 603")
    POWERPC_DEF("603e_v1.1",     CPU_POWERPC_603E_v11,               603E,
                "PowerPC 603e v1.1")
    POWERPC_DEF("603e_v1.2",     CPU_POWERPC_603E_v12,               603E,
                "PowerPC 603e v1.2")
    POWERPC_DEF("603e_v1.3",     CPU_POWERPC_603E_v13,               603E,
                "PowerPC 603e v1.3")
    POWERPC_DEF("603e_v1.4",     CPU_POWERPC_603E_v14,               603E,
                "PowerPC 603e v1.4")
    POWERPC_DEF("603e_v2.2",     CPU_POWERPC_603E_v22,               603E,
                "PowerPC 603e v2.2")
    POWERPC_DEF("603e_v3",       CPU_POWERPC_603E_v3,                603E,
                "PowerPC 603e v3")
    POWERPC_DEF("603e_v4",       CPU_POWERPC_603E_v4,                603E,
                "PowerPC 603e v4")
    POWERPC_DEF("603e_v4.1",     CPU_POWERPC_603E_v41,               603E,
                "PowerPC 603e v4.1")
    POWERPC_DEF("603e7",         CPU_POWERPC_603E7,                  603E,
                "PowerPC 603e (aka PID7)")
    POWERPC_DEF("603e7t",        CPU_POWERPC_603E7t,                 603E,
                "PowerPC 603e7t")
    POWERPC_DEF("603e7v",        CPU_POWERPC_603E7v,                 603E,
                "PowerPC 603e7v")
    POWERPC_DEF("603e7v1",       CPU_POWERPC_603E7v1,                603E,
                "PowerPC 603e7v1")
    POWERPC_DEF("603e7v2",       CPU_POWERPC_603E7v2,                603E,
                "PowerPC 603e7v2")
    POWERPC_DEF("603p",          CPU_POWERPC_603P,                   603E,
                "PowerPC 603p (aka PID7v)")
    POWERPC_DEF("604",           CPU_POWERPC_604,                    604,
                "PowerPC 604")
    POWERPC_DEF("604e_v1.0",     CPU_POWERPC_604E_v10,               604E,
                "PowerPC 604e v1.0")
    POWERPC_DEF("604e_v2.2",     CPU_POWERPC_604E_v22,               604E,
                "PowerPC 604e v2.2")
    POWERPC_DEF("604e_v2.4",     CPU_POWERPC_604E_v24,               604E,
                "PowerPC 604e v2.4")
    POWERPC_DEF("604r",          CPU_POWERPC_604R,                   604E,
                "PowerPC 604r (aka PIDA)")
    /* PowerPC 7xx family                                                    */
    POWERPC_DEF("740_v1.0",      CPU_POWERPC_7x0_v10,                740,
                "PowerPC 740 v1.0 (G3)")
    POWERPC_DEF("750_v1.0",      CPU_POWERPC_7x0_v10,                750,
                "PowerPC 750 v1.0 (G3)")
    POWERPC_DEF("740_v2.0",      CPU_POWERPC_7x0_v20,                740,
                "PowerPC 740 v2.0 (G3)")
    POWERPC_DEF("750_v2.0",      CPU_POWERPC_7x0_v20,                750,
                "PowerPC 750 v2.0 (G3)")
    POWERPC_DEF("740_v2.1",      CPU_POWERPC_7x0_v21,                740,
                "PowerPC 740 v2.1 (G3)")
    POWERPC_DEF("750_v2.1",      CPU_POWERPC_7x0_v21,                750,
                "PowerPC 750 v2.1 (G3)")
    POWERPC_DEF("740_v2.2",      CPU_POWERPC_7x0_v22,                740,
                "PowerPC 740 v2.2 (G3)")
    POWERPC_DEF("750_v2.2",      CPU_POWERPC_7x0_v22,                750,
                "PowerPC 750 v2.2 (G3)")
    POWERPC_DEF("740_v3.0",      CPU_POWERPC_7x0_v30,                740,
                "PowerPC 740 v3.0 (G3)")
    POWERPC_DEF("750_v3.0",      CPU_POWERPC_7x0_v30,                750,
                "PowerPC 750 v3.0 (G3)")
    POWERPC_DEF("740_v3.1",      CPU_POWERPC_7x0_v31,                740,
                "PowerPC 740 v3.1 (G3)")
    POWERPC_DEF("750_v3.1",      CPU_POWERPC_7x0_v31,                750,
                "PowerPC 750 v3.1 (G3)")
    POWERPC_DEF("740e",          CPU_POWERPC_740E,                   740,
                "PowerPC 740E (G3)")
    POWERPC_DEF("750e",          CPU_POWERPC_750E,                   750,
                "PowerPC 750E (G3)")
    POWERPC_DEF("740p",          CPU_POWERPC_7x0P,                   740,
                "PowerPC 740P (G3)")
    POWERPC_DEF("750p",          CPU_POWERPC_7x0P,                   750,
                "PowerPC 750P (G3)")
    POWERPC_DEF("750cl_v1.0",    CPU_POWERPC_750CL_v10,              750cl,
                "PowerPC 750CL v1.0")
    POWERPC_DEF("750cl_v2.0",    CPU_POWERPC_750CL_v20,              750cl,
                "PowerPC 750CL v2.0")
    POWERPC_DEF("750cx_v1.0",    CPU_POWERPC_750CX_v10,              750cx,
                "PowerPC 750CX v1.0 (G3 embedded)")
    POWERPC_DEF("750cx_v2.0",    CPU_POWERPC_750CX_v20,              750cx,
                "PowerPC 750CX v2.1 (G3 embedded)")
    POWERPC_DEF("750cx_v2.1",    CPU_POWERPC_750CX_v21,              750cx,
                "PowerPC 750CX v2.1 (G3 embedded)")
    POWERPC_DEF("750cx_v2.2",    CPU_POWERPC_750CX_v22,              750cx,
                "PowerPC 750CX v2.2 (G3 embedded)")
    POWERPC_DEF("750cxe_v2.1",   CPU_POWERPC_750CXE_v21,             750cx,
                "PowerPC 750CXe v2.1 (G3 embedded)")
    POWERPC_DEF("750cxe_v2.2",   CPU_POWERPC_750CXE_v22,             750cx,
                "PowerPC 750CXe v2.2 (G3 embedded)")
    POWERPC_DEF("750cxe_v2.3",   CPU_POWERPC_750CXE_v23,             750cx,
                "PowerPC 750CXe v2.3 (G3 embedded)")
    POWERPC_DEF("750cxe_v2.4",   CPU_POWERPC_750CXE_v24,             750cx,
                "PowerPC 750CXe v2.4 (G3 embedded)")
    POWERPC_DEF("750cxe_v2.4b",  CPU_POWERPC_750CXE_v24b,            750cx,
                "PowerPC 750CXe v2.4b (G3 embedded)")
    POWERPC_DEF("750cxe_v3.0",   CPU_POWERPC_750CXE_v30,             750cx,
                "PowerPC 750CXe v3.0 (G3 embedded)")
    POWERPC_DEF("750cxe_v3.1",   CPU_POWERPC_750CXE_v31,             750cx,
                "PowerPC 750CXe v3.1 (G3 embedded)")
    POWERPC_DEF("750cxe_v3.1b",  CPU_POWERPC_750CXE_v31b,            750cx,
                "PowerPC 750CXe v3.1b (G3 embedded)")
    POWERPC_DEF("750cxr",        CPU_POWERPC_750CXR,                 750cx,
                "PowerPC 750CXr (G3 embedded)")
    POWERPC_DEF("750fl",         CPU_POWERPC_750FL,                  750fx,
                "PowerPC 750FL (G3 embedded)")
    POWERPC_DEF("750fx_v1.0",    CPU_POWERPC_750FX_v10,              750fx,
                "PowerPC 750FX v1.0 (G3 embedded)")
    POWERPC_DEF("750fx_v2.0",    CPU_POWERPC_750FX_v20,              750fx,
                "PowerPC 750FX v2.0 (G3 embedded)")
    POWERPC_DEF("750fx_v2.1",    CPU_POWERPC_750FX_v21,              750fx,
                "PowerPC 750FX v2.1 (G3 embedded)")
    POWERPC_DEF("750fx_v2.2",    CPU_POWERPC_750FX_v22,              750fx,
                "PowerPC 750FX v2.2 (G3 embedded)")
    POWERPC_DEF("750fx_v2.3",    CPU_POWERPC_750FX_v23,              750fx,
                "PowerPC 750FX v2.3 (G3 embedded)")
    POWERPC_DEF("750gl",         CPU_POWERPC_750GL,                  750gx,
                "PowerPC 750GL (G3 embedded)")
    POWERPC_DEF("750gx_v1.0",    CPU_POWERPC_750GX_v10,              750gx,
                "PowerPC 750GX v1.0 (G3 embedded)")
    POWERPC_DEF("750gx_v1.1",    CPU_POWERPC_750GX_v11,              750gx,
                "PowerPC 750GX v1.1 (G3 embedded)")
    POWERPC_DEF("750gx_v1.2",    CPU_POWERPC_750GX_v12,              750gx,
                "PowerPC 750GX v1.2 (G3 embedded)")
    POWERPC_DEF("750l_v2.0",     CPU_POWERPC_750L_v20,               750,
                "PowerPC 750L v2.0 (G3 embedded)")
    POWERPC_DEF("750l_v2.1",     CPU_POWERPC_750L_v21,               750,
                "PowerPC 750L v2.1 (G3 embedded)")
    POWERPC_DEF("750l_v2.2",     CPU_POWERPC_750L_v22,               750,
                "PowerPC 750L v2.2 (G3 embedded)")
    POWERPC_DEF("750l_v3.0",     CPU_POWERPC_750L_v30,               750,
                "PowerPC 750L v3.0 (G3 embedded)")
    POWERPC_DEF("750l_v3.2",     CPU_POWERPC_750L_v32,               750,
                "PowerPC 750L v3.2 (G3 embedded)")
    POWERPC_DEF("745_v1.0",      CPU_POWERPC_7x5_v10,                745,
                "PowerPC 745 v1.0")
    POWERPC_DEF("755_v1.0",      CPU_POWERPC_7x5_v10,                755,
                "PowerPC 755 v1.0")
    POWERPC_DEF("745_v1.1",      CPU_POWERPC_7x5_v11,                745,
                "PowerPC 745 v1.1")
    POWERPC_DEF("755_v1.1",      CPU_POWERPC_7x5_v11,                755,
                "PowerPC 755 v1.1")
    POWERPC_DEF("745_v2.0",      CPU_POWERPC_7x5_v20,                745,
                "PowerPC 745 v2.0")
    POWERPC_DEF("755_v2.0",      CPU_POWERPC_7x5_v20,                755,
                "PowerPC 755 v2.0")
    POWERPC_DEF("745_v2.1",      CPU_POWERPC_7x5_v21,                745,
                "PowerPC 745 v2.1")
    POWERPC_DEF("755_v2.1",      CPU_POWERPC_7x5_v21,                755,
                "PowerPC 755 v2.1")
    POWERPC_DEF("745_v2.2",      CPU_POWERPC_7x5_v22,                745,
                "PowerPC 745 v2.2")
    POWERPC_DEF("755_v2.2",      CPU_POWERPC_7x5_v22,                755,
                "PowerPC 755 v2.2")
    POWERPC_DEF("745_v2.3",      CPU_POWERPC_7x5_v23,                745,
                "PowerPC 745 v2.3")
    POWERPC_DEF("755_v2.3",      CPU_POWERPC_7x5_v23,                755,
                "PowerPC 755 v2.3")
    POWERPC_DEF("745_v2.4",      CPU_POWERPC_7x5_v24,                745,
                "PowerPC 745 v2.4")
    POWERPC_DEF("755_v2.4",      CPU_POWERPC_7x5_v24,                755,
                "PowerPC 755 v2.4")
    POWERPC_DEF("745_v2.5",      CPU_POWERPC_7x5_v25,                745,
                "PowerPC 745 v2.5")
    POWERPC_DEF("755_v2.5",      CPU_POWERPC_7x5_v25,                755,
                "PowerPC 755 v2.5")
    POWERPC_DEF("745_v2.6",      CPU_POWERPC_7x5_v26,                745,
                "PowerPC 745 v2.6")
    POWERPC_DEF("755_v2.6",      CPU_POWERPC_7x5_v26,                755,
                "PowerPC 755 v2.6")
    POWERPC_DEF("745_v2.7",      CPU_POWERPC_7x5_v27,                745,
                "PowerPC 745 v2.7")
    POWERPC_DEF("755_v2.7",      CPU_POWERPC_7x5_v27,                755,
                "PowerPC 755 v2.7")
    POWERPC_DEF("745_v2.8",      CPU_POWERPC_7x5_v28,                745,
                "PowerPC 745 v2.8")
    POWERPC_DEF("755_v2.8",      CPU_POWERPC_7x5_v28,                755,
                "PowerPC 755 v2.8")
    /* PowerPC 74xx family                                                   */
    POWERPC_DEF("7400_v1.0",     CPU_POWERPC_7400_v10,               7400,
                "PowerPC 7400 v1.0 (G4)")
    POWERPC_DEF("7400_v1.1",     CPU_POWERPC_7400_v11,               7400,
                "PowerPC 7400 v1.1 (G4)")
    POWERPC_DEF("7400_v2.0",     CPU_POWERPC_7400_v20,               7400,
                "PowerPC 7400 v2.0 (G4)")
    POWERPC_DEF("7400_v2.1",     CPU_POWERPC_7400_v21,               7400,
                "PowerPC 7400 v2.1 (G4)")
    POWERPC_DEF("7400_v2.2",     CPU_POWERPC_7400_v22,               7400,
                "PowerPC 7400 v2.2 (G4)")
    POWERPC_DEF("7400_v2.6",     CPU_POWERPC_7400_v26,               7400,
                "PowerPC 7400 v2.6 (G4)")
    POWERPC_DEF("7400_v2.7",     CPU_POWERPC_7400_v27,               7400,
                "PowerPC 7400 v2.7 (G4)")
    POWERPC_DEF("7400_v2.8",     CPU_POWERPC_7400_v28,               7400,
                "PowerPC 7400 v2.8 (G4)")
    POWERPC_DEF("7400_v2.9",     CPU_POWERPC_7400_v29,               7400,
                "PowerPC 7400 v2.9 (G4)")
    POWERPC_DEF("7410_v1.0",     CPU_POWERPC_7410_v10,               7410,
                "PowerPC 7410 v1.0 (G4)")
    POWERPC_DEF("7410_v1.1",     CPU_POWERPC_7410_v11,               7410,
                "PowerPC 7410 v1.1 (G4)")
    POWERPC_DEF("7410_v1.2",     CPU_POWERPC_7410_v12,               7410,
                "PowerPC 7410 v1.2 (G4)")
    POWERPC_DEF("7410_v1.3",     CPU_POWERPC_7410_v13,               7410,
                "PowerPC 7410 v1.3 (G4)")
    POWERPC_DEF("7410_v1.4",     CPU_POWERPC_7410_v14,               7410,
                "PowerPC 7410 v1.4 (G4)")
    POWERPC_DEF("7448_v1.0",     CPU_POWERPC_7448_v10,               7400,
                "PowerPC 7448 v1.0 (G4)")
    POWERPC_DEF("7448_v1.1",     CPU_POWERPC_7448_v11,               7400,
                "PowerPC 7448 v1.1 (G4)")
    POWERPC_DEF("7448_v2.0",     CPU_POWERPC_7448_v20,               7400,
                "PowerPC 7448 v2.0 (G4)")
    POWERPC_DEF("7448_v2.1",     CPU_POWERPC_7448_v21,               7400,
                "PowerPC 7448 v2.1 (G4)")
    POWERPC_DEF("7450_v1.0",     CPU_POWERPC_7450_v10,               7450,
                "PowerPC 7450 v1.0 (G4)")
    POWERPC_DEF("7450_v1.1",     CPU_POWERPC_7450_v11,               7450,
                "PowerPC 7450 v1.1 (G4)")
    POWERPC_DEF("7450_v1.2",     CPU_POWERPC_7450_v12,               7450,
                "PowerPC 7450 v1.2 (G4)")
    POWERPC_DEF("7450_v2.0",     CPU_POWERPC_7450_v20,               7450,
                "PowerPC 7450 v2.0 (G4)")
    POWERPC_DEF("7450_v2.1",     CPU_POWERPC_7450_v21,               7450,
                "PowerPC 7450 v2.1 (G4)")
    POWERPC_DEF("7441_v2.1",     CPU_POWERPC_7450_v21,               7440,
                "PowerPC 7441 v2.1 (G4)")
    POWERPC_DEF("7441_v2.3",     CPU_POWERPC_74x1_v23,               7440,
                "PowerPC 7441 v2.3 (G4)")
    POWERPC_DEF("7451_v2.3",     CPU_POWERPC_74x1_v23,               7450,
                "PowerPC 7451 v2.3 (G4)")
    POWERPC_DEF("7441_v2.10",    CPU_POWERPC_74x1_v210,              7440,
                "PowerPC 7441 v2.10 (G4)")
    POWERPC_DEF("7451_v2.10",    CPU_POWERPC_74x1_v210,              7450,
                "PowerPC 7451 v2.10 (G4)")
    POWERPC_DEF("7445_v1.0",     CPU_POWERPC_74x5_v10,               7445,
                "PowerPC 7445 v1.0 (G4)")
    POWERPC_DEF("7455_v1.0",     CPU_POWERPC_74x5_v10,               7455,
                "PowerPC 7455 v1.0 (G4)")
    POWERPC_DEF("7445_v2.1",     CPU_POWERPC_74x5_v21,               7445,
                "PowerPC 7445 v2.1 (G4)")
    POWERPC_DEF("7455_v2.1",     CPU_POWERPC_74x5_v21,               7455,
                "PowerPC 7455 v2.1 (G4)")
    POWERPC_DEF("7445_v3.2",     CPU_POWERPC_74x5_v32,               7445,
                "PowerPC 7445 v3.2 (G4)")
    POWERPC_DEF("7455_v3.2",     CPU_POWERPC_74x5_v32,               7455,
                "PowerPC 7455 v3.2 (G4)")
    POWERPC_DEF("7445_v3.3",     CPU_POWERPC_74x5_v33,               7445,
                "PowerPC 7445 v3.3 (G4)")
    POWERPC_DEF("7455_v3.3",     CPU_POWERPC_74x5_v33,               7455,
                "PowerPC 7455 v3.3 (G4)")
    POWERPC_DEF("7445_v3.4",     CPU_POWERPC_74x5_v34,               7445,
                "PowerPC 7445 v3.4 (G4)")
    POWERPC_DEF("7455_v3.4",     CPU_POWERPC_74x5_v34,               7455,
                "PowerPC 7455 v3.4 (G4)")
    POWERPC_DEF("7447_v1.0",     CPU_POWERPC_74x7_v10,               7445,
                "PowerPC 7447 v1.0 (G4)")
    POWERPC_DEF("7457_v1.0",     CPU_POWERPC_74x7_v10,               7455,
                "PowerPC 7457 v1.0 (G4)")
    POWERPC_DEF("7447_v1.1",     CPU_POWERPC_74x7_v11,               7445,
                "PowerPC 7447 v1.1 (G4)")
    POWERPC_DEF("7457_v1.1",     CPU_POWERPC_74x7_v11,               7455,
                "PowerPC 7457 v1.1 (G4)")
    POWERPC_DEF("7457_v1.2",     CPU_POWERPC_74x7_v12,               7455,
                "PowerPC 7457 v1.2 (G4)")
    POWERPC_DEF("7447a_v1.0",    CPU_POWERPC_74x7A_v10,              7445,
                "PowerPC 7447A v1.0 (G4)")
    POWERPC_DEF("7457a_v1.0",    CPU_POWERPC_74x7A_v10,              7455,
                "PowerPC 7457A v1.0 (G4)")
    POWERPC_DEF("7447a_v1.1",    CPU_POWERPC_74x7A_v11,              7445,
                "PowerPC 7447A v1.1 (G4)")
    POWERPC_DEF("7457a_v1.1",    CPU_POWERPC_74x7A_v11,              7455,
                "PowerPC 7457A v1.1 (G4)")
    POWERPC_DEF("7447a_v1.2",    CPU_POWERPC_74x7A_v12,              7445,
                "PowerPC 7447A v1.2 (G4)")
    POWERPC_DEF("7457a_v1.2",    CPU_POWERPC_74x7A_v12,              7455,
                "PowerPC 7457A v1.2 (G4)")
#ifdef TARGET_PPC64
    POWERPC_DEF_SVR("e5500", "e5500",
                    CPU_POWERPC_e5500,        POWERPC_SVR_E500,      e5500)
    POWERPC_DEF_SVR("e6500", "e6500",
                    CPU_POWERPC_e6500,        POWERPC_SVR_E500,      e6500)
    POWERPC_DEF("970_v2.2",      CPU_POWERPC_970_v22,                970,
                "PowerPC 970 v2.2")
    POWERPC_DEF("970fx_v1.0",    CPU_POWERPC_970FX_v10,              970,
                "PowerPC 970FX v1.0 (G5)")
    POWERPC_DEF("970fx_v2.0",    CPU_POWERPC_970FX_v20,              970,
                "PowerPC 970FX v2.0 (G5)")
    POWERPC_DEF("970fx_v2.1",    CPU_POWERPC_970FX_v21,              970,
                "PowerPC 970FX v2.1 (G5)")
    POWERPC_DEF("970fx_v3.0",    CPU_POWERPC_970FX_v30,              970,
                "PowerPC 970FX v3.0 (G5)")
    POWERPC_DEF("970fx_v3.1",    CPU_POWERPC_970FX_v31,              970,
                "PowerPC 970FX v3.1 (G5)")
    POWERPC_DEF("970mp_v1.0",    CPU_POWERPC_970MP_v10,              970,
                "PowerPC 970MP v1.0")
    POWERPC_DEF("970mp_v1.1",    CPU_POWERPC_970MP_v11,              970,
                "PowerPC 970MP v1.1")
    POWERPC_DEF("power5+_v2.1",  CPU_POWERPC_POWER5P_v21,            POWER5P,
                "POWER5+ v2.1")
    POWERPC_DEF("power7_v2.3",   CPU_POWERPC_POWER7_v23,             POWER7,
                "POWER7 v2.3")
    POWERPC_DEF("power7+_v2.1",  CPU_POWERPC_POWER7P_v21,            POWER7,
                "POWER7+ v2.1")
    POWERPC_DEF("power8e_v2.1",  CPU_POWERPC_POWER8E_v21,            POWER8,
                "POWER8E v2.1")
    POWERPC_DEF("power8_v2.0",   CPU_POWERPC_POWER8_v20,             POWER8,
                "POWER8 v2.0")
    POWERPC_DEF("power8nvl_v1.0", CPU_POWERPC_POWER8NVL_v10,         POWER8,
                "POWER8NVL v1.0")
    POWERPC_DEF("power9_v1.0",   CPU_POWERPC_POWER9_DD1,             POWER9,
                "POWER9 v1.0")
    POWERPC_DEF("power9_v2.0",   CPU_POWERPC_POWER9_DD20,            POWER9,
                "POWER9 v2.0")
    POWERPC_DEF("power10_v1.0",  CPU_POWERPC_POWER10_DD1,            POWER10,
                "POWER10 v1.0")
#endif /* defined (TARGET_PPC64) */
};

PowerPCCPU *cpu_ppc_init(struct uc_struct *uc)
{
    PowerPCCPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    PowerPCCPUClass *pcc;

    cpu = malloc(sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }
    memset(cpu, 0, sizeof(*cpu));
#ifdef TARGET_PPC64
    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = UC_CPU_PPC64_POWER10_V1_0 + UC_CPU_PPC32_7457A_V1_2 + 1; // power10_v1.0
    } else if (uc->cpu_model + UC_CPU_PPC32_7457A_V1_2 + 1 >= ARRAY_SIZE(ppc_cpus)) {
        free(cpu);
        return NULL;
    }
#else
    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = UC_CPU_PPC32_7457A_V1_2; // 7457a_v1.2
    } else if (uc->cpu_model >= ARRAY_SIZE(ppc_cpus)) {
        free(cpu);
        return NULL;
    }
#endif


    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = (CPUState *)cpu;

    /* init CPUClass */
    cpu_class_init(uc, cc);
    /* init PowerPCCPUClass */
    ppc_cpu_class_init(uc, cc);
    /* init PowerPC family class */
    pcc = &cpu->cc;
    pcc->pvr = ppc_cpus[uc->cpu_model].pvr;
    pcc->svr = ppc_cpus[uc->cpu_model].svr;
    if (ppc_cpus[uc->cpu_model].cpu_family_class_init) {
        ppc_cpus[uc->cpu_model].cpu_family_class_init(cc, uc);
    }
    /* init CPUState */
    cpu_common_initfn(uc, cs);
    /* init PowerPCCPU */
    ppc_cpu_instance_init(uc, cs);
    /* init PowerPC types */
    /* postinit PowerPCCPU */
    /* realize PowerPCCPU */
    ppc_cpu_realize(uc, cs);
    /* realize CPUState */

    // init address space
    cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    ppc_cpu_reset((CPUState *)cpu);

    return cpu;
}
