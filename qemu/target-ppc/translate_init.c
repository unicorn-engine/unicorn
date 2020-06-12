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
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */



//#include "disas/bfd.h"
//#include "exec/gdbstub.h"
//#include <sysemu/kvm.h>
//#include "kvm_ppc.h"
//#include "sysemu/arch_init.h"
#include "sysemu/cpus.h"
#include "cpu-models.h"
#include "mmu-hash32.h"
#include "mmu-hash64.h"
//#include "qemu/error-report.h"
#include "qemu/module.h"

// From kvm_ppc.h
#define TYPE_HOST_POWERPC_CPU "host-" TYPE_POWERPC_CPU

#if defined(__GNUC__)
#define UNUSED_FUNCTION __attribute__ (( unused ))
#else
#define UNUSED_FUNCTION
#endif

#if defined(_WIN32) && defined(_MSC_VER)
#define strncasecmp _strnicmp
#endif

//#define PPC_DUMP_CPU
//#define PPC_DEBUG_SPR
//#define PPC_DUMP_SPR_ACCESSES
/* #define USE_APPLE_GDB */

void ppc_cpu_register_types(void *opaque);

/* For user-mode emulation, we don't emulate any IRQ controller */
#if defined(CONFIG_USER_ONLY)
#define PPC_IRQ_INIT_FN(name)                                                 \
static inline void glue(glue(ppc, name),_irq_init) (CPUPPCState *env)         \
{                                                                             \
}
#else
#define PPC_IRQ_INIT_FN(name)                                                 \
void glue(glue(ppc, name),_irq_init) (CPUPPCState *env);
#endif

PPC_IRQ_INIT_FN(40x);
PPC_IRQ_INIT_FN(6xx);
PPC_IRQ_INIT_FN(970);
PPC_IRQ_INIT_FN(POWER7);
PPC_IRQ_INIT_FN(e500);

/* Generic callbacks:
 * do nothing but store/retrieve spr value
 */
static void spr_load_dump_spr(int sprn)
{
#ifdef PPC_DUMP_SPR_ACCESSES
    TCGv_i32 t0 = tcg_const_i32(sprn);
    gen_helper_load_dump_spr(cpu_env, t0);
    tcg_temp_free_i32(t0);
#endif
}

static void spr_read_generic (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    gen_load_spr(ctx, cpu_gpr[gprn], sprn);
    spr_load_dump_spr(sprn);
}

static void spr_store_dump_spr(int sprn)
{
#ifdef PPC_DUMP_SPR_ACCESSES
    TCGv_i32 t0 = tcg_const_i32(sprn);
    gen_helper_store_dump_spr(cpu_env, t0);
    tcg_temp_free_i32(t0);
#endif
}

static void spr_write_generic (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    gen_store_spr(ctx, sprn, cpu_gpr[gprn]);
    spr_store_dump_spr(sprn);
}

#if !defined(CONFIG_USER_ONLY)
static void spr_write_generic32(void *opaque, int sprn, int gprn)
{
#ifdef TARGET_PPC64
    DisasContext *ctx = opaque;

    TCGv t0 = tcg_temp_new(ctx->uc->tcg_ctx);
    tcg_gen_ext32u_tl(ctx->uc->tcg_ctx, t0, cpu_gpr[gprn]);
    gen_store_spr(ctx->uc->tcg_ctx, sprn, t0);
    tcg_temp_free(ctx->uc->tcg_ctx, t0);
    spr_store_dump_spr(sprn);
#else
    spr_write_generic(opaque, sprn, gprn);
#endif
}

static void spr_write_clear (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    TCGv t0 = tcg_temp_new(ctx->uc->tcg_ctx);
    TCGv t1 = tcg_temp_new(ctx->uc->tcg_ctx);
    gen_load_spr(ctx, t0, sprn);
    tcg_gen_neg_tl(ctx->uc->tcg_ctx, t1, cpu_gpr[gprn]);
    tcg_gen_and_tl(ctx->uc->tcg_ctx, t0, t0, t1);
    gen_store_spr(ctx, sprn, t0);
    tcg_temp_free(ctx->uc->tcg_ctx, t0);
    tcg_temp_free(ctx->uc->tcg_ctx, t1);
}

#endif

/* SPR common to all PowerPC */
/* XER */
static void spr_read_xer (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    gen_read_xer(ctx, cpu_gpr[gprn]);
}

static void spr_write_xer (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    gen_write_xer(ctx, cpu_gpr[gprn]);
}

/* LR */
static void spr_read_lr (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    tcg_gen_mov_tl(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_lr);
}

static void spr_write_lr (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    tcg_gen_mov_tl(ctx->uc->tcg_ctx, cpu_lr, cpu_gpr[gprn]);
}

/* CFAR */
#if defined(TARGET_PPC64) && !defined(CONFIG_USER_ONLY)
static void spr_read_cfar (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    tcg_gen_mov_tl(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_cfar);
}

static void spr_write_cfar (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    tcg_gen_mov_tl(ctx->uc->tcg_ctx, cpu_cfar, cpu_gpr[gprn]);
}
#endif /* defined(TARGET_PPC64) && !defined(CONFIG_USER_ONLY) */

/* CTR */
static void spr_read_ctr (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    tcg_gen_mov_tl(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_ctr);
}

static void spr_write_ctr (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    tcg_gen_mov_tl(ctx->uc->tcg_ctx, cpu_ctr, cpu_gpr[gprn]);
}

/* User read access to SPR */
/* USPRx */
/* UMMCRx */
/* UPMCx */
/* USIA */
/* UDECR */
static void spr_read_ureg (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    gen_load_spr(ctx, cpu_gpr[gprn], sprn + 0x10);
}

#if defined(TARGET_PPC64) && !defined(CONFIG_USER_ONLY)
static void spr_write_ureg(void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    gen_store_spr(ctx->uc->tcg_ctx, sprn + 0x10, cpu_gpr[gprn]);
}
#endif

/* SPR common to all non-embedded PowerPC */
/* DECR */
#if !defined(CONFIG_USER_ONLY)
static void spr_read_decr (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
//    if (use_icount) {
//        gen_io_start();
//    }
    gen_helper_load_decr(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_env);
//    if (use_icount) {
//        gen_io_end();
//        gen_stop_exception(opaque);
//    }
}

static void spr_write_decr (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
//    if (use_icount) {
//        gen_io_start();
//    }
    gen_helper_store_decr(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
//    if (use_icount) {
//        gen_io_end();
//        gen_stop_exception(opaque);
//    }
}
#endif

/* SPR common to all non-embedded PowerPC, except 601 */
/* Time base */
static void spr_read_tbl (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
//    if (use_icount) {
//        gen_io_start();
//    }
    gen_helper_load_tbl(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_env);
//    if (use_icount) {
//        gen_io_end();
//        gen_stop_exception(opaque);
//    }
}

static void spr_read_tbu (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
//    if (use_icount) {
//        gen_io_start();
//    }
    gen_helper_load_tbu(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_env);
//    if (use_icount) {
//        gen_io_end();
//        gen_stop_exception(opaque);
//    }
}

UNUSED_FUNCTION
static void spr_read_atbl (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    gen_helper_load_atbl(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_env);
}

UNUSED_FUNCTION
static void spr_read_atbu (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    gen_helper_load_atbu(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_env);
}

#if !defined(CONFIG_USER_ONLY)
static void spr_write_tbl (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
//    if (use_icount) {
//        gen_io_start();
//    }
    gen_helper_store_tbl(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
//    if (use_icount) {
//        gen_io_end();
//        gen_stop_exception(opaque);
//    }
}

static void spr_write_tbu (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
//    if (use_icount) {
//        gen_io_start();
//    }
    gen_helper_store_tbu(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
//    if (use_icount) {
//        gen_io_end();
//        gen_stop_exception(opaque);
//    }
}

UNUSED_FUNCTION
static void spr_write_atbl (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    gen_helper_store_atbl(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
}

UNUSED_FUNCTION
static void spr_write_atbu (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    gen_helper_store_atbu(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
}

#if defined(TARGET_PPC64)
UNUSED_FUNCTION
static void spr_read_purr (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    gen_helper_load_purr(ctx->uc->tcg_ctx, cpu_gpr[gprn], cpu_env);
}
#endif
#endif

/* PowerPC 601 specific registers */
/* RTC */

/* PowerPC 40x specific registers */
#if !defined(CONFIG_USER_ONLY)
static void spr_write_40x_dbcr0 (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;

    gen_helper_store_40x_dbcr0(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
    /* We must stop translation as we may have rebooted */
    gen_stop_exception(ctx);
}

static void spr_write_booke_tcr (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    gen_helper_store_booke_tcr(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
}

static void spr_write_booke_tsr (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    gen_helper_store_booke_tsr(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
}
#endif

/* PowerPC 403 specific registers */
/* PBL1 / PBU1 / PBL2 / PBU2 */
#if !defined(CONFIG_USER_ONLY)
static void spr_write_pir (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    TCGv t0 = tcg_temp_new(ctx->uc->tcg_ctx);
    tcg_gen_andi_tl(ctx->uc->tcg_ctx, t0, cpu_gpr[gprn], 0xF);
    gen_store_spr(ctx, SPR_PIR, t0);
    tcg_temp_free(ctx->uc->tcg_ctx, t0);
}
#endif

/* SPE specific registers */
static void spr_read_spefscr (void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    TCGv_i32 t0 = tcg_temp_new_i32(ctx->uc->tcg_ctx);
    tcg_gen_ld_i32(ctx->uc->tcg_ctx, t0, cpu_env, offsetof(CPUPPCState, spe_fscr));
    tcg_gen_extu_i32_tl(ctx->uc->tcg_ctx, cpu_gpr[gprn], t0);
    tcg_temp_free_i32(ctx->uc->tcg_ctx, t0);
}

static void spr_write_spefscr (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    TCGv_i32 t0 = tcg_temp_new_i32(ctx->uc->tcg_ctx);
    tcg_gen_trunc_tl_i32(ctx->uc->tcg_ctx, t0, cpu_gpr[gprn]);
    tcg_gen_st_i32(ctx->uc->tcg_ctx, t0, cpu_env, offsetof(CPUPPCState, spe_fscr));
    tcg_temp_free_i32(ctx->uc->tcg_ctx, t0);
}

#if !defined(CONFIG_USER_ONLY)
/* Callback used to write the exception vector base */
static void spr_write_excp_prefix (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    TCGv t0 = tcg_temp_new(ctx->uc->tcg_ctx);
    tcg_gen_ld_tl(ctx->uc->tcg_ctx, t0, cpu_env, offsetof(CPUPPCState, ivpr_mask));
    tcg_gen_and_tl(ctx->uc->tcg_ctx, t0, t0, cpu_gpr[gprn]);
    tcg_gen_st_tl(ctx->uc->tcg_ctx, t0, cpu_env, offsetof(CPUPPCState, excp_prefix));
    gen_store_spr(ctx, sprn, t0);
    tcg_temp_free(ctx->uc->tcg_ctx, t0);
}

static void spr_write_excp_vector (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
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

    TCGv t0 = tcg_temp_new(ctx->uc->tcg_ctx);
    tcg_gen_ld_tl(ctx->uc->tcg_ctx, t0, cpu_env, offsetof(CPUPPCState, ivor_mask));
    tcg_gen_and_tl(ctx->uc->tcg_ctx, t0, t0, cpu_gpr[gprn]);
    tcg_gen_st_tl(ctx->uc->tcg_ctx, t0, cpu_env, offsetof(CPUPPCState, excp_vectors[sprn_offs]));
    gen_store_spr(ctx, sprn, t0);
    tcg_temp_free(ctx->uc->tcg_ctx, t0);
}
#endif

static inline void vscr_init (CPUPPCState *env, uint32_t val)
{
    env->vscr = val;
    /* Altivec always uses round-to-nearest */
    set_float_rounding_mode(float_round_nearest_even, &env->vec_status);
    set_flush_to_zero(vscr_nj, &env->vec_status);
}

#ifdef CONFIG_USER_ONLY
#define spr_register_kvm(env, num, name, uea_read, uea_write,                  \
                         oea_read, oea_write, one_reg_id, initial_value)       \
    _spr_register(env, num, name, uea_read, uea_write, initial_value)
#else
#if !defined(CONFIG_KVM)
#define spr_register_kvm(env, num, name, uea_read, uea_write,                  \
                         oea_read, oea_write, one_reg_id, initial_value) \
    _spr_register(env, num, name, uea_read, uea_write,                         \
                  oea_read, oea_write, initial_value)
#else
#define spr_register_kvm(env, num, name, uea_read, uea_write,                  \
                         oea_read, oea_write, one_reg_id, initial_value) \
    _spr_register(env, num, name, uea_read, uea_write,                         \
                  oea_read, oea_write, one_reg_id, initial_value)
#endif
#endif

#define spr_register(env, num, name, uea_read, uea_write,                      \
                     oea_read, oea_write, initial_value)                       \
    spr_register_kvm(env, num, name, uea_read, uea_write,                      \
                     oea_read, oea_write, 0, initial_value)

static inline void _spr_register(CPUPPCState *env, int num,
                                 const char *name,
                                 void (*uea_read)(void *opaque, int gprn, int sprn),
                                 void (*uea_write)(void *opaque, int sprn, int gprn),
#if !defined(CONFIG_USER_ONLY)

                                 void (*oea_read)(void *opaque, int gprn, int sprn),
                                 void (*oea_write)(void *opaque, int sprn, int gprn),
#endif
#if defined(CONFIG_KVM)
                                 uint64_t one_reg_id,
#endif
                                 target_ulong initial_value)
{
    ppc_spr_t *spr;

    spr = &env->spr_cb[num];
    if (spr->name != NULL ||env-> spr[num] != 0x00000000 ||
#if !defined(CONFIG_USER_ONLY)
        spr->oea_read != NULL || spr->oea_write != NULL ||
#endif
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
#if !defined(CONFIG_USER_ONLY)
    spr->oea_read = oea_read;
    spr->oea_write = oea_write;
#endif
#if defined(CONFIG_KVM)
    spr->one_reg_id = one_reg_id,
#endif
    env->spr[num] = spr->default_value = initial_value;
}

/* Generic PowerPC SPRs */
static void gen_spr_generic (CPUPPCState *env)
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

/* Generic PowerPC time base */
static void gen_tbl (CPUPPCState *env)
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

#if !defined(CONFIG_USER_ONLY)
static void spr_write_e500_l1csr0 (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    TCGv t0 = tcg_temp_new(ctx->uc->tcg_ctx);

    tcg_gen_andi_tl(ctx->uc->tcg_ctx, t0, cpu_gpr[gprn], L1CSR0_DCE | L1CSR0_CPE);
    gen_store_spr(ctx, sprn, t0);
    tcg_temp_free(ctx->uc->tcg_ctx, t0);
}
#endif

static void spr_write_e500_l1csr1(void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    TCGv t0 = tcg_temp_new(ctx->uc->tcg_ctx);

    tcg_gen_andi_tl(ctx->uc->tcg_ctx, t0, cpu_gpr[gprn], L1CSR1_ICE | L1CSR1_CPE);
    gen_store_spr(ctx, sprn, t0);
    tcg_temp_free(ctx->uc->tcg_ctx, t0);
}

static void spr_write_booke206_mmucsr0 (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    gen_helper_booke206_tlbflush(ctx->uc->tcg_ctx, cpu_env, cpu_gpr[gprn]);
}

static void spr_write_booke_pid (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    TCGv_i32 t0 = tcg_const_i32(ctx->uc->tcg_ctx, sprn);
    gen_helper_booke_setpid(ctx->uc->tcg_ctx, cpu_env, t0, cpu_gpr[gprn]);
    tcg_temp_free_i32(ctx->uc->tcg_ctx, t0);
}

static void gen_spr_usprgh (CPUPPCState *env)
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
static void gen_spr_BookE (CPUPPCState *env, uint64_t ivor_mask)
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
                              uint32_t *tlbncfg)
{
#if !defined(CONFIG_USER_ONLY)
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
        void (*uea_write)(void *o, int sprn, int gprn) = &spr_write_generic32;
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
    /* XXX : not implemented */
    spr_register(env, SPR_MMUCFG, "MMUCFG",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 0x00000000); /* TOFIX */
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
#endif

    gen_spr_usprgh(env);
}

// XXX: TODO
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
 * EPLC    => SPR 947 (Power 2.04 emb)
 * EPSC    => SPR 948 (Power 2.04 emb)
 * DABRX   => 1015    (Power 2.04 hypv)
 * FPECR   => SPR 1022 (?)
 * ... and more (thermal management, performance counters, ...)
 */

static void init_excp_e200(CPUPPCState *env, target_ulong ivpr_mask)
{
#if !defined(CONFIG_USER_ONLY)
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
#endif
}

static int check_pow_hid0 (CPUPPCState *env)
{
    if (env->spr[SPR_HID0] & 0x00E00000)
        return 1;

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

#define POWERPC_FAMILY_NAME(_name) \
    glue(glue(ppc_, _name), _cpu_family_class_init)
#define POWERPC_FAMILY(_name)                                               \
    static void POWERPC_FAMILY_NAME(_name)

#if !defined(CONFIG_USER_ONLY)
static void spr_write_mas73(void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
 
    TCGv val = tcg_temp_new(ctx->uc->tcg_ctx);
    tcg_gen_ext32u_tl(ctx->uc->tcg_ctx, val, cpu_gpr[gprn]);
    gen_store_spr(ctx, SPR_BOOKE_MAS3, val);
    tcg_gen_shri_tl(ctx->uc->tcg_ctx, val, cpu_gpr[gprn], 32);
    gen_store_spr(ctx, SPR_BOOKE_MAS7, val);
    tcg_temp_free(ctx->uc->tcg_ctx, val);
}

static void spr_read_mas73(void *opaque, int gprn, int sprn)
{
    DisasContext *ctx = opaque;
 
    TCGv mas7 = tcg_temp_new(ctx->uc->tcg_ctx);
    TCGv mas3 = tcg_temp_new(ctx->uc->tcg_ctx);
    gen_load_spr(ctx, mas7, SPR_BOOKE_MAS7);
    tcg_gen_shli_tl(ctx->uc->tcg_ctx, mas7, mas7, 32);
    gen_load_spr(ctx, mas3, SPR_BOOKE_MAS3);
    tcg_gen_or_tl(ctx->uc->tcg_ctx, cpu_gpr[gprn], mas3, mas7);
    tcg_temp_free(ctx->uc->tcg_ctx, mas3);
    tcg_temp_free(ctx->uc->tcg_ctx, mas7);
}

#endif

enum fsl_e500_version {
    fsl_e500v1,
    fsl_e500v2,
    fsl_e500mc,
    fsl_e5500,
};

static void init_proc_e500 (CPUPPCState *env, int version)
{
    PowerPCCPU *cpu = ppc_env_get_cpu(env);
    uint32_t tlbncfg[2];
    uint64_t ivor_mask;
    uint64_t ivpr_mask = 0xFFFF0000ULL;
    uint32_t l1cfg0 = 0x3800  /* 8 ways */
                    | 0x0020; /* 32 kb */
    uint32_t l1cfg1 = 0x3800  /* 8 ways */
                    | 0x0020; /* 32 kb */
#if !defined(CONFIG_USER_ONLY)
    int i;
#endif

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
    }
    gen_spr_BookE(env, ivor_mask);
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
#if !defined(CONFIG_USER_ONLY)
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
    default:
        cpu_abort(CPU(cpu), "Unknown CPU: " TARGET_FMT_lx "\n", env->spr[SPR_PVR]);
    }
#endif
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
    default:
        cpu_abort(CPU(cpu), "Unknown CPU: " TARGET_FMT_lx "\n", env->spr[SPR_PVR]);
    }
    gen_spr_BookE206(env, 0x000000DF, tlbncfg);
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
    if (version == fsl_e5500) {
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

#if !defined(CONFIG_USER_ONLY)
    env->nb_tlb = 0;
    env->tlb_type = TLB_MAS;
    for (i = 0; i < BOOKE206_MAX_TLBN; i++) {
        env->nb_tlb += booke206_tlb_size(env, i);
    }
#endif

    init_excp_e200(env, ivpr_mask);
    /* Allocate hardware IRQ controller */
    ppce500_irq_init(env);
}

static void init_proc_e500v2(CPUPPCState *env)
{
    init_proc_e500(env, fsl_e500v2);
}

POWERPC_FAMILY(e500v2)(struct uc_struct *uc, CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc, oc);

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
//    pcc->mmu_model = POWERPC_MMU_BOOKE206;
	pcc->mmu_model = POWERPC_MMU_REAL;				//  Disable MMU
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
//    pcc->bfd_mach = bfd_mach_ppc_860;
    pcc->flags = POWERPC_FLAG_SPE | POWERPC_FLAG_CE |
                 POWERPC_FLAG_UBLE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}

/*****************************************************************************/
/* Generic CPU instantiation routine                                         */
static void init_ppc_proc(struct uc_struct *uc, PowerPCCPU *cpu)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(uc, cpu);
    CPUPPCState *env = &cpu->env;
#if !defined(CONFIG_USER_ONLY)
    int i;

    env->irq_inputs = NULL;
    /* Set all exception vectors to an invalid address */
    for (i = 0; i < POWERPC_EXCP_NB; i++)
        env->excp_vectors[i] = (target_ulong)(-1ULL);
    env->ivor_mask = 0x00000000;
    env->ivpr_mask = 0x00000000;
    /* Default MMU definitions */
    env->nb_BATs = 0;
    env->nb_tlb = 0;
    env->nb_ways = 0;
    env->tlb_type = TLB_NONE;
#endif
    /* Register SPR common to all PowerPC implementations */
    gen_spr_generic(env);
#if defined(CONFIG_LINUX_USER)
    spr_register(env, SPR_PVR, "PVR",
                 /* Linux permits userspace to read PVR */
                 &spr_read_generic,
                 SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 pcc->pvr);
#else
    spr_register(env, SPR_PVR, "PVR",
                 SPR_NOACCESS,
                 SPR_NOACCESS,
                 &spr_read_generic, SPR_NOACCESS,
                 pcc->pvr);
#endif
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
#if !defined(CONFIG_USER_ONLY)
    if (env->nb_tlb != 0) {
        int nb_tlb = env->nb_tlb;
        if (env->id_tlbs != 0)
            nb_tlb *= 2;
        switch (env->tlb_type) {
        case TLB_6XX:
            env->tlb.tlb6 = g_malloc0(nb_tlb * sizeof(ppc6xx_tlb_t));
            break;
        case TLB_EMB:
            env->tlb.tlbe = g_malloc0(nb_tlb * sizeof(ppcemb_tlb_t));
            break;
        case TLB_MAS:
            env->tlb.tlbm = g_malloc0(nb_tlb * sizeof(ppcmas_tlb_t));
            break;
        }
        /* Pre-compute some useful values */
        env->tlb_per_way = env->nb_tlb / env->nb_ways;
    }
/*    if (env->irq_inputs == NULL) {
        fprintf(stderr, "WARNING: no internal IRQ controller registered.\n"
                " Attempt QEMU to crash very soon !\n");
    }*/
#endif
    if (env->check_pow == NULL) {
        fprintf(stderr, "WARNING: no power management check handler "
                "registered.\n"
                " Attempt QEMU to crash very soon !\n");
    }
}

#if defined(PPC_DUMP_CPU)
static void dump_ppc_sprs (CPUPPCState *env)
{
    ppc_spr_t *spr;
#if !defined(CONFIG_USER_ONLY)
    uint32_t sr, sw;
#endif
    uint32_t ur, uw;
    int i, j, n;

    printf("Special purpose registers:\n");
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 32; j++) {
            n = (i << 5) | j;
            spr = &env->spr_cb[n];
            uw = spr->uea_write != NULL && spr->uea_write != SPR_NOACCESS;
            ur = spr->uea_read != NULL && spr->uea_read != SPR_NOACCESS;
#if !defined(CONFIG_USER_ONLY)
            sw = spr->oea_write != NULL && spr->oea_write != SPR_NOACCESS;
            sr = spr->oea_read != NULL && spr->oea_read != SPR_NOACCESS;
            if (sw || sr || uw || ur) {
                printf("SPR: %4d (%03x) %-8s s%c%c u%c%c\n",
                       (i << 5) | j, (i << 5) | j, spr->name,
                       sw ? 'w' : '-', sr ? 'r' : '-',
                       uw ? 'w' : '-', ur ? 'r' : '-');
            }
#else
            if (uw || ur) {
                printf("SPR: %4d (%03x) %-8s u%c%c\n",
                       (i << 5) | j, (i << 5) | j, spr->name,
                       uw ? 'w' : '-', ur ? 'r' : '-');
            }
#endif
        }
    }
    fflush(stdout);
    fflush(stderr);
}
#endif

/*****************************************************************************/
#include <stdlib.h>
#include <string.h>

/* Opcode types */
enum {
    PPC_DIRECT   = 0, /* Opcode routine        */
    PPC_INDIRECT = 1, /* Indirect opcode table */
};

#define PPC_OPCODE_MASK 0x3

static inline int is_indirect_opcode (void *handler)
{
    return ((uintptr_t)handler & PPC_OPCODE_MASK) == PPC_INDIRECT;
}

static inline opc_handler_t **ind_table(void *handler)
{
    return (opc_handler_t **)((uintptr_t)handler & ~PPC_OPCODE_MASK);
}

/* Instruction table creation */
/* Opcodes tables creation */
static void fill_new_table (opc_handler_t **table, int len)
{
    int i;

    for (i = 0; i < len; i++)
        table[i] = &invalid_handler;
}

static int create_new_table (opc_handler_t **table, unsigned char idx)
{
    opc_handler_t **tmp;

    tmp = g_new(opc_handler_t *, PPC_CPU_INDIRECT_OPCODES_LEN);
    fill_new_table(tmp, PPC_CPU_INDIRECT_OPCODES_LEN);
    table[idx] = (opc_handler_t *)((uintptr_t)tmp | PPC_INDIRECT);

    return 0;
}

static int insert_in_table (opc_handler_t **table, unsigned char idx,
                            opc_handler_t *handler)
{
    if (table[idx] != &invalid_handler)
        return -1;
    table[idx] = handler;

    return 0;
}

static int register_direct_insn (opc_handler_t **ppc_opcodes,
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

static int register_ind_in_table (opc_handler_t **table,
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

static int register_ind_insn (opc_handler_t **ppc_opcodes,
                              unsigned char idx1, unsigned char idx2,
                              opc_handler_t *handler)
{
    int ret;

    ret = register_ind_in_table(ppc_opcodes, idx1, idx2, handler);

    return ret;
}

static int register_dblind_insn (opc_handler_t **ppc_opcodes,
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

static int register_insn (opc_handler_t **ppc_opcodes, opcode_t *insn)
{
    if (insn->opc2 != 0xFF) {
        if (insn->opc3 != 0xFF) {
            if (register_dblind_insn(ppc_opcodes, insn->opc1, insn->opc2,
                                     insn->opc3, &insn->handler) < 0)
                return -1;
        } else {
            if (register_ind_insn(ppc_opcodes, insn->opc1,
                                  insn->opc2, &insn->handler) < 0)
                return -1;
        }
    } else {
        if (register_direct_insn(ppc_opcodes, insn->opc1, &insn->handler) < 0)
            return -1;
    }

    return 0;
}

static int test_opcode_table (opc_handler_t **table, int len)
{
    int i, count, tmp;

    for (i = 0, count = 0; i < len; i++) {
        /* Consistency fixup */
        if (table[i] == NULL)
            table[i] = &invalid_handler;
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

static void fix_opcode_tables (opc_handler_t **ppc_opcodes)
{
    if (test_opcode_table(ppc_opcodes, PPC_CPU_OPCODES_LEN) == 0)
        printf("*** WARNING: no opcode defined !\n");
}

/*****************************************************************************/
static void create_ppc_opcodes(struct uc_struct *uc, PowerPCCPU *cpu)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(uc, cpu);
    CPUPPCState *env = &cpu->env;
    opcode_t *opc;

    fill_new_table(env->opcodes, PPC_CPU_OPCODES_LEN);
    for (opc = opcodes; opc < &opcodes[ARRAY_SIZE(opcodes)]; opc++) {
        if (((opc->handler.type & pcc->insns_flags) != 0) ||
            ((opc->handler.type2 & pcc->insns_flags2) != 0)) {
            if (register_insn(env->opcodes, opc) < 0) {
                return;
            }
        }
    }
    fix_opcode_tables(env->opcodes);
    fflush(stdout);
    fflush(stderr);
}

#if defined(PPC_DUMP_CPU)
static void dump_ppc_insns (CPUPPCState *env)
{
    opc_handler_t **table, *handler;
    const char *p, *q;
    uint8_t opc1, opc2, opc3;

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
                                if ((p - handler->oname) != strlen(q) ||
                                    memcmp(handler->oname, q, strlen(q)) != 0) {
                                    /* First instruction */
                                    printf("INSN: %02x %02x %02x (%02d %04d) : "
                                           "%.*s\n",
                                           opc1, opc2 << 1, opc3, opc1,
                                           (opc3 << 6) | (opc2 << 1),
                                           (int)(p - handler->oname),
                                           handler->oname);
                                }
                                if (strcmp(p + 1, q) != 0) {
                                    /* Second instruction */
                                    printf("INSN: %02x %02x %02x (%02d %04d) : "
                                           "%s\n",
                                           opc1, (opc2 << 1) | 1, opc3, opc1,
                                           (opc3 << 6) | (opc2 << 1) | 1,
                                           p + 1);
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

static int ppc_fixup_cpu(PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;

    /* TCG doesn't (yet) emulate some groups of instructions that
     * are implemented on some otherwise supported CPUs (e.g. VSX
     * and decimal floating point instructions on POWER7).  We
     * remove unsupported instruction groups from the cpu state's
     * instruction masks and hope the guest can cope.  For at
     * least the pseries machine, the unavailability of these
     * instructions can be advertised to the guest via the device
     * tree. */
    if ((env->insns_flags & ~PPC_TCG_INSNS)
        || (env->insns_flags2 & ~PPC_TCG_INSNS2)) {
        fprintf(stderr, "Warning: Disabling some instructions which are not "
                "emulated by TCG (0x%" PRIx64 ", 0x%" PRIx64 ")\n",
                (unsigned long)(env->insns_flags & ~PPC_TCG_INSNS),
                (unsigned long)(env->insns_flags2 & ~PPC_TCG_INSNS2));
    }
    env->insns_flags &= PPC_TCG_INSNS;
    env->insns_flags2 &= PPC_TCG_INSNS2;
    return 0;
}

static inline bool ppc_cpu_is_valid(PowerPCCPUClass *pcc)
{
#ifdef TARGET_PPCEMB
    return pcc->mmu_model == POWERPC_MMU_BOOKE ||
           pcc->mmu_model == POWERPC_MMU_SOFT_4xx ||
           pcc->mmu_model == POWERPC_MMU_SOFT_4xx_Z;
#else
    return true;
#endif
}

static int ppc_cpu_realizefn(struct uc_struct *uc, CPUState *dev)
{
    CPUState *cs = CPU(dev);
    PowerPCCPU *cpu = POWERPC_CPU(uc, dev);
/*#if !defined(CONFIG_USER_ONLY)
//    int max_smt = kvm_enabled() ? kvmppc_smt_threads() : 1;
    int max_smt = 1;
#endif*/

/*#if !defined(CONFIG_USER_ONLY)
    if (smp_threads > max_smt) {
        error_setg(errp, "Cannot support more than %d threads on PPC with %s",
                   max_smt, kvm_enabled() ? "KVM" : "TCG");
        return;
    }
    if (!is_power_of_2(smp_threads)) {
        error_setg(errp, "Cannot support %d threads on PPC with %s, "
                   "threads count must be a power of 2.",
                   smp_threads, kvm_enabled() ? "KVM" : "TCG");
        return;
    }

    cpu->cpu_dt_id = (cs->cpu_index / smp_threads) * max_smt
        + (cs->cpu_index % smp_threads);
#endif*/

    if (tcg_enabled(uc)) {
        if (ppc_fixup_cpu(cpu) != 0) {
            return -1;
        }
    }

#if defined(TARGET_PPCEMB)
    if (!ppc_cpu_is_valid(pcc)) {
        return -1;
    }
#endif

    create_ppc_opcodes(uc, cpu);
    init_ppc_proc(uc, cpu);

/*    if (pcc->insns_flags & PPC_FLOAT) {
        gdb_register_coprocessor(cs, gdb_get_float_reg, gdb_set_float_reg,
                                 33, "power-fpu.xml", 0);
    }
    if (pcc->insns_flags & PPC_ALTIVEC) {
        gdb_register_coprocessor(cs, gdb_get_avr_reg, gdb_set_avr_reg,
                                 34, "power-altivec.xml", 0);
    }
    if (pcc->insns_flags & PPC_SPE) {
        gdb_register_coprocessor(cs, gdb_get_spe_reg, gdb_set_spe_reg,
                                 34, "power-spe.xml", 0);
    }
*/
    qemu_init_vcpu(cs);

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
#if defined (TARGET_PPC64)
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
#if defined (TARGET_PPC64)
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
#if defined (TARGET_PPC64)
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
#if !defined(CONFIG_USER_ONLY)
        if (env->tlb.tlb6) {
            printf("                       %d %s TLB in %d ways\n",
                   env->nb_tlb, env->id_tlbs ? "splitted" : "merged",
                   env->nb_ways);
        }
#endif
        printf("    Exceptions model : %s\n"
               "    Bus model        : %s\n",
               excp_model, bus_model);
        printf("    MSR features     :\n");
        if (env->flags & POWERPC_FLAG_SPE)
            printf("                        signal processing engine enable"
                   "\n");
        else if (env->flags & POWERPC_FLAG_VRE)
            printf("                        vector processor enable\n");
        if (env->flags & POWERPC_FLAG_TGPR)
            printf("                        temporary GPRs\n");
        else if (env->flags & POWERPC_FLAG_CE)
            printf("                        critical input enable\n");
        if (env->flags & POWERPC_FLAG_SE)
            printf("                        single-step trace mode\n");
        else if (env->flags & POWERPC_FLAG_DWE)
            printf("                        debug wait enable\n");
        else if (env->flags & POWERPC_FLAG_UBLE)
            printf("                        user BTB lock enable\n");
        if (env->flags & POWERPC_FLAG_BE)
            printf("                        branch-step trace mode\n");
        else if (env->flags & POWERPC_FLAG_DE)
            printf("                        debug interrupt enable\n");
        if (env->flags & POWERPC_FLAG_PX)
            printf("                        inclusive protection\n");
        else if (env->flags & POWERPC_FLAG_PMM)
            printf("                        performance monitor mark\n");
        if (env->flags == POWERPC_FLAG_NONE)
            printf("                        none\n");
        printf("    Time-base/decrementer clock source: %s\n",
               env->flags & POWERPC_FLAG_RTC_CLK ? "RTC clock" : "bus clock");
        dump_ppc_insns(env);
        dump_ppc_sprs(env);
        fflush(stdout);
    }
#endif
	return 0;
}

void ppc_cpu_unrealizefn(struct uc_struct *uc, CPUState *dev);
void ppc_cpu_unrealizefn(struct uc_struct *uc, CPUState *dev)
{
    PowerPCCPU *cpu = POWERPC_CPU(uc, dev);
    CPUPPCState *env = &cpu->env;
    opc_handler_t **table;
    int i, j;

    for (i = 0; i < PPC_CPU_OPCODES_LEN; i++) {
        if (env->opcodes[i] == &invalid_handler) {
            continue;
        }
        if (is_indirect_opcode(env->opcodes[i])) {
            table = ind_table(env->opcodes[i]);
            for (j = 0; j < PPC_CPU_INDIRECT_OPCODES_LEN; j++) {
                if (table[j] != &invalid_handler &&
                        is_indirect_opcode(table[j])) {
                    g_free((opc_handler_t *)((uintptr_t)table[j] &
                        ~PPC_INDIRECT));
                }
            }
            g_free((opc_handler_t *)((uintptr_t)env->opcodes[i] &
                ~PPC_INDIRECT));
        }
    }
    return;
}

static void ppc_cpu_set_pc(CPUState *cs, vaddr value)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs->uc, cs);
    cpu->env.nip = value;
}

static bool ppc_cpu_has_work(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs->uc, cs);
    CPUPPCState *env = &cpu->env;

    return msr_ee && (cs->interrupt_request & CPU_INTERRUPT_HARD);
}

static void ppc_cpu_exec_enter(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs->uc, cs);
    CPUPPCState *env = &cpu->env;

    env->reserve_addr = -1;
}

/* CPUClass::reset() */
static void ppc_cpu_reset(CPUState *s)
{
    PowerPCCPU *cpu = POWERPC_CPU(s->uc, s);
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(s->uc, cpu);
    CPUPPCState *env = &cpu->env;
    target_ulong msr;
    int i;

    pcc->parent_reset(s);

    msr = (target_ulong)0;
    if (0) {
        /* XXX: find a suitable condition to enable the hypervisor mode */
        msr |= (target_ulong)MSR_HVB;
    }
    msr |= (target_ulong)0 << MSR_AP; /* TO BE CHECKED */
    msr |= (target_ulong)0 << MSR_SA; /* TO BE CHECKED */
    msr |= (target_ulong)1 << MSR_EP;
#if defined(DO_SINGLE_STEP) && 0
    /* Single step trace mode */
    msr |= (target_ulong)1 << MSR_SE;
    msr |= (target_ulong)1 << MSR_BE;
#endif
#if defined(CONFIG_USER_ONLY)
    msr |= (target_ulong)1 << MSR_FP; /* Allow floating point usage */
    msr |= (target_ulong)1 << MSR_VR; /* Allow altivec usage */
    msr |= (target_ulong)1 << MSR_VSX; /* Allow VSX usage */
    msr |= (target_ulong)1 << MSR_SPE; /* Allow SPE usage */
    msr |= (target_ulong)1 << MSR_PR;
#if defined(TARGET_PPC64)
    msr |= (target_ulong)1 << MSR_TM; /* Transactional memory */
#endif
#if !defined(TARGET_WORDS_BIGENDIAN)
    msr |= (target_ulong)1 << MSR_LE; /* Little-endian user mode */
    if (!((env->msr_mask >> MSR_LE) & 1)) {
        fprintf(stderr, "Selected CPU does not support little-endian.\n");
        exit(1);
    }
#endif
#endif

#if defined(TARGET_PPC64)
    if (env->mmu_model & POWERPC_MMU_64) {
        env->msr |= (1ULL << MSR_SF);
    }
#endif

    hreg_store_msr(env, msr, 1);

#if !defined(CONFIG_USER_ONLY)
    env->nip = env->hreset_vector | env->excp_prefix;
    if (env->mmu_model != POWERPC_MMU_REAL) {
        ppc_tlb_invalidate_all(env);
    }
#endif

    hreg_compute_hflags(env);
    env->reserve_addr = (target_ulong)-1ULL;
    /* Be sure no exception or interrupt is pending */
    env->pending_interrupts = 0;
    s->exception_index = POWERPC_EXCP_NONE;
    env->error_code = 0;

#if defined(TARGET_PPC64) && !defined(CONFIG_USER_ONLY)
    env->vpa_addr = 0;
    env->slb_shadow_addr = 0;
    env->slb_shadow_size = 0;
    env->dtl_addr = 0;
    env->dtl_size = 0;
#endif /* TARGET_PPC64 */

    for (i = 0; i < ARRAY_SIZE(env->spr_cb); i++) {
        ppc_spr_t *spr = &env->spr_cb[i];

        if (!spr->name) {
            continue;
        }
        env->spr[i] = spr->default_value;
    }

    /* Flush all TLBs */
    tlb_flush(s, 1);
}

/*#ifndef CONFIG_USER_ONLY
static bool ppc_cpu_is_big_endian(struct uc_struct *uc, CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(uc, cs);
    CPUPPCState *env = &cpu->env;

    //cpu_synchronize_state(cs);

    return !msr_le;
}
#endif*/

static void ppc_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    PowerPCCPU *cpu = POWERPC_CPU(uc, obj);
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(uc, cpu);
    CPUPPCState *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(env, uc);
    cpu->cpu_dt_id = cs->cpu_index;

    env->msr_mask = pcc->msr_mask;
    env->mmu_model = pcc->mmu_model;
    env->excp_model = pcc->excp_model;
    env->bus_model = pcc->bus_model;
    env->insns_flags = pcc->insns_flags;
    env->insns_flags2 = pcc->insns_flags2;
    env->flags = pcc->flags;
    env->bfd_mach = pcc->bfd_mach;
    env->check_pow = pcc->check_pow;

#if defined(TARGET_PPC64)
    if (pcc->sps) {
        env->sps = *pcc->sps;
    } else if (env->mmu_model & POWERPC_MMU_64) {
        /* Use default sets of page sizes */
        static const struct ppc_segment_page_sizes defsps = {
            .sps = {
                { .page_shift = 12, /* 4K */
                  .slb_enc = 0,
                  .enc = { { .page_shift = 12, .pte_enc = 0 } }
                },
                { .page_shift = 24, /* 16M */
                  .slb_enc = 0x100,
                  .enc = { { .page_shift = 24, .pte_enc = 0 } }
                },
            },
        };
        env->sps = defsps;
    }
#endif /* defined(TARGET_PPC64) */

    if (tcg_enabled(uc)) {
        ppc_translate_init(uc);
    }
}

static bool ppc_pvr_match_default(PowerPCCPUClass *pcc, uint32_t pvr)
{
    return pcc->pvr == pvr;
}

static void ppc_cpu_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc, oc);
    CPUClass *cc = CPU_CLASS(uc, oc);
    pcc->pvr_match = ppc_pvr_match_default;
    pcc->interrupts_big_endian = ppc_cpu_interrupts_big_endian_always;

    pcc->parent_reset = cc->reset;
    cc->reset = ppc_cpu_reset;

    cc->has_work = ppc_cpu_has_work;
    cc->do_interrupt = ppc_cpu_do_interrupt;
    cc->cpu_exec_interrupt = ppc_cpu_exec_interrupt;
    cc->set_pc = ppc_cpu_set_pc;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = ppc_cpu_handle_mmu_fault;
#else
    cc->get_phys_page_debug = ppc_cpu_get_phys_page_debug;
#endif
    cc->cpu_exec_enter = ppc_cpu_exec_enter;
}

/* PowerPC CPU definitions from cpu-models.c*/
typedef struct PowerPCCPUInfo {
    const char *name;
    uint32_t pvr;
    uint32_t svr;
    void (*cpu_family_class_init)(struct uc_struct *uc, CPUClass *oc, void *data);
} PowerPCCPUInfo;

#define POWERPC_DEF_SVR(_name, _desc, _pvr, _svr, _type) \
    { _name, _pvr, _svr, POWERPC_FAMILY_NAME(_type) },

#define POWERPC_DEF(_name, _pvr, _type, _desc) \
    POWERPC_DEF_SVR(_name, _desc, _pvr, POWERPC_SVR_NONE, _type)


static const PowerPCCPUInfo ppc_cpus[] = {
    POWERPC_DEF_SVR("e500v2_v10", "PowerPC e500v2 v1.0 core",
                    CPU_POWERPC_e500v2_v10,   POWERPC_SVR_E500,      e500v2)
};

PowerPCCPU *cpu_ppc_init(struct uc_struct *uc, const char *cpu_model)
{
    int i;
    PowerPCCPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    PowerPCCPUClass *pcc;

    if (cpu_model == NULL) {
        cpu_model = "e500v2_v10";
    }

    cpu = malloc(sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }
    memset(cpu, 0, sizeof(*cpu));

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    /* init CPUClass */
    cpu_klass_init(uc, cc);
    /* init PowerPCCPUClass */
    ppc_cpu_class_init(uc, cc, NULL);
    /* init PowerPC family class */
    pcc = &cpu->cc;
    for (i = 0; i < ARRAY_SIZE(ppc_cpus); i++) {
        if (strcmp(cpu_model, ppc_cpus[i].name) == 0) {
            pcc->pvr = ppc_cpus[i].pvr;
            pcc->svr = ppc_cpus[i].svr;
            if (ppc_cpus[i].cpu_family_class_init) {
                ppc_cpus[i].cpu_family_class_init(uc, cc, uc);
            }
            break;
        }
    }
    /* init CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_init(uc, cs);
#endif
    /* init PowerPCCPU */
    ppc_cpu_initfn(uc, cs, uc);
    /* init PowerPC types */
    /* realize PowerPCCPU */
    ppc_cpu_realizefn(uc, cs);
    /* realize CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_realize(uc, cs);
#endif

    return cpu;
}
