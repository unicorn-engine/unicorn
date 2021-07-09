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
#include "translate.h"
#include "cpu.h"
#include "qemu/timer.h"
#include "sysemu/cpus.h"
//#include "cpu-models.h"
#include "mmu-hash32.h"
#include "mmu-hash64.h"
#include "qapi/visitor.h"

//#define PPC_DUMP_CPU
//#define PPC_DEBUG_SPR
//#define PPC_DUMP_SPR_ACCESSES
/* #define USE_APPLE_GDB */

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



/*
 * e500v2 support
 */

/* Create -kernel TLB entries for BookE.  */
static inline hwaddr booke206_page_size_to_tlb(uint64_t size)
{
    return 63 - clz64(size >> 10);
}


static int booke206_initial_map_tsize(CPUPPCState *env)
{
    //struct boot_info *bi = env->load_info;
    hwaddr dt_end;
    int ps;

    /* Our initial TLB entry needs to cover everything from 0 to
       the device tree top */
    dt_end = 0 + 0xFFFFFFFF; // bi->dt_base + bi->dt_size;
    ps = booke206_page_size_to_tlb(dt_end) + 1;
    if (ps & 1) {
        /* e500v2 can only do even TLB size bits */
        ps++;
    }
    return ps;
}

void mmubooke_create_initial_mapping(CPUPPCState *env)
{
    ppcmas_tlb_t *tlb = booke206_get_tlbm(env, 1, 0, 0);
    hwaddr size;
    int ps;

    ps = booke206_initial_map_tsize(env);
    size = (ps << MAS1_TSIZE_SHIFT);
    tlb->mas1 = MAS1_VALID | size;
    tlb->mas2 = 0;
    tlb->mas7_3 = 0;
    tlb->mas7_3 |= MAS3_UR | MAS3_UW | MAS3_UX | MAS3_SR | MAS3_SW | MAS3_SX;

    env->tlb_dirty = true;
}

/* Generic callbacks:
 * do nothing but store/retrieve spr value
 */
static void spr_load_dump_spr(int sprn)
{
#ifdef PPC_DUMP_SPR_ACCESSES
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx,sprn);
    gen_helper_load_dump_spr(tcg_ctx->cpu_env, t0);
    tcg_temp_free_i32(tcg_ctx,t0);
#endif
}

static void spr_read_generic (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_load_spr(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], sprn);
    spr_load_dump_spr(sprn);
}

static void spr_store_dump_spr(int sprn)
{
#ifdef PPC_DUMP_SPR_ACCESSES
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx,sprn);
    gen_helper_store_dump_spr(tcg_ctx->cpu_env, t0);
    tcg_temp_free_i32(tcg_ctx,t0);
#endif
}

static void spr_write_generic (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_store_spr(tcg_ctx,sprn,tcg_ctx->ppc_cpu_gpr[gprn]);
    spr_store_dump_spr(sprn);
}

#if !defined(CONFIG_USER_ONLY)
static void spr_write_generic32(void *opaque, int sprn, int gprn)
{
#ifdef TARGET_PPC64
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_ext32u_tl(tcg_ctx,t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    gen_store_spr(tcg_ctx,sprn, t0);
    tcg_temp_free(tcg_ctx,t0);
    spr_store_dump_spr(sprn);
#else
    spr_write_generic(opaque, sprn, gprn);
#endif
}

static void spr_write_clear (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv t1 = tcg_temp_new(tcg_ctx);
    gen_load_spr(tcg_ctx,t0, sprn);
    tcg_gen_neg_tl(tcg_ctx,t1,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_gen_and_tl(tcg_ctx,t0, t0, t1);
    gen_store_spr(tcg_ctx,sprn, t0);
    tcg_temp_free(tcg_ctx,t0);
    tcg_temp_free(tcg_ctx,t1);
}

#endif

/* SPR common to all PowerPC */
/* XER */

static void spr_read_xer (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_read_xer(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn]);
}

static void spr_write_xer (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_write_xer(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn]);
}

/* LR */
static void spr_read_lr(void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_mov_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_lr);
}

static void spr_write_lr(void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_lr, tcg_ctx->ppc_cpu_gpr[gprn]);
}

/* CFAR */
#if defined(TARGET_PPC64) && !defined(CONFIG_USER_ONLY)
static void spr_read_cfar (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_mov_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_cfar);
}

static void spr_write_cfar (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cfar, tcg_ctx->ppc_cpu_gpr[gprn]);
}
#endif /* defined(TARGET_PPC64) && !defined(CONFIG_USER_ONLY) */

/* CTR */
static void spr_read_ctr (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_mov_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_ctr);
}

static void spr_write_ctr (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_mov_tl(tcg_ctx,tcg_ctx->cpu_ctr, tcg_ctx->ppc_cpu_gpr[gprn]);
}

/* User read access to SPR */
/* USPRx */
/* UMMCRx */
/* UPMCx */
/* USIA */
/* UDECR */
static void spr_read_ureg (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_load_spr(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], sprn + 0x10);
}

#if defined(TARGET_PPC64) && !defined(CONFIG_USER_ONLY)
static void spr_write_ureg(void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_store_spr(tcg_ctx,sprn + 0x10, tcg_ctx->ppc_cpu_gpr[gprn]);
}
#endif

/* SPR common to all non-embedded PowerPC */
/* DECR */
#if !defined(CONFIG_USER_ONLY)
static void spr_read_decr (void *opaque, int gprn, int sprn)
{
    /*
    if (use_icount) {
        gen_io_start();
    }
    */
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_load_decr(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env);
    
    /*
    if (use_icount) {
        gen_io_end();
        gen_stop_exception(opaque);
    }
    */
}

static void spr_write_decr (void *opaque, int sprn, int gprn)
{
    /*
    if (use_icount) {
        gen_io_start();
    }
    */
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_store_decr(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
    
    /*
    if (use_icount) {
        gen_io_end();
        gen_stop_exception(opaque);
    }
    */
}
#endif

/* SPR common to all non-embedded PowerPC, except 601 */
/* Time base */
static void spr_read_tbl (void *opaque, int gprn, int sprn)
{
    /*
    if (use_icount) {
        gen_io_start();
    }
    */
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_load_tbl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env);
    /*
    if (use_icount) {
        gen_io_end();
        gen_stop_exception(opaque);
    }
    */
}

static void spr_read_tbu (void *opaque, int gprn, int sprn)
{
    /*
    if (use_icount) {
        gen_io_start();
    }
    */
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_load_tbu(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn],tcg_ctx->cpu_env);
    
    /*
    if (use_icount) {
        gen_io_end();
        gen_stop_exception(opaque);
    }
    */
}

__attribute__ (( unused ))
static void spr_read_atbl (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_load_atbl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env);
}

__attribute__ (( unused ))
static void spr_read_atbu (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_load_atbu(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env);
}

#if !defined(CONFIG_USER_ONLY)
static void spr_write_tbl (void *opaque, int sprn, int gprn)
{
    /*
    if (use_icount) {
        gen_io_start();
    }
    */
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_store_tbl(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
    
    /*
    if (use_icount) {
        gen_io_end();
        gen_stop_exception(opaque);
    }
    */
}

static void spr_write_tbu (void *opaque, int sprn, int gprn)
{
    /*
    if (use_icount) {
        gen_io_start();
    }
    */
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_store_tbu(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
    
    /*
    if (use_icount) {
        gen_io_end();
        gen_stop_exception(opaque);
    }
    */
}

__attribute__ (( unused ))
static void spr_write_atbl (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_store_atbl(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
}

__attribute__ (( unused ))
static void spr_write_atbu (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_store_atbu(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
}

#if defined(TARGET_PPC64)
__attribute__ (( unused ))
static void spr_read_purr (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_load_purr(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env);
}
#endif
#endif


#if !defined(CONFIG_USER_ONLY)

/* IBAT0U...IBAT0U */
/* IBAT0L...IBAT7L */
static void spr_read_ibat (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_ld_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env, offsetof(CPUPPCState, IBAT[sprn & 1][(sprn - SPR_IBAT0U) / 2]));
}


static void spr_write_ibatu (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx,(sprn - SPR_IBAT0U) / 2);
    gen_helper_store_ibatu(tcg_ctx,tcg_ctx->cpu_env, t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx,t0);
}


static void spr_write_ibatl (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx,(sprn - SPR_IBAT0L) / 2);
    gen_helper_store_ibatl(tcg_ctx,tcg_ctx->cpu_env, t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx,t0);
}


/* DBAT0U...DBAT7U */
/* DBAT0L...DBAT7L */
static void spr_read_dbat (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_ld_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env, offsetof(CPUPPCState, DBAT[sprn & 1][(sprn - SPR_DBAT0U) / 2]));
}


static void spr_write_dbatu (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx,(sprn - SPR_DBAT0U) / 2);
    gen_helper_store_dbatu(tcg_ctx,tcg_ctx->cpu_env, t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx,t0);
}

static void spr_write_dbatl (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx,(sprn - SPR_DBAT0L) / 2);
    gen_helper_store_dbatl(tcg_ctx,tcg_ctx->cpu_env, t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx,t0);
}



/* SDR1 */
static void spr_write_sdr1 (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    gen_helper_store_sdr1(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
}

#endif

/* 64 bits PowerPC specific SPRs */
#if defined(TARGET_PPC64)
static void spr_read_hior (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    tcg_gen_ld_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env, offsetof(CPUPPCState, excp_prefix));
}

static void spr_write_hior (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    
    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_tl(tcg_ctx,t0,tcg_ctx->ppc_cpu_gpr[gprn], 0x3FFFFF00000ULL);
    tcg_gen_st_tl(tcg_ctx,t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, excp_prefix));
    tcg_temp_free(tcg_ctx,t0);
}
#endif

/* PowerPC 40x specific registers */
#if !defined(CONFIG_USER_ONLY)
static void spr_read_40x_pit (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_helper_load_40x_pit(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], tcg_ctx->cpu_env);
}

static void spr_write_40x_pit (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_helper_store_40x_pit(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
}

static void spr_write_40x_dbcr0 (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
    TCGContext* tcg_ctx = ctx->uc->tcg_ctx;

    gen_helper_store_40x_dbcr0(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
    /* We must stop translation as we may have rebooted */
    gen_stop_exception(ctx);
}

static void spr_write_40x_sler (void *opaque, int sprn, int gprn)
{
     TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_helper_store_40x_sler(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
}

static void spr_write_booke_tcr (void *opaque, int sprn, int gprn)
{
     TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_helper_store_booke_tcr(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
}

static void spr_write_booke_tsr (void *opaque, int sprn, int gprn)
{
     TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_helper_store_booke_tsr(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
}
#endif



static void spr_write_pir (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    

    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_tl(tcg_ctx,t0,tcg_ctx->ppc_cpu_gpr[gprn], 0xF);
    gen_store_spr(tcg_ctx,SPR_PIR, t0);
    tcg_temp_free(tcg_ctx,t0);
}

/* SPE specific registers */
static void spr_read_spefscr (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    

    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_ld_i32(tcg_ctx,t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, spe_fscr));
    tcg_gen_extu_i32_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], t0);
    tcg_temp_free_i32(tcg_ctx,t0);
}

static void spr_write_spefscr (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    

    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_trunc_tl_i32(tcg_ctx,t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_gen_st_i32(tcg_ctx,t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, spe_fscr));
    tcg_temp_free_i32(tcg_ctx,t0);
}

#if !defined(CONFIG_USER_ONLY)
/* Callback used to write the exception vector base */
static void spr_write_excp_prefix (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;    

    TCGv t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_ld_tl(tcg_ctx,t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, ivpr_mask));
    tcg_gen_and_tl(tcg_ctx,t0, t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_gen_st_tl(tcg_ctx,t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, excp_prefix));
    gen_store_spr(tcg_ctx,sprn, t0);
    tcg_temp_free(tcg_ctx,t0);
}

static void spr_write_excp_vector (void *opaque, int sprn, int gprn)
{
    DisasContext *ctx = opaque;
    TCGContext* tcg_ctx = ctx->uc->tcg_ctx;
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
    tcg_gen_ld_tl(tcg_ctx,t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, ivor_mask));
    tcg_gen_and_tl(tcg_ctx,t0, t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_gen_st_tl(tcg_ctx,t0, tcg_ctx->cpu_env, offsetof(CPUPPCState, excp_vectors[sprn_offs]));
    gen_store_spr(tcg_ctx,sprn, t0);
    tcg_temp_free(tcg_ctx,t0);
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
void gen_spr_generic (CPUPPCState *env)
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
static void gen_spr_ne_601 (CPUPPCState *env)
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
    /* Memory management */
    spr_register(env, SPR_SDR1, "SDR1",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_sdr1,
                 0x00000000);
}

/* BATs 0-3 */
static void gen_low_BATs (CPUPPCState *env)
{
#if !defined(CONFIG_USER_ONLY)
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
#endif
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

#ifdef TARGET_PPC64
#ifndef CONFIG_USER_ONLY
static void spr_read_uamr (void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_load_spr(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], SPR_AMR);
    spr_load_dump_spr(SPR_AMR);
}

static void spr_write_uamr (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_store_spr(tcg_ctx,SPR_AMR,tcg_ctx->ppc_cpu_gpr[gprn]);
    spr_store_dump_spr(SPR_AMR);
}

static void spr_write_uamr_pr (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    gen_load_spr(tcg_ctx,t0, SPR_UAMOR);
    tcg_gen_and_tl(tcg_ctx,t0, t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    gen_store_spr(tcg_ctx,SPR_AMR, t0);
    spr_store_dump_spr(SPR_AMR);
}
#endif /* CONFIG_USER_ONLY */

static void gen_spr_amr (CPUPPCState *env)
{
#ifndef CONFIG_USER_ONLY
    /* Virtual Page Class Key protection */
    /* The AMR is accessible either via SPR 13 or SPR 29.  13 is
     * userspace accessible, 29 is privileged.  So we only need to set
     * the kvm ONE_REG id on one of them, we use 29 */
    spr_register(env, SPR_UAMR, "UAMR",
                 &spr_read_uamr, &spr_write_uamr_pr,
                 &spr_read_uamr, &spr_write_uamr,
                 0);
    spr_register_kvm(env, SPR_AMR, "AMR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_AMR, 0);
    spr_register_kvm(env, SPR_UAMOR, "UAMOR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_UAMOR, 0);
#endif /* !CONFIG_USER_ONLY */
}
#endif /* TARGET_PPC64 */

/* SPR specific to PowerPC 604 implementation */
static void gen_spr_604 (CPUPPCState *env)
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

#if !defined(CONFIG_USER_ONLY)
static void spr_write_e500_l1csr0 (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    tcg_gen_andi_tl(tcg_ctx,t0,tcg_ctx->ppc_cpu_gpr[gprn], L1CSR0_DCE | L1CSR0_CPE);
    gen_store_spr(tcg_ctx,sprn, t0);
    tcg_temp_free(tcg_ctx,t0);
}

static void spr_write_e500_l1csr1(void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    tcg_gen_andi_tl(tcg_ctx,t0,tcg_ctx->ppc_cpu_gpr[gprn], L1CSR1_ICE | L1CSR1_CPE);
    gen_store_spr(tcg_ctx,sprn, t0);
    tcg_temp_free(tcg_ctx,t0);
}

static void spr_write_booke206_mmucsr0 (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    gen_helper_booke206_tlbflush(tcg_ctx,tcg_ctx->cpu_env,tcg_ctx->ppc_cpu_gpr[gprn]);
}

static void spr_write_booke_pid (void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv_i32 t0 = tcg_const_i32(tcg_ctx,sprn);
    gen_helper_booke_setpid(tcg_ctx,tcg_ctx->cpu_env, t0,tcg_ctx->ppc_cpu_gpr[gprn]);
    tcg_temp_free_i32(tcg_ctx,t0);
}
#endif

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

/* SPR shared between PowerPC 40x implementations */
static void gen_spr_40x (CPUPPCState *env)
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
static void gen_spr_405 (CPUPPCState *env)
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
static void gen_spr_401_403 (CPUPPCState *env)
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
static void gen_spr_401 (CPUPPCState *env)
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

/*****************************************************************************/
/* Exception vectors models                                                  */
static void init_excp_4xx_real (CPUPPCState *env)
{
#if !defined(CONFIG_USER_ONLY)
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
#endif
}

static void init_excp_4xx_softmmu (CPUPPCState *env)
{
#if !defined(CONFIG_USER_ONLY)
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
#endif
}

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


#if defined (TARGET_PPC64)
static void init_excp_970 (CPUPPCState *env)
{
#if !defined(CONFIG_USER_ONLY)
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
#endif
}

#endif

/*****************************************************************************/
/* PowerPC implementations definitions                                       */

#define POWERPC_FAMILY(_name)                                               \
    static void                                                             \
    glue(glue(ppc_, _name), _cpu_family_class_init)(struct uc_struct* uc,ObjectClass *, void *); \
                                                                            \
    static const TypeInfo                                                   \
    glue(glue(ppc_, _name), _cpu_family_type_info) = {                      \
        .name = stringify(_name) "-family-" TYPE_POWERPC_CPU,               \
        .parent = TYPE_POWERPC_CPU,                                         \
        .abstract = true,                                                   \
        .class_init = glue(glue(ppc_, _name), _cpu_family_class_init),      \
    };                                                                      \
                                                                            \
    static void glue(glue(ppc_, _name), _cpu_family_register_types)(struct uc_struct* uc)   \
    {                                                                       \
        type_register_static(uc,                                               \
            &glue(glue(ppc_, _name), _cpu_family_type_info));               \
    }                                                                       \
                                                                            \
    type_init(glue(glue(ppc_, _name), _cpu_family_register_types))          \
                                                                            \
    static void glue(glue(ppc_, _name), _cpu_family_class_init)

void init_proc_401 (CPUPPCState *env)
{
    gen_spr_40x(env);
    gen_spr_401_403(env);
    gen_spr_401(env);
    init_excp_4xx_real(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    //ppc40x_irq_init(env);

    SET_FIT_PERIOD(12, 16, 20, 24);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

void init_proc_405 (CPUPPCState *env)
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
#if !defined(CONFIG_USER_ONLY)
    env->nb_tlb = 64;
    env->nb_ways = 1;
    env->id_tlbs = 0;
    env->tlb_type = TLB_EMB;
#endif
    init_excp_4xx_softmmu(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    //ppc40x_irq_init(env);

    SET_FIT_PERIOD(8, 12, 16, 20);
    SET_WDT_PERIOD(16, 20, 24, 28);
}

#if !defined(CONFIG_USER_ONLY)
static void spr_write_mas73(void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv val = tcg_temp_new(tcg_ctx);
    tcg_gen_ext32u_tl(tcg_ctx,val,tcg_ctx->ppc_cpu_gpr[gprn]);
    gen_store_spr(tcg_ctx,SPR_BOOKE_MAS3, val);
    tcg_gen_shri_tl(tcg_ctx,val,tcg_ctx->ppc_cpu_gpr[gprn], 32);
    gen_store_spr(tcg_ctx,SPR_BOOKE_MAS7, val);
    tcg_temp_free(tcg_ctx,val);
}

static void spr_read_mas73(void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv mas7 = tcg_temp_new(tcg_ctx);
    TCGv mas3 = tcg_temp_new(tcg_ctx);
    gen_load_spr(tcg_ctx,mas7, SPR_BOOKE_MAS7);
    tcg_gen_shli_tl(tcg_ctx,mas7, mas7, 32);
    gen_load_spr(tcg_ctx,mas3, SPR_BOOKE_MAS3);
    tcg_gen_or_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], mas3, mas7);
    tcg_temp_free(tcg_ctx,mas3);
    tcg_temp_free(tcg_ctx,mas7);
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
    //ppce500_irq_init(env);
}


void init_proc_e500v2(CPUPPCState *env)
{
    init_proc_e500(env, fsl_e500v2);
}





void init_proc_604(CPUPPCState *env)
{
    gen_spr_ne_601(env);
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
    //init_excp_604(env);
    env->dcache_line_size = 32;
    env->icache_line_size = 32;
    /* Allocate hardware IRQ controller */
    //ppc6xx_irq_init(env);
}

#if defined (TARGET_PPC64)
#if defined(CONFIG_USER_ONLY)
#define POWERPC970_HID5_INIT 0x00000080
#else
#define POWERPC970_HID5_INIT 0x00000000
#endif

enum BOOK3S_CPU_TYPE {
    BOOK3S_CPU_970,
    BOOK3S_CPU_POWER5PLUS,
    BOOK3S_CPU_POWER6,
    BOOK3S_CPU_POWER7,
    BOOK3S_CPU_POWER8
};

static void gen_fscr_facility_check(void *opaque, int facility_sprn, int bit,
                                    int sprn, int cause)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv_i32 t1 = tcg_const_i32(tcg_ctx,bit);
    TCGv_i32 t2 = tcg_const_i32(tcg_ctx,sprn);
    TCGv_i32 t3 = tcg_const_i32(tcg_ctx,cause);


    gen_update_nip(opaque, ((DisasContext*)opaque)->nip);
    gen_helper_fscr_facility_check(tcg_ctx, tcg_ctx->cpu_env, t1, t2, t3);

    tcg_temp_free_i32(tcg_ctx,t3);
    tcg_temp_free_i32(tcg_ctx,t2);
    tcg_temp_free_i32(tcg_ctx,t1);
}

static void gen_msr_facility_check(void *opaque, int facility_sprn, int bit,
                                   int sprn, int cause)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv_i32 t1 = tcg_const_i32(tcg_ctx,bit);
    TCGv_i32 t2 = tcg_const_i32(tcg_ctx,sprn);
    TCGv_i32 t3 = tcg_const_i32(tcg_ctx,cause);

    gen_update_nip(opaque, ((DisasContext*)opaque)->nip);
    gen_helper_msr_facility_check(tcg_ctx, tcg_ctx->cpu_env, t1, t2, t3);

    tcg_temp_free_i32(tcg_ctx,t3);
    tcg_temp_free_i32(tcg_ctx,t2);
    tcg_temp_free_i32(tcg_ctx,t1);
}

static void spr_read_prev_upper32(void *opaque, int gprn, int sprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv spr_up = tcg_temp_new(tcg_ctx);
    TCGv spr = tcg_temp_new(tcg_ctx);

    gen_load_spr(tcg_ctx,spr, sprn - 1);
    tcg_gen_shri_tl(tcg_ctx,spr_up, spr, 32);
    tcg_gen_ext32u_tl(tcg_ctx,tcg_ctx->ppc_cpu_gpr[gprn], spr_up);

    tcg_temp_free(tcg_ctx,spr);
    tcg_temp_free(tcg_ctx,spr_up);
}

static void spr_write_prev_upper32(void *opaque, int sprn, int gprn)
{
    TCGContext* tcg_ctx = ((DisasContext*)opaque)->uc->tcg_ctx;
    TCGv spr = tcg_temp_new(tcg_ctx);

    gen_load_spr(tcg_ctx,spr, sprn - 1);
    tcg_gen_deposit_tl(tcg_ctx, spr, spr,tcg_ctx->ppc_cpu_gpr[gprn], 32, 32);
    gen_store_spr(tcg_ctx,sprn - 1, spr);

    tcg_temp_free(tcg_ctx,spr);
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

static void gen_spr_970_lpar(CPUPPCState *env)
{
    /* Logical partitionning */
    /* PPC970: HID4 is effectively the LPCR */
    spr_register(env, SPR_970_HID4, "HID4",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void gen_spr_book3s_common(CPUPPCState *env)
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

    /* Can't find information on what this should be on reset.  This
     * value is the one used by 74xx processors. */
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
}

static void gen_spr_power8_pmu_user(CPUPPCState *env)
{
    spr_register(env, SPR_POWER_UMMCR2, "UMMCR2",
                 &spr_read_ureg, SPR_NOACCESS,
                 &spr_read_ureg, &spr_write_ureg,
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

static void gen_spr_power5p_lpar(CPUPPCState *env)
{
    /* Logical partitionning */
    spr_register_kvm(env, SPR_LPCR, "LPCR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_LPCR, 0x00000000);
}

static void gen_spr_book3s_ids(CPUPPCState *env)
{
    /* Processor identification */
    spr_register(env, SPR_PIR, "PIR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_generic, &spr_write_pir,
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
#if !defined(CONFIG_USER_ONLY)
    /* PURR & SPURR: Hack - treat these as aliases for the TB for now */
    spr_register_kvm(env, SPR_PURR,   "PURR",
                     &spr_read_purr, SPR_NOACCESS,
                     &spr_read_purr, SPR_NOACCESS,
                     KVM_REG_PPC_PURR, 0x00000000);
    spr_register_kvm(env, SPR_SPURR,   "SPURR",
                     &spr_read_purr, SPR_NOACCESS,
                     &spr_read_purr, SPR_NOACCESS,
                     KVM_REG_PPC_SPURR, 0x00000000);
#endif
}

static void gen_spr_power6_dbg(CPUPPCState *env)
{
#if !defined(CONFIG_USER_ONLY)
    spr_register(env, SPR_CFAR, "SPR_CFAR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 &spr_read_cfar, &spr_write_cfar,
                 0x00000000);
#endif
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
#if !defined(CONFIG_USER_ONLY)
    spr_register_kvm(env, SPR_DSCR, "SPR_DSCR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_DSCR, 0x00000000);
#endif
    /*
     * Register PCR to report POWERPC_EXCP_PRIV_REG instead of
     * POWERPC_EXCP_INVAL_SPR.
     */
    spr_register(env, SPR_PCR, "PCR",
                 SPR_NOACCESS, SPR_NOACCESS,
                 SPR_NOACCESS, SPR_NOACCESS,
                 0x00000000);
}

static void spr_read_tar(void *opaque, int gprn, int sprn)
{
    gen_fscr_facility_check(opaque, SPR_FSCR, FSCR_TAR, sprn, FSCR_IC_TAR);
    spr_read_generic(opaque, gprn, sprn);
}

static void spr_write_tar(void *opaque, int sprn, int gprn)
{
    gen_fscr_facility_check(opaque, SPR_FSCR, FSCR_TAR, sprn, FSCR_IC_TAR);
    spr_write_generic(opaque, sprn, gprn);
}

static void gen_spr_power8_tce_address_control(CPUPPCState *env)
{
    spr_register(env, SPR_TAR, "TAR",
                 &spr_read_tar, &spr_write_tar,
                 &spr_read_generic, &spr_write_generic,
                 0x00000000);
}

static void spr_read_tm(void *opaque, int gprn, int sprn)
{
    gen_msr_facility_check(opaque, SPR_FSCR, MSR_TM, sprn, FSCR_IC_TM);
    spr_read_generic(opaque, gprn, sprn);
}

static void spr_write_tm(void *opaque, int sprn, int gprn)
{
    gen_msr_facility_check(opaque, SPR_FSCR, MSR_TM, sprn, FSCR_IC_TM);
    spr_write_generic(opaque, sprn, gprn);
}

static void spr_read_tm_upper32(void *opaque, int gprn, int sprn)
{
    gen_msr_facility_check(opaque, SPR_FSCR, MSR_TM, sprn, FSCR_IC_TM);
    spr_read_prev_upper32(opaque, gprn, sprn);
}

static void spr_write_tm_upper32(void *opaque, int sprn, int gprn)
{
    gen_msr_facility_check(opaque, SPR_FSCR, MSR_TM, sprn, FSCR_IC_TM);
    spr_write_prev_upper32(opaque, sprn, gprn);
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

static void spr_read_ebb(void *opaque, int gprn, int sprn)
{
    gen_fscr_facility_check(opaque, SPR_FSCR, FSCR_EBB, sprn, FSCR_IC_EBB);
    spr_read_generic(opaque, gprn, sprn);
}

static void spr_write_ebb(void *opaque, int sprn, int gprn)
{
    gen_fscr_facility_check(opaque, SPR_FSCR, FSCR_EBB, sprn, FSCR_IC_EBB);
    spr_write_generic(opaque, sprn, gprn);
}

static void spr_read_ebb_upper32(void *opaque, int gprn, int sprn)
{
    gen_fscr_facility_check(opaque, SPR_FSCR, FSCR_EBB, sprn, FSCR_IC_EBB);
    spr_read_prev_upper32(opaque, gprn, sprn);
}

static void spr_write_ebb_upper32(void *opaque, int sprn, int gprn)
{
    gen_fscr_facility_check(opaque, SPR_FSCR, FSCR_EBB, sprn, FSCR_IC_EBB);
    spr_write_prev_upper32(opaque, sprn, gprn);
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

static void gen_spr_power8_fscr(CPUPPCState *env)
{
#if defined(CONFIG_USER_ONLY)
    target_ulong initval = 1ULL << FSCR_TAR;
#else
    target_ulong initval = 0;
#endif
    spr_register_kvm(env, SPR_FSCR, "FSCR",
                     SPR_NOACCESS, SPR_NOACCESS,
                     &spr_read_generic, &spr_write_generic,
                     KVM_REG_PPC_FSCR, initval);
}

static void init_proc_book3s_64(CPUPPCState *env, int version)
{
    gen_spr_ne_601(env);
    gen_tbl(env);
    gen_spr_book3s_altivec(env);
    gen_spr_book3s_pmu_sup(env);
    gen_spr_book3s_pmu_user(env);
    gen_spr_book3s_common(env);

    switch (version) {
    case BOOK3S_CPU_970:
    case BOOK3S_CPU_POWER5PLUS:
        gen_spr_970_hid(env);
        gen_spr_970_hior(env);
        gen_low_BATs(env);
        gen_spr_970_pmu_sup(env);
        gen_spr_970_pmu_user(env);
        break;
    case BOOK3S_CPU_POWER7:
    case BOOK3S_CPU_POWER8:
        gen_spr_book3s_ids(env);
        gen_spr_amr(env);
        gen_spr_book3s_purr(env);
        break;
    default:
        g_assert_not_reached();
    }
    if (version >= BOOK3S_CPU_POWER5PLUS) {
        gen_spr_power5p_common(env);
        gen_spr_power5p_lpar(env);
        gen_spr_power5p_ear(env);
    } else {
        gen_spr_970_lpar(env);
    }
    if (version == BOOK3S_CPU_970) {
        gen_spr_970_dbg(env);
    }
    if (version >= BOOK3S_CPU_POWER6) {
        gen_spr_power6_common(env);
        gen_spr_power6_dbg(env);
    }
    if (version >= BOOK3S_CPU_POWER8) {
        gen_spr_power8_tce_address_control(env);
        gen_spr_power8_ids(env);
        gen_spr_power8_ebb(env);
        gen_spr_power8_fscr(env);
        gen_spr_power8_pmu_sup(env);
        gen_spr_power8_pmu_user(env);
        gen_spr_power8_tm(env);
    }
    if (version < BOOK3S_CPU_POWER8) {
        gen_spr_book3s_dbg(env);
    }
#if !defined(CONFIG_USER_ONLY)
    switch (version) {
    case BOOK3S_CPU_970:
    case BOOK3S_CPU_POWER5PLUS:
        env->slb_nr = 64;
        break;
    case BOOK3S_CPU_POWER7:
    case BOOK3S_CPU_POWER8:
    default:
        env->slb_nr = 32;
        break;
    }
#endif
    /* Allocate hardware IRQ controller */
    switch (version) {
    case BOOK3S_CPU_970:
    case BOOK3S_CPU_POWER5PLUS:
        init_excp_970(env);
        //ppc970_irq_init(env);
        break;
    case BOOK3S_CPU_POWER7:
    case BOOK3S_CPU_POWER8:
        //init_excp_POWER7(env);
        //ppcPOWER7_irq_init(env);
        break;
    default:
        g_assert_not_reached();
    }

    env->dcache_line_size = 128;
    env->icache_line_size = 128;
}

void init_proc_970(CPUPPCState *env)
{
    init_proc_book3s_64(env, BOOK3S_CPU_970);
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

int is_indirect_opcode (void *handler)
{
    return ((uintptr_t)handler & PPC_OPCODE_MASK) == PPC_INDIRECT;
}

opc_handler_t **ind_table(void *handler)
{
    return (opc_handler_t **)((uintptr_t)handler & ~PPC_OPCODE_MASK);
}

/* Instruction table creation */
/* Opcodes tables creation */
void fill_new_table (opc_handler_t **table, int len)
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

int register_insn (opc_handler_t **ppc_opcodes, opcode_t *insn)
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

void fix_opcode_tables (opc_handler_t **ppc_opcodes)
{
    if (test_opcode_table(ppc_opcodes, PPC_CPU_OPCODES_LEN) == 0)
        printf("*** WARNING: no opcode defined !\n");
}

/*****************************************************************************/

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


#include <ctype.h>

//static ObjectClass *ppc_cpu_class_by_name(struct uc_struct *uc,const char *name);

/* CPUClass::reset() */
void ppc_cpu_reset(CPUState *s)
{
    CPUPPCState *env = s->env_ptr;
    PowerPCCPU *cpu = POWERPC_CPU(env->uc,s);
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(env->uc,cpu);
    //CPUPPCState *env = &cpu->env;
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
#endif

#if !defined(TARGET_WORDS_BIGENDIAN)
    msr |= (target_ulong)1 << MSR_LE; /* Little-endian user mode */
    if (!((env->msr_mask >> MSR_LE) & 1)) {
        fprintf(stderr, "Selected CPU does not support little-endian.\n");
        exit(1);
    }
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


